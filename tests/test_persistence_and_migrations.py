"""Database schema v1->v2 migration, backup/restore, retention purge, and EphemeralRouteStore tests."""

from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
_TESTS_DIR = Path(__file__).resolve().parent
_ROOT = _TESTS_DIR.parent
for _p in (str(_TESTS_DIR), str(_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from tijaraguard.ledger import (
    ApprovalLedger,
    EphemeralRouteStore,
    compute_draft_payload_sha256,
    restore_ledger_backup,
    verify_audit_database_readonly,
)
from tijaraguard.models import DraftState, ExecutionMode, MalformedInputError
from tijaraguard.pipeline import TijaraGuardPipeline

from helpers import REPO_ROOT, load_test_catalog, make_inbound_message, make_secret_bytes


class TestPersistenceAndMigrations(unittest.TestCase):
    def setUp(self) -> None:
        base_tmp = REPO_ROOT / ".tmp_test"
        base_tmp.mkdir(parents=True, exist_ok=True)
        self.tmpdir = Path(tempfile.mkdtemp(prefix="mig_", dir=str(base_tmp)))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_v1_database_migrates_cleanly_to_v2_preserving_audit_chain(self) -> None:
        v1_db = self.tmpdir / "v1_ledger.sqlite3"
        secret = make_secret_bytes()
        conn = sqlite3.connect(str(v1_db))
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE drafts (
                draft_id TEXT PRIMARY KEY,
                message_id TEXT NOT NULL UNIQUE,
                conversation_id TEXT NOT NULL,
                customer_handle TEXT NOT NULL,
                contact_ref TEXT NOT NULL,
                contact_channel TEXT NOT NULL,
                sku TEXT,
                language TEXT NOT NULL,
                redacted_inquiry TEXT NOT NULL,
                pii_summary_json TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                consent_to_contact INTEGER NOT NULL CHECK(consent_to_contact IN (0, 1)),
                consent_evidence TEXT NOT NULL,
                verification_status TEXT NOT NULL,
                verification_report_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                state TEXT NOT NULL,
                delivery_key TEXT UNIQUE,
                receipt_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE approvals (
                lease_id TEXT PRIMARY KEY,
                draft_id TEXT NOT NULL REFERENCES drafts(draft_id),
                payload_sha256 TEXT NOT NULL,
                reviewer_id TEXT NOT NULL,
                notes TEXT NOT NULL,
                approved_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                approval_mac TEXT NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0, 1)),
                consumed_at REAL,
                revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
                revoked_reason TEXT
            );
            CREATE TABLE audit_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                draft_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT NOT NULL,
                actor TEXT NOT NULL,
                payload_sha256 TEXT,
                details_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL UNIQUE
            );
            CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
            CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
            BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
            PRAGMA user_version = 1;
            """
        )
        p_hash = compute_draft_payload_sha256(
            {
                "draft_id": "DRAFT-V1-001",
                "sku": "DELONGHI-EC685",
                "language": "ar",
                "subject": "استفسار",
                "body": "السعر 850.00 SAR",
                "contact_ref": "ref-0123456789abcdef",
                "contact_channel": "whatsapp",
                "consent_to_contact": 1,
                "consent_evidence": "opt_in_v1",
                "verification_status": "PASS",
            }
        )
        conn.execute(
            """
            INSERT INTO drafts VALUES (
                'DRAFT-V1-001', 'msg-v1-1', 'conv-v1-1', 'cust1', 'ref-0123456789abcdef',
                'whatsapp', 'DELONGHI-EC685', 'ar', 'كم السعر؟', '{}',
                'استفسار', 'السعر 850.00 SAR', 1, 'opt_in_v1', 'PASS', '{}',
                ?, 'PENDING_APPROVAL', NULL, NULL, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
            )
            """,
            (p_hash,),
        )
        conn.commit()
        conn.close()

        # Open with v2 ApprovalLedger -> triggers automatic migration
        ledger = ApprovalLedger(v1_db, secret)
        row = ledger.get_draft("DRAFT-V1-001")
        self.assertEqual(row["tenant_id"], "default")
        tok = ledger.approve_draft("DRAFT-V1-001", "reviewer_1", row["payload_sha256"])
        self.assertEqual(tok.draft_id, "DRAFT-V1-001")

        # Verify PRAGMA user_version == 2 & audit chain valid
        check_conn = sqlite3.connect(str(v1_db))
        ver = check_conn.execute("PRAGMA user_version").fetchone()[0]
        check_conn.close()
        self.assertEqual(ver, 2)
        ok, errs = ledger.verify_audit_chain()
        self.assertTrue(ok, errs)

    def test_backup_restore_and_retention_purge(self) -> None:
        db_path = self.tmpdir / "ledger.sqlite3"
        pipe = TijaraGuardPipeline(
            catalog=load_test_catalog(),
            ledger_db_path=db_path,
            approval_secret=make_secret_bytes(),
            contact_hash_key=make_secret_bytes(),
            mode=ExecutionMode.SHADOW,
            retention_days=1,
        )
        r_shadow = pipe.process_inbound(
            make_inbound_message(
                message_id="msg-ret-shadow",
                requested_sku="DELONGHI-EC685",
                raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
            )
        )
        tok = pipe.approve(
            r_shadow["draft_id"],
            reviewer_id="sup",
            expected_payload_sha256=r_shadow["payload_sha256"],
        )
        pipe.dispatch(r_shadow["draft_id"], tok)

        r_pending = pipe.process_inbound(
            make_inbound_message(
                message_id="msg-ret-pending",
                requested_sku="DELONGHI-EC685",
                raw_text="استفسار معلق",
            )
        )

        # Backup & restore
        bak_path = self.tmpdir / "backups" / "ledger.bak.sqlite3"
        bak_info = pipe.ledger.backup_to(bak_path)
        self.assertTrue(bak_info["valid"])

        restored_db = self.tmpdir / "restored.sqlite3"
        res_info = restore_ledger_backup(bak_path, restored_db)
        self.assertTrue(res_info["restored"])
        ok_ro, _cnt, errs_ro = verify_audit_database_readonly(restored_db)
        self.assertTrue(ok_ro, errs_ro)

        # Corrupted backup fails verification before overwriting target
        bad_bak = self.tmpdir / "bad.sqlite3"
        shutil.copy2(bak_path, bad_bak)
        bconn = sqlite3.connect(str(bad_bak))
        bconn.execute("DROP TRIGGER audit_events_no_delete")
        bconn.commit()
        bconn.close()
        with self.assertRaises(MalformedInputError):
            restore_ledger_backup(bad_bak, restored_db)

        # Retention purge scrubs expired terminal draft but preserves pending draft & audit chain
        purge_res = pipe.ledger.purge_expired_retention(now_iso="2099-01-01T00:00:00+00:00")
        self.assertEqual(purge_res["purged_drafts"], 1)
        self.assertEqual(
            pipe.ledger.get_draft(r_shadow["draft_id"])["redacted_inquiry"],
            "[PURGED_BY_RETENTION]",
        )
        self.assertEqual(
            pipe.ledger.get_draft(r_pending["draft_id"])["redacted_inquiry"],
            "استفسار معلق",
        )
        chain_ok, chain_errs = pipe.ledger.verify_audit_chain()
        self.assertTrue(chain_ok, chain_errs)

    def test_ephemeral_route_store_isolation(self) -> None:
        routes = EphemeralRouteStore(self.tmpdir / "routes.sqlite3", default_ttl_seconds=60)
        routes.put(
            tenant_id="tenant_a",
            channel="whatsapp",
            contact_ref="ref-1111",
            external_target="966501111111",
            external_conversation_id="conv-1",
            ttl_seconds=60,
        )
        self.assertIsNotNone(
            routes.get(tenant_id="tenant_a", channel="whatsapp", contact_ref="ref-1111")
        )
        # Cross-tenant or cross-channel lookup returns None
        self.assertIsNone(
            routes.get(tenant_id="tenant_b", channel="whatsapp", contact_ref="ref-1111")
        )
        self.assertIsNone(
            routes.get(tenant_id="tenant_a", channel="telegram", contact_ref="ref-1111")
        )
        self.assertEqual(routes.purge_expired(now=time.time() + 120), 1)
        self.assertIsNone(
            routes.get(tenant_id="tenant_a", channel="whatsapp", contact_ref="ref-1111")
        )
