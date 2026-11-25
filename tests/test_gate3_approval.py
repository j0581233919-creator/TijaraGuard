"""Gate 3 SQLite WAL approval ledger, Shadow Mode, tamper & concurrency tests."""

from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
_TESTS_DIR = Path(__file__).resolve().parent
_ROOT = _TESTS_DIR.parent
for _p in (str(_TESTS_DIR), str(_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from tijaraguard.ledger import verify_audit_database_readonly
from tijaraguard.models import (
    ApprovalAlreadyConsumedError,
    ApprovalExpiredError,
    ApprovalRequiredError,
    ApprovalTamperError,
    ApprovalToken,
    DraftState,
    ExecutionMode,
    MalformedInputError,
    VerificationBlockedError,
)
from tijaraguard.pipeline import TijaraGuardPipeline

from helpers import (
    ALL_SYNTH_PII_SECRETS,
    REPO_ROOT,
    SYNTH_SAUDI_ID,
    load_test_catalog,
    make_inbound_message,
    make_secret_bytes,
    scan_sqlite_for_secrets,
)


class TestGate3Approval(unittest.TestCase):
    def setUp(self) -> None:
        base_tmp = REPO_ROOT / ".tmp_test"
        base_tmp.mkdir(parents=True, exist_ok=True)
        self.tmpdir = Path(tempfile.mkdtemp(prefix="g3_", dir=str(base_tmp)))
        self.ledger_db = self.tmpdir / "ledger.sqlite3"
        self.pipe = TijaraGuardPipeline(
            catalog=load_test_catalog(),
            ledger_db_path=self.ledger_db,
            approval_secret=make_secret_bytes(),
            contact_hash_key=make_secret_bytes(),
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_shadow_mode_is_default_and_never_sends_externally(self) -> None:
        self.assertEqual(self.pipe.mode, ExecutionMode.SHADOW)
        self.assertIsNone(self.pipe.delivery)

        res = self.pipe.process_inbound(
            make_inbound_message(
                message_id="msg-g3-shadow",
                requested_sku="DELONGHI-EC685",
                raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
            )
        )
        token = self.pipe.approve(
            res["draft_id"],
            reviewer_id="supervisor_1",
            expected_payload_sha256=res["payload_sha256"],
        )
        outcome = self.pipe.dispatch(res["draft_id"], token)
        self.assertEqual(outcome.mode, "SIMULATED_NO_SEND")
        self.assertEqual(outcome.state, DraftState.SHADOW_RECORDED.value)
        self.assertFalse(outcome.dispatched)

    def test_unapproved_or_wrong_hash_or_malformed_mac_rejected(self) -> None:
        res = self.pipe.process_inbound(
            make_inbound_message(
                message_id="msg-g3-unapproved",
                requested_sku="DELONGHI-EC685",
                raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
            )
        )
        fake_token = ApprovalToken(
            lease_id="LEASE-NONEXISTENT",
            draft_id=res["draft_id"],
            payload_sha256=res["payload_sha256"],
            reviewer_id="attacker",
            approved_at=time.time(),
            expires_at=time.time() + 60,
            approval_mac="0" * 64,
        )
        with self.assertRaises(ApprovalRequiredError):
            self.pipe.dispatch(res["draft_id"], fake_token)

        with self.assertRaises(ApprovalTamperError):
            self.pipe.approve(
                res["draft_id"],
                reviewer_id="supervisor_1",
                expected_payload_sha256="f" * 64,
            )

        with self.assertRaises(MalformedInputError):
            self.pipe.approve(
                res["draft_id"],
                reviewer_id="supervisor_1",
                expected_payload_sha256="not-a-hex-digest",
            )

    def test_single_use_lease_blocks_replay_and_concurrent_threads(self) -> None:
        res = self.pipe.process_inbound(
            make_inbound_message(
                message_id="msg-g3-race",
                requested_sku="DELONGHI-EC685",
                raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
            )
        )
        token = self.pipe.approve(
            res["draft_id"],
            reviewer_id="supervisor_1",
            expected_payload_sha256=res["payload_sha256"],
        )

        # Sequential replay attempt
        barrier = threading.Barrier(6)
        successes = 0
        consumed_errors = 0
        lock = threading.Lock()

        def worker() -> None:
            nonlocal successes, consumed_errors
            barrier.wait()
            try:
                self.pipe.dispatch(res["draft_id"], token)
                with lock:
                    successes += 1
            except ApprovalAlreadyConsumedError:
                with lock:
                    consumed_errors += 1

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        self.assertEqual(successes, 1)
        self.assertEqual(consumed_errors, 5)

        with self.assertRaises(ApprovalAlreadyConsumedError):
            self.pipe.dispatch(res["draft_id"], token)

    def test_payload_edit_or_direct_sqlite_tamper_invalidates_approval(self) -> None:
        # 1. Explicit edit via edit_draft revokes approval
        res1 = self.pipe.process_inbound(
            make_inbound_message(
                message_id="msg-g3-edit",
                requested_sku="DELONGHI-EC685",
                raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
            )
        )
        tok1 = self.pipe.approve(
            res1["draft_id"],
            reviewer_id="supervisor_1",
            expected_payload_sha256=res1["payload_sha256"],
        )
        self.pipe.edit_draft(
            res1["draft_id"],
            new_body="مرحباً، سعر ماكينة قهوة ديلونجي EC685 هو 1.00 SAR.",
            actor="malicious_editor",
        )
        with self.assertRaises(ApprovalTamperError):
            self.pipe.dispatch(res1["draft_id"], tok1)

        # 2. Direct SQLite row mutation behind the application's back
        res2 = self.pipe.process_inbound(
            make_inbound_message(
                message_id="msg-g3-sqli-tamper",
                requested_sku="DELONGHI-EC685",
                raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
            )
        )
        tok2 = self.pipe.approve(
            res2["draft_id"],
            reviewer_id="supervisor_1",
            expected_payload_sha256=res2["payload_sha256"],
        )
        conn = sqlite3.connect(str(self.ledger_db))
        try:
            conn.execute(
                "UPDATE drafts SET body=? WHERE draft_id=?",
                ("تم التلاعب بالسعر إلى 10 SAR", res2["draft_id"]),
            )
            conn.commit()
        finally:
            conn.close()

        with self.assertRaises(ApprovalTamperError):
            self.pipe.dispatch(res2["draft_id"], tok2)

        events = self.pipe.ledger.list_audit_events(res2["draft_id"])
        self.assertTrue(any(e["event_type"] == "APPROVAL_INVALIDATED_TAMPER" for e in events))

        # 3. Non-hex MAC passed directly
        bad_mac_tok = ApprovalToken(
            lease_id=tok2.lease_id,
            draft_id=res2["draft_id"],
            payload_sha256=res2["payload_sha256"],
            reviewer_id="supervisor_1",
            approved_at=tok2.approved_at,
            expires_at=tok2.expires_at,
            approval_mac="g" * 64,
        )
        with self.assertRaises(ApprovalTamperError):
            self.pipe.dispatch(res2["draft_id"], bad_mac_tok)

    def test_expired_lease_rejected_and_audit_triggers_immutable(self) -> None:
        res = self.pipe.process_inbound(
            make_inbound_message(
                message_id="msg-g3-expiry",
                requested_sku="DELONGHI-EC685",
                raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
            )
        )
        tok = self.pipe.approve(
            res["draft_id"],
            reviewer_id="supervisor_1",
            expected_payload_sha256=res["payload_sha256"],
            ttl_seconds=10,
        )
        with self.assertRaises(ApprovalExpiredError):
            self.pipe.ledger.consume_approval_for_dispatch(
                draft_id=res["draft_id"],
                lease_id=tok.lease_id,
                approval_mac=tok.approval_mac,
                mode=ExecutionMode.SHADOW,
                now=tok.expires_at + 1.0,
            )

        # Direct UPDATE/DELETE on audit_events must be blocked by SQLite triggers
        conn = sqlite3.connect(str(self.ledger_db))
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("UPDATE audit_events SET actor='forged' WHERE seq=1")
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM audit_events WHERE seq=1")
        finally:
            conn.close()

        valid, errors = self.pipe.ledger.verify_audit_chain()
        self.assertTrue(valid, f"Audit chain errors: {errors}")
        self.assertEqual(errors, [])

    def test_consent_and_channel_tamper_and_non_ascii_mac_invalidated(self) -> None:
        # 1. Mutating consent_to_contact in SQLite post-approval triggers ApprovalTamperError
        r1 = self.pipe.process_inbound(
            make_inbound_message(
                message_id="msg-g3-consent-tamper",
                requested_sku="DELONGHI-EC685",
                raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
            )
        )
        t1 = self.pipe.approve(
            r1["draft_id"],
            reviewer_id="supervisor_1",
            expected_payload_sha256=r1["payload_sha256"],
        )
        conn = sqlite3.connect(str(self.ledger_db))
        try:
            conn.execute(
                "UPDATE drafts SET consent_to_contact=0 WHERE draft_id=?",
                (r1["draft_id"],),
            )
            conn.commit()
        finally:
            conn.close()
        with self.assertRaises(ApprovalTamperError):
            self.pipe.dispatch(r1["draft_id"], t1)

        # 2. Mutating contact_channel in SQLite triggers ApprovalTamperError
        r2 = self.pipe.process_inbound(
            make_inbound_message(
                message_id="msg-g3-channel-tamper",
                requested_sku="DELONGHI-EC685",
                raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
            )
        )
        t2 = self.pipe.approve(
            r2["draft_id"],
            reviewer_id="supervisor_1",
            expected_payload_sha256=r2["payload_sha256"],
        )
        conn = sqlite3.connect(str(self.ledger_db))
        try:
            conn.execute(
                "UPDATE drafts SET contact_channel='email' WHERE draft_id=?",
                (r2["draft_id"],),
            )
            conn.commit()
        finally:
            conn.close()
        with self.assertRaises(ApprovalTamperError):
            self.pipe.dispatch(r2["draft_id"], t2)

        # 3. Non-ASCII tampered approval_mac in DB triggers ApprovalTamperError (not TypeError)
        r3 = self.pipe.process_inbound(
            make_inbound_message(
                message_id="msg-g3-nonascii-mac",
                requested_sku="DELONGHI-EC685",
                raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
            )
        )
        t3 = self.pipe.approve(
            r3["draft_id"],
            reviewer_id="supervisor_1",
            expected_payload_sha256=r3["payload_sha256"],
        )
        conn = sqlite3.connect(str(self.ledger_db))
        try:
            conn.execute(
                "UPDATE approvals SET approval_mac=? WHERE lease_id=?",
                ("م" * 64, t3.lease_id),
            )
            conn.commit()
        finally:
            conn.close()
        with self.assertRaises(ApprovalTamperError):
            self.pipe.dispatch(r3["draft_id"], t3)
        self.assertTrue(
            any(
                e["event_type"] == "APPROVAL_INVALIDATED_TAMPER"
                for e in self.pipe.ledger.list_audit_events(r3["draft_id"])
            )
        )

    def test_readonly_verify_audit_detects_dropped_trigger_tail_delete_non_ascii_and_wrong_db(self) -> None:
        self.pipe.process_inbound(
            make_inbound_message(
                message_id="msg-g3-audit-ro",
                requested_sku="DELONGHI-EC685",
                raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
            )
        )
        # Wrong SQLite DB (non-ledger) fails cleanly without mutating schema
        other_db = self.tmpdir / "other.sqlite3"
        oc = sqlite3.connect(str(other_db))
        oc.execute("CREATE TABLE unrelated(id INTEGER PRIMARY KEY)")
        oc.commit()
        oc.close()
        ok_other, _cnt, errs_other = verify_audit_database_readonly(other_db)
        self.assertFalse(ok_other)
        self.assertTrue(errs_other)
        oc2 = sqlite3.connect(str(other_db))
        tables = {
            r[0]
            for r in oc2.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        oc2.close()
        self.assertEqual(tables, {"unrelated"})

        # Non-ASCII event_hash in tampered copy fails cleanly without TypeError
        copy_bad_hash = self.tmpdir / "ledger_bad_hash.sqlite3"
        shutil.copy2(self.ledger_db, copy_bad_hash)
        conn = sqlite3.connect(str(copy_bad_hash))
        conn.execute("DROP TRIGGER audit_events_no_update")
        conn.execute("UPDATE audit_events SET event_hash=? WHERE seq=1", ("ت" * 64,))
        conn.commit()
        conn.close()
        ok_bh, _cnt, errs_bh = verify_audit_database_readonly(copy_bad_hash)
        self.assertFalse(ok_bh)
        self.assertTrue(any("trigger" in e.lower() for e in errs_bh))
        self.assertTrue(any("non-hex" in e.lower() for e in errs_bh))

        # Tail deletion detected via sqlite_sequence mismatch
        copy_tail_del = self.tmpdir / "ledger_tail_del.sqlite3"
        shutil.copy2(self.ledger_db, copy_tail_del)
        conn2 = sqlite3.connect(str(copy_tail_del))
        conn2.execute("DROP TRIGGER audit_events_no_delete")
        conn2.execute("DELETE FROM audit_events WHERE seq=(SELECT MAX(seq) FROM audit_events)")
        conn2.commit()
        conn2.close()
        ok_td, _cnt, errs_td = verify_audit_database_readonly(copy_tail_del)
        self.assertFalse(ok_td)
        self.assertTrue(any("tail deletion" in e.lower() for e in errs_td))

    def test_delivery_state_machine_blocks_illegal_transitions_and_operator_pii_redacted(self) -> None:
        res = self.pipe.process_inbound(
            make_inbound_message(
                message_id="msg-g3-fsm",
                requested_sku="DELONGHI-EC685",
                raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
            )
        )
        # Illegal transition directly from PENDING_APPROVAL to DELIVERED blocked
        with self.assertRaises(VerificationBlockedError):
            self.pipe.ledger.record_delivery_state(res["draft_id"], DraftState.DELIVERED)

        # Empty actor rejected in edit_draft_body
        with self.assertRaises(MalformedInputError):
            self.pipe.edit_draft(res["draft_id"], new_body="تجربة", actor="   ")

        # Operator reject reason containing PII is redacted before immutable audit storage
        self.pipe.reject(
            res["draft_id"],
            reviewer_id="supervisor_1",
            reason=f"مرفوض لوجود رقم هوية {SYNTH_SAUDI_ID}",
        )
        self.assertEqual(scan_sqlite_for_secrets(self.ledger_db, ALL_SYNTH_PII_SECRETS), [])

        # Rejected draft cannot be edited afterwards
        with self.assertRaises(VerificationBlockedError):
            self.pipe.edit_draft(res["draft_id"], new_body="نص جديد", actor="supervisor_1")
