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

from tijaraguard.models import (
    ApprovalAlreadyConsumedError,
    ApprovalExpiredError,
    ApprovalRequiredError,
    ApprovalTamperError,
    ApprovalToken,
    DraftState,
    ExecutionMode,
    MalformedInputError,
)
from tijaraguard.pipeline import TijaraGuardPipeline

from helpers import (
    FIXED_REFERENCE_TIME,
    REPO_ROOT,
    load_test_catalog,
    make_inbound_message,
    make_secret_bytes,
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
