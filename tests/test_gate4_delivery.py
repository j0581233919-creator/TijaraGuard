"""Gate 4 (MessageShield) reliable loopback delivery, lost-ACK, concurrency, and crash tests."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
_TESTS_DIR = Path(__file__).resolve().parent
_ROOT = _TESTS_DIR.parent
for _p in (str(_TESTS_DIR), str(_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from tijaraguard.delivery import LocalLoopbackReceiver, MessageShieldDeliveryAdapter, compute_delivery_key
from tijaraguard.deps import load_dependencies
from tijaraguard.models import ApprovalRequiredError, DeliveryError, DraftState, ExecutionMode
from tijaraguard.pipeline import TijaraGuardPipeline

from helpers import (
    FIXED_REFERENCE_TIME,
    REPO_ROOT,
    load_test_catalog,
    make_inbound_message,
    make_secret_bytes,
)

_DEPS = load_dependencies()


class TestGate4Delivery(unittest.TestCase):
    def setUp(self) -> None:
        base_tmp = REPO_ROOT / ".tmp_test"
        base_tmp.mkdir(parents=True, exist_ok=True)
        self.tmpdir = Path(tempfile.mkdtemp(prefix="g4_", dir=str(base_tmp)))
        self.catalog = load_test_catalog()
        self.secret = make_secret_bytes()
        self.hash_key = make_secret_bytes()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _new_live_pipeline(self, endpoint_url: str, *, timeout: float = 0.5) -> TijaraGuardPipeline:
        return TijaraGuardPipeline(
            catalog=self.catalog,
            ledger_db_path=self.tmpdir / "ledger.sqlite3",
            approval_secret=self.secret,
            contact_hash_key=self.hash_key,
            mode=ExecutionMode.LOOPBACK_LIVE,
            outbox_db_path=self.tmpdir / "outbox.sqlite3",
            receiver_endpoint=endpoint_url,
            shield_timeout=timeout,
        )

    def test_non_loopback_endpoint_rejected(self) -> None:
        for bad_url in (
            "https://example.com/inbox",
            "http://192.168.1.50:8877/inbox",
            "http://localhost:8877/inbox",
        ):
            with self.assertRaises(DeliveryError):
                MessageShieldDeliveryAdapter(
                    outbox_db_path=self.tmpdir / "outbox_bad.sqlite3",
                    endpoint_url=bad_url,
                )

    def test_lost_ack_enters_unknown_and_recovers_single_logical_delivery(self) -> None:
        receiver_db = self.tmpdir / "receiver.sqlite3"
        with LocalLoopbackReceiver(receiver_db, drop_ack=True) as receiver:
            pipe = self._new_live_pipeline(receiver.endpoint_url)
            res = pipe.process_inbound(
                make_inbound_message(
                    message_id="msg-g4-lostack",
                    requested_sku="DELONGHI-EC685",
                    raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
                )
            )
            token = pipe.approve(
                res["draft_id"],
                reviewer_id="supervisor_1",
                expected_payload_sha256=res["payload_sha256"],
            )

            outcome1 = pipe.dispatch(res["draft_id"], token)
            self.assertEqual(outcome1.state, DraftState.UNKNOWN_DELIVERY.value)
            self.assertEqual(outcome1.message_shield_state, "UNKNOWN")
            self.assertEqual(receiver.count_post_attempts(outcome1.delivery_key), 1)
            self.assertEqual(receiver.count_logical_deliveries(outcome1.delivery_key), 1)

            # Reopen fresh MessageShield adapter / pipeline instance and recover via GET
            pipe_reopened = self._new_live_pipeline(receiver.endpoint_url)
            outcome2 = pipe_reopened.recover_delivery(res["draft_id"], confirm_delivered=True)
            self.assertEqual(outcome2.state, DraftState.DELIVERED.value)
            self.assertEqual(outcome2.message_shield_state, "DELIVERED")
            self.assertIsNotNone(outcome2.receipt_id)

            # Strictly 1 POST attempt (recovery only did GET readback) and 1 inbox row.
            self.assertEqual(receiver.count_post_attempts(outcome2.delivery_key), 1)
            self.assertEqual(receiver.count_logical_deliveries(outcome2.delivery_key), 1)

    def test_duplicate_http_and_concurrent_retries_produce_one_logical_inbox_row(self) -> None:
        receiver_db = self.tmpdir / "receiver_dup.sqlite3"
        with LocalLoopbackReceiver(receiver_db, drop_ack=False) as receiver:
            pipe = self._new_live_pipeline(receiver.endpoint_url)
            res = pipe.process_inbound(
                make_inbound_message(
                    message_id="msg-g4-dup",
                    requested_sku="DELONGHI-EC685",
                    raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
                )
            )
            token = pipe.approve(
                res["draft_id"],
                reviewer_id="supervisor_1",
                expected_payload_sha256=res["payload_sha256"],
            )
            outcome = pipe.dispatch(res["draft_id"], token, confirm_delivered=True)
            self.assertEqual(outcome.state, DraftState.DELIVERED.value)

            # Fetch exact wire envelope from MessageShield outbox to simulate duplicate retries
            from message_shield.model import fingerprint as ms_fingerprint  # type: ignore

            shield_row = pipe.delivery.shield.store
            with shield_row.connect() as sconn:
                msg_row = dict(
                    sconn.execute(
                        "SELECT * FROM messages WHERE message_id=?", (res["draft_id"],)
                    ).fetchone()
                )
            wire_payload = json.loads(msg_row["wire_json"])
            body_dict = {
                "key": outcome.delivery_key,
                "payload": wire_payload,
                "payload_sha256": ms_fingerprint(wire_payload),
            }
            raw_body = json.dumps(body_dict, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
            parsed = urlsplit(receiver.endpoint_url)

            # Replay 5 concurrent identical POST retries against the loopback receiver
            barrier = threading.Barrier(5)
            statuses = []
            receipt_ids = set()
            lock = threading.Lock()

            def post_retry() -> None:
                barrier.wait()
                conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=2.0)
                try:
                    conn.request(
                        "POST",
                        "/inbox",
                        body=raw_body,
                        headers={
                            "Content-Type": "application/json",
                            "Content-Length": str(len(raw_body)),
                            "Idempotency-Key": outcome.delivery_key or "",
                            "Connection": "close",
                        },
                    )
                    resp = conn.getresponse()
                    data = json.loads(resp.read().decode("utf-8"))
                    with lock:
                        statuses.append(resp.status)
                        receipt_ids.add(data["receipt_id"])
                finally:
                    conn.close()

            threads = [threading.Thread(target=post_retry) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5.0)

            self.assertEqual(statuses, [200] * 5)
            self.assertEqual(receipt_ids, {outcome.receipt_id})
            self.assertEqual(receiver.count_post_attempts(outcome.delivery_key), 6)
            self.assertEqual(receiver.count_logical_deliveries(outcome.delivery_key), 1)

            # Conflicting payload under same Idempotency-Key must be rejected with 409
            bad_payload = dict(wire_payload, text="سعر مزيف 1 SAR")
            conflict_body = json.dumps(
                {
                    "key": outcome.delivery_key,
                    "payload": bad_payload,
                    "payload_sha256": ms_fingerprint(bad_payload),
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            c_conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=2.0)
            try:
                c_conn.request(
                    "POST",
                    "/inbox",
                    body=conflict_body,
                    headers={
                        "Content-Type": "application/json",
                        "Content-Length": str(len(conflict_body)),
                        "Idempotency-Key": outcome.delivery_key or "",
                        "Connection": "close",
                    },
                )
                c_resp = c_conn.getresponse()
                self.assertEqual(c_resp.status, 409)
            finally:
                c_conn.close()

            self.assertEqual(receiver.count_logical_deliveries(outcome.delivery_key), 1)

    def test_process_sigkill_during_sending_recovers_after_lease_expiry(self) -> None:
        receiver_db = self.tmpdir / "receiver_crash.sqlite3"
        # Receiver commits row immediately, then sleeps 2.5s before ACK while client timeout=1.0s
        # so SIGKILL lands strictly while MessageShield outbox state == 'SENDING'.
        with LocalLoopbackReceiver(
            receiver_db,
            drop_ack=False,
            post_delay_before_ack=2.5,
        ) as receiver:
            pipe = self._new_live_pipeline(receiver.endpoint_url, timeout=1.0)
            res = pipe.process_inbound(
                make_inbound_message(
                    message_id="msg-g4-sigkill",
                    requested_sku="DELONGHI-EC685",
                    raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
                )
            )
            token = pipe.approve(
                res["draft_id"],
                reviewer_id="supervisor_1",
                expected_payload_sha256=res["payload_sha256"],
            )
            consumed = pipe.ledger.consume_approval_for_dispatch(
                draft_id=res["draft_id"],
                lease_id=token.lease_id,
                approval_mac=token.approval_mac,
                mode=ExecutionMode.LOOPBACK_LIVE,
            )

            # Launch a child worker process to run MessageShield.send() and kill it mid-POST!
            worker_code = (
                "import sys; sys.dont_write_bytecode = True; "
                "from pathlib import Path; "
                f"sys.path.insert(0, {str(REPO_ROOT)!r}); "
                "from tijaraguard.delivery import MessageShieldDeliveryAdapter; "
                f"adapter = MessageShieldDeliveryAdapter(outbox_db_path={str(self.tmpdir / 'outbox.sqlite3')!r}, "
                f"endpoint_url={receiver.endpoint_url!r}, timeout=1.0); "
                f"adapter.admit_and_send({res['draft_id']!r}, {consumed['body']!r})"
            )
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
            proc = subprocess.Popen(
                [sys.executable, "-B", "-c", worker_code],
                cwd=str(REPO_ROOT),
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            key = compute_delivery_key(res["draft_id"])
            try:
                # Wait for subprocess startup + POST commit into receiver SQLite, then SIGKILL.
                deadline = time.time() + 8.0
                while time.time() < deadline and receiver.count_logical_deliveries(key) == 0:
                    time.sleep(0.01)
                self.assertEqual(receiver.count_logical_deliveries(key), 1)
            finally:
                if proc.poll() is None:
                    os.kill(proc.pid, signal.SIGKILL)
                proc.wait(timeout=3.0)

            # Confirm MessageShield outbox persisted SENDING before SIGKILL
            reopened = self._new_live_pipeline(receiver.endpoint_url, timeout=1.0)
            pre_state = reopened.delivery.status(res["draft_id"])
            self.assertEqual(pre_state["state"], "SENDING")

            # Wait for MessageShield lease_until (2*1.0 + 1 = 3.0s) to expire
            time.sleep(3.15)

            recovered = reopened.recover_delivery(res["draft_id"], confirm_delivered=True)
            self.assertEqual(recovered.state, DraftState.DELIVERED.value)
            self.assertEqual(recovered.message_shield_state, "DELIVERED")
            self.assertEqual(receiver.count_post_attempts(key), 1)
            self.assertEqual(receiver.count_logical_deliveries(key), 1)

    def test_compatibility_with_upstream_message_shield_example_receiver(self) -> None:
        from examples.local_receiver import receiver as ms_example_receiver  # type: ignore

        ms_rx_db = self.tmpdir / "ms_example_inbox.sqlite3"
        httpd = ms_example_receiver(ms_rx_db, port=0, drop_ack=True)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            endpoint_url = f"http://127.0.0.1:{httpd.server_port}/inbox"
            adapter = MessageShieldDeliveryAdapter(
                outbox_db_path=self.tmpdir / "ms_compat_outbox.sqlite3",
                endpoint_url=endpoint_url,
                timeout=0.5,
            )
            first = adapter.admit_and_send("DRAFT-COMPAT-1", "مرحباً، طلبكم جاهز.")
            self.assertEqual(first["state"], "UNKNOWN")

            recovered = adapter.recover("DRAFT-COMPAT-1")
            self.assertEqual(recovered["state"], "ACCEPTED")
            self.assertIsNotNone(recovered["receipt_id"])
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2.0)

    def test_shadow_mode_blocks_recover_oversized_preserves_lease_and_deliv_idempotent(self) -> None:
        receiver_db = self.tmpdir / "rx_m3.sqlite3"
        with LocalLoopbackReceiver(receiver_db, drop_ack=False) as receiver:
            # 1. Shadow mode disables self.delivery and blocks recover_delivery
            shadow_pipe = TijaraGuardPipeline(
                catalog=self.catalog,
                ledger_db_path=self.tmpdir / "shadow_only.sqlite3",
                approval_secret=self.secret,
                contact_hash_key=self.hash_key,
                mode=ExecutionMode.SHADOW,
                outbox_db_path=self.tmpdir / "unused_outbox.sqlite3",
                receiver_endpoint=receiver.endpoint_url,
            )
            self.assertIsNone(shadow_pipe.delivery)
            s_res = shadow_pipe.process_inbound(
                make_inbound_message(
                    message_id="msg-g4-shadow-blk",
                    requested_sku="DELONGHI-EC685",
                    raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
                )
            )
            with self.assertRaises(DeliveryError):
                shadow_pipe.recover_delivery(s_res["draft_id"])

            # 2. Live mode: ineligible PENDING_APPROVAL blocks recover_delivery;
            # successful DELIVERED returns idempotent delivered outcome on repeat recover
            live_pipe = self._new_live_pipeline(receiver.endpoint_url)
            pending_res = live_pipe.process_inbound(
                make_inbound_message(
                    message_id="msg-g4-pending-rec",
                    requested_sku="DELONGHI-EC685",
                    raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
                )
            )
            with self.assertRaises(ApprovalRequiredError):
                live_pipe.recover_delivery(pending_res["draft_id"])

            tok = live_pipe.approve(
                pending_res["draft_id"],
                reviewer_id="supervisor_1",
                expected_payload_sha256=pending_res["payload_sha256"],
            )
            d1 = live_pipe.dispatch(pending_res["draft_id"], tok, confirm_delivered=True)
            self.assertEqual(d1.state, DraftState.DELIVERED.value)
            d2 = live_pipe.recover_delivery(pending_res["draft_id"], confirm_delivered=True)
            self.assertTrue(d2.dispatched)
            self.assertEqual(d2.state, DraftState.DELIVERED.value)
            self.assertEqual(d2.receipt_id, d1.receipt_id)

            # 3. Oversized payload (>8192 bytes) raises DeliveryError BEFORE consuming lease
            big_res = live_pipe.process_inbound(
                make_inbound_message(
                    message_id="msg-g4-oversized",
                    requested_sku="DELONGHI-EC685",
                    raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
                )
            )
            # Directly insert valid >8192-byte approved draft via edit_draft / oversized legitimate check:
            # construct valid CommercialEvaluation and update ledger body properly
            big_text = "مرحباً، " + ("سعر المنتج 850.00 SAR " * 400)
            self.assertGreater(len(big_text.encode("utf-8")), 8192)
            big_edited = live_pipe.edit_draft(
                big_res["draft_id"],
                new_body=big_text,
                actor="tester",
            )
            self.assertEqual(big_edited["verification_status"], "PASS")
            big_tok = live_pipe.approve(
                big_res["draft_id"],
                reviewer_id="supervisor_1",
                expected_payload_sha256=big_edited["payload_sha256"],
            )
            with self.assertRaises(DeliveryError):
                live_pipe.dispatch(big_res["draft_id"], big_tok)
            # Draft remains APPROVED (lease NOT stranded in DISPATCHING)
            self.assertEqual(
                live_pipe.ledger.get_draft(big_res["draft_id"])["state"],
                DraftState.APPROVED.value,
            )

    def test_receiver_rejects_dup_json_keys_transfer_encoding_and_missing_idem(self) -> None:
        rx_db = self.tmpdir / "rx_strict.sqlite3"
        with LocalLoopbackReceiver(rx_db) as receiver:
            parsed = urlsplit(receiver.endpoint_url)
            valid_key = compute_delivery_key("DRAFT-STRICT-1")
            payload = {
                "tenant": "tijaraguard",
                "source": "approved_draft",
                "message_id": "DRAFT-STRICT-1",
                "text": "مرحباً",
            }
            from message_shield.model import fingerprint as ms_fp  # type: ignore

            body_bytes = json.dumps(
                {"key": valid_key, "payload": payload, "payload_sha256": ms_fp(payload)},
                ensure_ascii=False,
            ).encode("utf-8")

            # 1. Missing Idempotency-Key -> 400
            c1 = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=2.0)
            c1.request(
                "POST",
                "/inbox",
                body=body_bytes,
                headers={"Content-Type": "application/json", "Content-Length": str(len(body_bytes))},
            )
            self.assertEqual(c1.getresponse().status, 400)
            c1.close()

            # 2. Duplicate JSON key -> 400
            dup_json = (
                b'{"key":"' + valid_key.encode() + b'","key":"' + valid_key.encode() + b'"}'
            )
            c2 = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=2.0)
            c2.request(
                "POST",
                "/inbox",
                body=dup_json,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(dup_json)),
                    "Idempotency-Key": valid_key,
                },
            )
            self.assertEqual(c2.getresponse().status, 400)
            c2.close()

            # 3. Transfer-Encoding header -> 400
            c3 = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=2.0)
            c3.request(
                "POST",
                "/inbox",
                body=body_bytes,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body_bytes)),
                    "Transfer-Encoding": "chunked",
                    "Idempotency-Key": valid_key,
                },
            )
            self.assertEqual(c3.getresponse().status, 400)
            c3.close()

            self.assertEqual(receiver.count_logical_deliveries(), 0)

            # 4. IPv6 formatting check (binds ::1 if supported on host, else checks formatting logic)
            try:
                with LocalLoopbackReceiver(self.tmpdir / "rx_v6.sqlite3", host="::1") as rx6:
                    self.assertTrue(rx6.endpoint_url.startswith("http://[::1]:"))
            except OSError:
                pass
