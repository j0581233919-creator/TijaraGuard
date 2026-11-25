"""Live HTTP server REST API, operator dashboard, webhooks, and CLI subprocess tests."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import subprocess
import sys
import tempfile
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

from tijaraguard.api import TijaraGuardHTTPServer
from tijaraguard.config import load_config
from tijaraguard.delivery import LocalLoopbackReceiver
from tijaraguard.security import compute_hmac_sha256_hex

from helpers import CATALOG_PATH, REPO_ROOT, SYNTH_SAUDI_ID


class TestAPIAndCLI(unittest.TestCase):
    def setUp(self) -> None:
        base_tmp = REPO_ROOT / ".tmp_test"
        base_tmp.mkdir(parents=True, exist_ok=True)
        self.tmpdir = Path(tempfile.mkdtemp(prefix="apicli_", dir=str(base_tmp)))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _http(
        self,
        base_url: str,
        method: str,
        path: str,
        *,
        body: dict | None = None,
        headers: dict | None = None,
    ) -> tuple[int, dict, str]:
        parsed = urlsplit(base_url)
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=15.0)
        hdrs = dict(headers or {})
        raw_body = None
        if body is not None:
            raw_body = json.dumps(body, ensure_ascii=False).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
            hdrs["Content-Length"] = str(len(raw_body))
        try:
            conn.request(method, path, body=raw_body, headers=hdrs)
            resp = conn.getresponse()
            raw_resp = resp.read().decode("utf-8")
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, raw_resp
        finally:
            conn.close()

    def test_rest_api_auth_operator_workflow_webhooks_and_rate_limit(self) -> None:
        rx_db = self.tmpdir / "rx.sqlite3"
        with LocalLoopbackReceiver(rx_db, drop_ack=True) as receiver:
            env = {
                "TIJARAGUARD_MODE": "LOOPBACK_LIVE",
                "TIJARAGUARD_STATE_DIR": str(self.tmpdir / "state"),
                "TIJARAGUARD_CATALOG_PATH": str(CATALOG_PATH),
                "TIJARAGUARD_APPROVAL_SECRET": "a" * 64,
                "TIJARAGUARD_CONTACT_HASH_KEY": "b" * 64,
                "TIJARAGUARD_API_KEY": "op-secret-key-2026",
                "TIJARAGUARD_LOOPBACK_RECEIVER_URL": receiver.endpoint_url,
                "TIJARAGUARD_RATE_LIMIT_PER_MIN": "50",
                "TIJARAGUARD_WEBHOOK_ENABLED": "true",
                "TIJARAGUARD_WEBHOOK_INBOUND_SECRET": "wh-in-secret-99",
            }
            cfg = load_config(env=env)
            with TijaraGuardHTTPServer(cfg, host="127.0.0.1", port=0) as srv:
                # 1. Public health, readiness, and dashboard HTML
                st, hdrs, raw = self._http(srv.base_url, "GET", "/health")
                self.assertEqual(st, 200)
                self.assertEqual(hdrs.get("x-content-type-options"), "nosniff")
                self.assertEqual(json.loads(raw)["status"], "ok")

                st_r, _, raw_r = self._http(srv.base_url, "GET", "/ready")
                self.assertEqual(st_r, 200)
                self.assertTrue(json.loads(raw_r)["ready"])

                st_h, _, html = self._http(srv.base_url, "GET", "/")
                self.assertEqual(st_h, 200)
                self.assertIn("TijaraGuard Operator Console", html)
                self.assertNotIn("op-secret-key-2026", html)

                # 2. Protected /api/v1/* fails closed without valid Bearer/X-API-Key
                st_u, _, _ = self._http(srv.base_url, "GET", "/api/v1/status")
                self.assertEqual(st_u, 401)
                st_b, _, _ = self._http(
                    srv.base_url,
                    "GET",
                    "/api/v1/status",
                    headers={"Authorization": "Bearer wrong"},
                )
                self.assertEqual(st_b, 401)

                auth = {"Authorization": "Bearer op-secret-key-2026"}

                # 3. Catalog search, inquiry ingestion, edit, approve, dispatch (lost ACK -> UNKNOWN), recover
                st_cs, _, cs_raw = self._http(
                    srv.base_url,
                    "GET",
                    "/api/v1/catalog/search?q=EC685",
                    headers=auth,
                )
                self.assertEqual(st_cs, 200)
                self.assertEqual(json.loads(cs_raw)["resolved_item"]["sku"], "DELONGHI-EC685")

                st_in, _, in_raw = self._http(
                    srv.base_url,
                    "POST",
                    "/api/v1/inquiries",
                    headers=auth,
                    body={
                        "message_id": "msg-api-1",
                        "conversation_id": "conv-api-1",
                        "customer_handle": "عميل_واجهة",
                        "raw_contact_target": "+966501234567",
                        "contact_channel": "whatsapp",
                        "consent_to_contact": True,
                        "consent_evidence": "api_opt_in",
                        "preferred_language": "ar",
                        "raw_text": f"كم سعر ماكينة قهوة ديلونجي EC685؟ هويتي {SYNTH_SAUDI_ID}",
                    },
                )
                self.assertEqual(st_in, 201)
                draft = json.loads(in_raw)
                self.assertNotIn(SYNTH_SAUDI_ID, draft["redacted_inquiry"])

                # Approve -> Dispatch -> Recover
                st_ap, _, ap_raw = self._http(
                    srv.base_url,
                    "POST",
                    f"/api/v1/drafts/{draft['draft_id']}/approve",
                    headers=auth,
                    body={
                        "reviewer_id": "op_ahmed",
                        "expected_payload_sha256": draft["payload_sha256"],
                    },
                )
                self.assertEqual(st_ap, 200)

                st_dp, _, dp_raw = self._http(
                    srv.base_url,
                    "POST",
                    f"/api/v1/drafts/{draft['draft_id']}/dispatch",
                    headers=auth,
                    body={},
                )
                self.assertEqual(st_dp, 200)
                self.assertEqual(json.loads(dp_raw)["state"], "UNKNOWN_DELIVERY")

                st_rc, _, rc_raw = self._http(
                    srv.base_url,
                    "POST",
                    f"/api/v1/drafts/{draft['draft_id']}/recover",
                    headers=auth,
                    body={},
                )
                self.assertEqual(st_rc, 200)
                self.assertEqual(json.loads(rc_raw)["state"], "DELIVERED")

                # 4. CSV export & maintenance backup/purge & conversations & usage
                st_csv, _, csv_text = self._http(srv.base_url, "GET", "/api/v1/audit/export.csv", headers=auth)
                self.assertEqual(st_csv, 200)
                self.assertIn("event_hash", csv_text)

                st_bak, _, bak_raw = self._http(
                    srv.base_url, "POST", "/api/v1/maintenance/backup", headers=auth, body={}
                )
                self.assertEqual(st_bak, 200)
                self.assertTrue(json.loads(bak_raw)["valid"])

                # 5. Generic webhook endpoint rejects unsigned and accepts signed payload
                st_wh_bad, _, _ = self._http(
                    srv.base_url, "POST", "/webhooks/generic", body={"event_id": "e1"}
                )
                self.assertEqual(st_wh_bad, 401)

                wh_body = {
                    "event_id": "wh-api-evt-1",
                    "conversation_id": "wh-api-conv-1",
                    "target": "+966509998877",
                    "text": "كم سعر سماعة سوني WH-1000XM5؟",
                    "consent_to_contact": True,
                    "consent_evidence": "wh_opt_in",
                }
                wh_raw = json.dumps(wh_body, ensure_ascii=False).encode("utf-8")
                ts_str = str(int(time.time()))
                wh_sig = "sha256=" + compute_hmac_sha256_hex(
                    "wh-in-secret-99", f"{ts_str}.".encode("utf-8") + wh_raw
                )
                parsed = urlsplit(srv.base_url)
                c = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=5.0)
                c.request(
                    "POST",
                    "/webhooks/generic",
                    body=wh_raw,
                    headers={
                        "Content-Type": "application/json",
                        "Content-Length": str(len(wh_raw)),
                        "X-TijaraGuard-Timestamp": ts_str,
                        "X-TijaraGuard-Signature": wh_sig,
                    },
                )
                wh_resp = c.getresponse()
                self.assertEqual(wh_resp.status, 200)
                c.close()

        # 6. Rate limiting returns HTTP 429 with Retry-After header
        env_rl = {
            "TIJARAGUARD_MODE": "SIMULATED_NO_SEND",
            "TIJARAGUARD_STATE_DIR": str(self.tmpdir / "state_rl"),
            "TIJARAGUARD_CATALOG_PATH": str(CATALOG_PATH),
            "TIJARAGUARD_APPROVAL_SECRET": "a" * 64,
            "TIJARAGUARD_CONTACT_HASH_KEY": "b" * 64,
            "TIJARAGUARD_RATE_LIMIT_PER_MIN": "2",
        }
        with TijaraGuardHTTPServer(load_config(env=env_rl), host="127.0.0.1", port=0) as rl_srv:
            self.assertEqual(self._http(rl_srv.base_url, "GET", "/health")[0], 200)
            self.assertEqual(self._http(rl_srv.base_url, "GET", "/health")[0], 200)
            st429, hdr429, _ = self._http(rl_srv.base_url, "GET", "/health")
            self.assertEqual(st429, 429)
            self.assertIn("retry-after", hdr429)

    def test_cli_check_config_and_operator_commands(self) -> None:
        state_dir = self.tmpdir / "cli_state"
        env = dict(
            os.environ,
            PYTHONDONTWRITEBYTECODE="1",
            TIJARAGUARD_MODE="SIMULATED_NO_SEND",
            TIJARAGUARD_STATE_DIR=str(state_dir),
            TIJARAGUARD_CATALOG_PATH=str(CATALOG_PATH),
            TIJARAGUARD_APPROVAL_SECRET="c" * 64,
            TIJARAGUARD_CONTACT_HASH_KEY="d" * 64,
        )

        p_chk = subprocess.run(
            [sys.executable, "-B", "-m", "tijaraguard", "check-config"],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertTrue(json.loads(p_chk.stdout)["valid"])

        p_ing = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "tijaraguard",
                "ingest",
                "--message-id",
                "cli-msg-1",
                "--conversation-id",
                "cli-conv-1",
                "--customer-handle",
                "cli_user",
                "--contact-target",
                "+966501112233",
                "--consent",
                "true",
                "--consent-evidence",
                "cli_opt_in",
                "--text",
                "كم سعر ماكينة قهوة ديلونجي EC685؟",
            ],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        ing = json.loads(p_ing.stdout)
        self.assertEqual(ing["verification_status"], "PASS")

        p_app = subprocess.run(
            [
                sys.executable,
                "-B",
                "-m",
                "tijaraguard",
                "approve",
                ing["draft_id"],
                "--reviewer",
                "cli_sup",
                "--payload-sha256",
                ing["payload_sha256"],
            ],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(json.loads(p_app.stdout)["draft_id"], ing["draft_id"])

        p_disp = subprocess.run(
            [sys.executable, "-B", "-m", "tijaraguard", "dispatch", ing["draft_id"]],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(json.loads(p_disp.stdout)["state"], "SHADOW_RECORDED")

        bak_file = self.tmpdir / "cli_bak.sqlite3"
        subprocess.run(
            [sys.executable, "-B", "-m", "tijaraguard", "backup", str(bak_file)],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertTrue(bak_file.is_file())
