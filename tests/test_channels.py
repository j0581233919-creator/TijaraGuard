"""Controlled HTTP server tests for WhatsApp, Telegram, Chatwoot, Generic Webhook, and LIVE mode."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List

sys.dont_write_bytecode = True
_TESTS_DIR = Path(__file__).resolve().parent
_ROOT = _TESTS_DIR.parent
for _p in (str(_TESTS_DIR), str(_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from tijaraguard.channels import (
    ChannelRegistry,
    ChatwootAdapter,
    GenericWebhookAdapter,
    TelegramBotAdapter,
    WhatsAppCloudAdapter,
)
from tijaraguard.config import (
    ChatwootConfig,
    GenericWebhookConfig,
    TelegramConfig,
    WhatsAppConfig,
)
from tijaraguard.ledger import EphemeralRouteStore
from tijaraguard.models import DeliveryError, DraftState, ExecutionMode
from tijaraguard.pipeline import TijaraGuardPipeline
from tijaraguard.security import ReplayError, WebhookSignatureError, compute_hmac_sha256_hex

from helpers import (
    ALL_SYNTH_PII_SECRETS,
    REPO_ROOT,
    SYNTH_PHONE_INTL,
    SYNTH_SAUDI_ID,
    load_test_catalog,
    make_secret_bytes,
    scan_sqlite_for_secrets,
)


class _MockChannelGatewayServer:
    """Controlled HTTP server simulating Meta Graph, Telegram Bot, Chatwoot, and Webhook APIs."""

    def __init__(self) -> None:
        self.outbound_requests: List[Dict[str, Any]] = []
        self.receipts: Dict[str, str] = {}
        self.fail_next_send = False
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        assert self._server is not None
        return f"http://127.0.0.1:{self._server.server_port}"

    def start(self) -> "_MockChannelGatewayServer":
        srv_ref = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send(self, code: int, obj: Dict[str, Any]) -> None:
                raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                if self.path.startswith("/webhook/receipts/"):
                    key = self.path[len("/webhook/receipts/"):]
                    rcpt = srv_ref.receipts.get(key)
                    if rcpt:
                        self._send(200, {"receipt_id": rcpt, "state": "ACCEPTED"})
                    else:
                        self._send(404, {"error": "not_found"})
                    return
                self._send(404, {"error": "not_found"})

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or "0")
                raw = self.rfile.read(length) if length > 0 else b"{}"
                body = json.loads(raw.decode("utf-8"))
                srv_ref.outbound_requests.append(
                    {
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                        "body": body,
                    }
                )
                if srv_ref.fail_next_send:
                    srv_ref.fail_next_send = False
                    self._send(503, {"error": "temporary_gateway_failure"})
                    return

                # WhatsApp Cloud API
                if self.path.endswith("/messages") and "/v21.0/" in self.path:
                    self._send(
                        200,
                        {
                            "messaging_product": "whatsapp",
                            "messages": [{"id": "wamid.HBgMOTE5OTAwMDAwMDAw"}],
                        },
                    )
                    return

                # Telegram Bot API
                if self.path.endswith("/sendMessage"):
                    self._send(200, {"ok": True, "result": {"message_id": 7711}})
                    return
                if self.path.endswith("/getUpdates"):
                    self._send(
                        200,
                        {
                            "ok": True,
                            "result": [
                                {
                                    "update_id": 9001,
                                    "message": {
                                        "message_id": 55,
                                        "date": int(time.time()),
                                        "chat": {"id": 445566},
                                        "from": {"id": 445566, "username": "tg_buyer"},
                                        "text": "كم سعر سماعة سوني WH-1000XM5؟",
                                    },
                                }
                            ],
                        },
                    )
                    return

                # Chatwoot API
                if "/api/v1/accounts/" in self.path:
                    self._send(200, {"id": 8822, "content": body.get("content", "")})
                    return

                # Generic Webhook
                if self.path == "/webhook/outbound":
                    idem = body.get("idempotency_key", "")
                    rcpt = f"whrcpt-{len(srv_ref.outbound_requests)}"
                    if idem:
                        srv_ref.receipts[idem] = rcpt
                    self._send(202, {"receipt_id": rcpt})
                    return

                self._send(404, {"error": "unknown_route"})

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None


class TestChannels(unittest.TestCase):
    def setUp(self) -> None:
        base_tmp = REPO_ROOT / ".tmp_test"
        base_tmp.mkdir(parents=True, exist_ok=True)
        self.tmpdir = Path(tempfile.mkdtemp(prefix="chan_", dir=str(base_tmp)))
        self.gw = _MockChannelGatewayServer().start()

    def tearDown(self) -> None:
        self.gw.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_whatsapp_telegram_chatwoot_webhook_auth_replay_and_live_delivery(self) -> None:
        now_ts = int(time.time())
        wa = WhatsAppCloudAdapter(
            WhatsAppConfig(
                enabled=True,
                phone_number_id="1234567890",
                access_token="wa-access-token-secret",
                verify_token="wa-verify-token-secret",
                app_secret="wa-app-secret-key",
                base_url=self.gw.base_url,
            ),
            allow_loopback=True,
        )
        tg = TelegramBotAdapter(
            TelegramConfig(
                enabled=True,
                bot_token="123456:TGSecretBotTokenXYZ",
                webhook_secret_token="tg-webhook-secret",
                base_url=self.gw.base_url,
            ),
            allow_loopback=True,
        )
        cw = ChatwootAdapter(
            ChatwootConfig(
                enabled=True,
                base_url=self.gw.base_url,
                account_id="1",
                api_access_token="cw-api-token-secret",
                webhook_secret="cw-webhook-secret",
            ),
            allow_loopback=True,
        )
        wh = GenericWebhookAdapter(
            GenericWebhookConfig(
                enabled=True,
                inbound_secret="wh-in-secret",
                outbound_url=f"{self.gw.base_url}/webhook/outbound",
                outbound_secret="wh-out-secret",
                receipt_lookup_url=f"{self.gw.base_url}/webhook/receipts",
            ),
            allow_loopback=True,
        )

        # 1. Fail-closed signature checks & replay checks
        self.assertEqual(
            wa.verify_challenge(
                {"hub.mode": "subscribe", "hub.verify_token": "wa-verify-token-secret", "hub.challenge": "ch-99"}
            ),
            "ch-99",
        )
        with self.assertRaises(WebhookSignatureError):
            wa.verify_challenge({"hub.mode": "subscribe", "hub.verify_token": "wrong", "hub.challenge": "x"})

        wa_payload = {
            "entry": [
                {
                    "changes": [
                        {
                            "value": {
                                "contacts": [{"wa_id": "966501234567", "profile": {"name": "عميل_واتساب"}}],
                                "messages": [
                                    {
                                        "id": "wamid.INBOUND.1",
                                        "from": "966501234567",
                                        "timestamp": str(now_ts),
                                        "type": "text",
                                        "text": {"body": f"كم سعر سماعة سوني WH-1000XM5؟ هويتي {SYNTH_SAUDI_ID}"},
                                    }
                                ],
                            }
                        }
                    ]
                }
            ]
        }
        wa_raw = json.dumps(wa_payload).encode("utf-8")
        wa_sig = "sha256=" + compute_hmac_sha256_hex("wa-app-secret-key", wa_raw)
        wa.verify_inbound_request({"X-Hub-Signature-256": wa_sig}, wa_raw)
        with self.assertRaises(WebhookSignatureError):
            wa.verify_inbound_request({"X-Hub-Signature-256": "sha256=" + ("0" * 64)}, wa_raw)

        # Telegram secret token + getUpdates
        tg.verify_inbound_request({"X-Telegram-Bot-Api-Secret-Token": "tg-webhook-secret"}, b"{}")
        with self.assertRaises(WebhookSignatureError):
            tg.verify_inbound_request({"X-Telegram-Bot-Api-Secret-Token": "bad"}, b"{}")
        polled = tg.fetch_updates()
        self.assertEqual(len(polled), 1)
        self.assertEqual(polled[0].channel, "telegram")

        # Chatwoot echo loop ignored + replay window check
        cw_out_payload = {"event": "message_created", "id": 10, "message_type": "outgoing", "content": "bot", "conversation": {"id": 5}}
        self.assertEqual(cw.parse_inbound(cw_out_payload)[0], [])
        cw_old_headers = {
            "X-Chatwoot-Timestamp": "1000",
            "X-Chatwoot-Signature": "sha256=" + compute_hmac_sha256_hex("cw-webhook-secret", b"1000.{}"),
        }
        with self.assertRaises(ReplayError):
            cw.verify_inbound_request(cw_old_headers, b"{}")

        # 2. Full LIVE pipeline integration with RouteStore + MessageShield + cross-customer isolation
        registry = ChannelRegistry({"whatsapp": wa, "telegram": tg, "chatwoot": cw, "webhook": wh})
        routes = EphemeralRouteStore(self.tmpdir / "routes.sqlite3")
        pipe = TijaraGuardPipeline(
            catalog=load_test_catalog(),
            ledger_db_path=self.tmpdir / "ledger.sqlite3",
            approval_secret=make_secret_bytes(),
            contact_hash_key=make_secret_bytes(),
            mode=ExecutionMode.LIVE,
            outbox_db_path=self.tmpdir / "outbox.sqlite3",
            channel_registry=registry,
            route_store=routes,
            allow_loopback_channels=True,
        )

        wa_events, _ = wa.parse_inbound(wa_payload)
        ing1 = pipe.ingest_channel_event(wa_events[0])
        self.assertFalse(ing1["duplicate"])
        self.assertEqual(ing1["verification_status"], "PASS")
        # Duplicate webhook event rejected cleanly
        ing_dup = pipe.ingest_channel_event(wa_events[0])
        self.assertTrue(ing_dup["duplicate"])

        # Ledger DB must NEVER contain raw phone or raw Saudi ID!
        self.assertEqual(
            scan_sqlite_for_secrets(
                self.tmpdir / "ledger.sqlite3",
                [*ALL_SYNTH_PII_SECRETS, "966501234567", SYNTH_PHONE_INTL],
            ),
            [],
        )

        tok = pipe.approve(
            ing1["draft_id"],
            reviewer_id="supervisor_1",
            expected_payload_sha256=ing1["payload_sha256"],
        )

        # Cross-customer recipient_target mismatch must be rejected BEFORE consuming approval
        with self.assertRaises(DeliveryError):
            pipe.dispatch(ing1["draft_id"], tok, recipient_target="966599999999")
        self.assertEqual(pipe.ledger.get_draft(ing1["draft_id"])["state"], DraftState.APPROVED.value)

        # Valid LIVE WhatsApp dispatch (without confirm_delivered so status callback can confirm it!)
        out_wa = pipe.dispatch(ing1["draft_id"], tok, confirm_delivered=False)
        self.assertEqual(out_wa.state, DraftState.ACCEPTED_DELIVERY.value)

        # WhatsApp delivery status webhook callback marks DELIVERED
        st_payload = {
            "entry": [
                {
                    "changes": [
                        {
                            "value": {
                                "statuses": [
                                    {
                                        "id": "wamid.HBgMOTE5OTAwMDAwMDAw",
                                        "status": "delivered",
                                        "timestamp": str(now_ts),
                                    }
                                ]
                            }
                        }
                    ]
                }
            ]
        }
        _, st_events = wa.parse_inbound(st_payload)
        st_res = pipe.process_status_event(st_events[0])
        self.assertTrue(st_res["matched"])
        self.assertEqual(pipe.ledger.get_draft(ing1["draft_id"])["state"], DraftState.DELIVERED.value)

        # Generic webhook UNKNOWN -> recover_delivery via readback URL
        wh_payload = {
            "event_id": "wh-evt-1",
            "conversation_id": "wh-conv-1",
            "target": "customer-endpoint-1",
            "text": "كم سعر ماكينة قهوة ديلونجي EC685؟",
            "consent_to_contact": True,
            "consent_evidence": "webhook_opt_in",
        }
        wh_events, _ = wh.parse_inbound(wh_payload)
        ing_wh = pipe.ingest_channel_event(wh_events[0])
        tok_wh = pipe.approve(
            ing_wh["draft_id"],
            reviewer_id="supervisor_1",
            expected_payload_sha256=ing_wh["payload_sha256"],
        )
        self.gw.fail_next_send = True
        out_wh_unk = pipe.dispatch(ing_wh["draft_id"], tok_wh)
        self.assertEqual(out_wh_unk.state, DraftState.UNKNOWN_DELIVERY.value)
        # Simulate external gateway actually having accepted earlier
        assert out_wh_unk.delivery_key is not None
        self.gw.receipts[out_wh_unk.delivery_key] = "whrcpt-recovered"
        out_wh_rec = pipe.recover_delivery(ing_wh["draft_id"])
        self.assertEqual(out_wh_rec.state, DraftState.DELIVERED.value)

        # Chatwoot private note & human escalation
        cw_in_payload = {
            "event": "message_created",
            "id": 9901,
            "message_type": "incoming",
            "private": False,
            "content": "كم سعر سماعة سوني WH-1000XM5؟",
            "created_at": now_ts,
            "conversation": {"id": 321, "custom_attributes": {"consent_to_contact": True}},
            "sender": {"name": "عميل_شاتووت", "phone_number": SYNTH_PHONE_INTL},
        }
        cw_events, _ = cw.parse_inbound(cw_in_payload)
        ing_cw = pipe.ingest_channel_event(cw_events[0], post_chatwoot_private_note=True)
        self.assertTrue(any(r["body"].get("private") is True for r in self.gw.outbound_requests))
        esc = pipe.escalate(ing_cw["draft_id"], actor="supervisor_1", reason="Needs custom quote")
        self.assertEqual(esc["state"], DraftState.ESCALATED.value)

    def test_non_default_tenant_chatwoot_concurrency_pii_event_and_status_edge_cases(self) -> None:
        from datetime import datetime, timezone
        from tijaraguard.models import ChannelError, PrivacyViolationError
        from tijaraguard.channels.base import ChannelStatusEvent

        now_ts = int(time.time())
        iso_now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        wa = WhatsAppCloudAdapter(
            WhatsAppConfig(
                enabled=True,
                phone_number_id="1234567890",
                access_token="wa-access-token-secret",
                verify_token="wa-verify-token-secret",
                app_secret="wa-app-secret-key",
                base_url=self.gw.base_url,
            ),
            allow_loopback=True,
        )
        tg = TelegramBotAdapter(
            TelegramConfig(
                enabled=True,
                bot_token="123456:TGSecretBotTokenXYZ",
                webhook_secret_token="tg-webhook-secret",
                base_url=self.gw.base_url,
            ),
            allow_loopback=True,
        )
        cw = ChatwootAdapter(
            ChatwootConfig(
                enabled=True,
                base_url=self.gw.base_url,
                account_id="1",
                api_access_token="cw-api-token-secret",
                webhook_secret="cw-webhook-secret",
            ),
            allow_loopback=True,
        )
        wh = GenericWebhookAdapter(
            GenericWebhookConfig(
                enabled=True,
                inbound_secret="wh-in-secret",
                outbound_url=f"{self.gw.base_url}/webhook/outbound",
            ),
            allow_loopback=True,
        )

        # Chatwoot rejects path traversal conversation_id and missing created_at, accepts ISO-8601
        with self.assertRaises(ChannelError):
            cw.parse_inbound(
                {
                    "event": "message_created",
                    "id": 1,
                    "message_type": "incoming",
                    "content": "hello",
                    "created_at": iso_now,
                    "conversation": {"id": "../../admin"},
                }
            )
        with self.assertRaises(ReplayError):
            cw.parse_inbound(
                {
                    "event": "message_created",
                    "id": 2,
                    "message_type": "incoming",
                    "content": "hello",
                    "conversation": {"id": 101},
                }
            )
        # Timestamp-bound Chatwoot signature rejects unbound raw_body signature
        raw_cw = b'{"event":"message_created"}'
        unbound_sig = "sha256=" + compute_hmac_sha256_hex("cw-webhook-secret", raw_cw)
        with self.assertRaises(WebhookSignatureError):
            cw.verify_inbound_request(
                {"X-Chatwoot-Timestamp": str(now_ts), "X-Chatwoot-Signature": unbound_sig},
                raw_cw,
            )

        # Generic webhook ignores untrusted payload tenant_id
        wh_ev, _ = wh.parse_inbound(
            {
                "event_id": "wh-t-1",
                "conversation_id": "wh-c-1",
                "target": "+966500001111",
                "text": "كم سعر سماعة سوني WH-1000XM5؟",
                "tenant_id": "victim_tenant",
            },
            tenant_id="acme",
        )
        self.assertEqual(wh_ev[0].tenant_id, "acme")

        # Non-default tenant 'acme' full pipeline with fresh outbox + concurrent LIVE dispatches
        routes = EphemeralRouteStore(self.tmpdir / "routes_acme.sqlite3")
        pipe = TijaraGuardPipeline(
            catalog=load_test_catalog(),
            ledger_db_path=self.tmpdir / "ledger_acme.sqlite3",
            approval_secret=make_secret_bytes(),
            contact_hash_key=make_secret_bytes(),
            mode=ExecutionMode.LIVE,
            outbox_db_path=self.tmpdir / "fresh_outbox_acme.sqlite3",
            channel_registry=ChannelRegistry({"whatsapp": wa, "telegram": tg, "chatwoot": cw, "webhook": wh}),
            route_store=routes,
            tenant_id="acme",
            allow_loopback_channels=True,
        )

        # Pre-Gate-1 PII in webhook event_id must NEVER touch ledger.sqlite3
        bad_wh_ev, _ = wh.parse_inbound(
            {
                "event_id": SYNTH_SAUDI_ID,
                "conversation_id": "wh-conv-safe",
                "target": "+966500001111",
                "text": "كم سعر سماعة سوني WH-1000XM5؟",
            },
            tenant_id="acme",
        )
        with self.assertRaises(PrivacyViolationError):
            pipe.ingest_channel_event(bad_wh_ev[0])
        self.assertEqual(
            scan_sqlite_for_secrets(self.tmpdir / "ledger_acme.sqlite3", [SYNTH_SAUDI_ID]),
            [],
        )

        # Same Chatwoot customer with two concurrent conversations (101 & 102) routes accurately
        cw_101, _ = cw.parse_inbound(
            {
                "event": "message_created",
                "id": 5001,
                "message_type": "incoming",
                "content": "كم سعر ماكينة قهوة ديلونجي EC685؟",
                "created_at": iso_now,
                "conversation": {"id": 101},
                "sender": {"name": "cust", "phone_number": SYNTH_PHONE_INTL},
            },
            tenant_id="acme",
        )
        cw_102, _ = cw.parse_inbound(
            {
                "event": "message_created",
                "id": 5002,
                "message_type": "incoming",
                "content": "كم سعر ماكينة قهوة ديلونجي EC685؟",
                "created_at": iso_now,
                "conversation": {"id": 102},
                "sender": {"name": "cust", "phone_number": SYNTH_PHONE_INTL},
            },
            tenant_id="acme",
        )
        d101 = pipe.ingest_channel_event(cw_101[0])
        d102 = pipe.ingest_channel_event(cw_102[0])
        self.assertEqual(d101["tenant_id"], "acme")

        # Cross-conversation explicit target rejected
        tok101 = pipe.approve(
            d101["draft_id"],
            reviewer_id="sup",
            expected_payload_sha256=d101["payload_sha256"],
        )
        with self.assertRaises(DeliveryError):
            pipe.dispatch(d101["draft_id"], tok101, recipient_target="102")

        tok102 = pipe.approve(
            d102["draft_id"],
            reviewer_id="sup",
            expected_payload_sha256=d102["payload_sha256"],
        )
        # Concurrent LIVE dispatches succeed cleanly on fresh outbox
        results: List[str] = []
        lock = threading.Lock()
        barrier = threading.Barrier(2)

        def run_disp(did: str, tk: Any) -> None:
            barrier.wait()
            out = pipe.dispatch(did, tk)
            with lock:
                results.append(out.state)

        t1 = threading.Thread(target=run_disp, args=(d101["draft_id"], tok101))
        t2 = threading.Thread(target=run_disp, args=(d102["draft_id"], tok102))
        t1.start()
        t2.start()
        t1.join(timeout=5.0)
        t2.join(timeout=5.0)
        self.assertEqual(results, [DraftState.DELIVERED.value, DraftState.DELIVERED.value])

        # Telegram LIVE dispatch + process_status_event 'failed' handling & non-DELIVERED accuracy
        tg_ev, _ = tg.parse_inbound(
            {
                "update_id": 7001,
                "message": {
                    "message_id": 12,
                    "date": now_ts,
                    "chat": {"id": 998877},
                    "from": {"username": "tg_acme_user"},
                    "text": "كم سعر ماكينة قهوة ديلونجي EC685؟",
                },
            },
            tenant_id="acme",
        )
        ing_tg = pipe.ingest_channel_event(tg_ev[0])
        tok_tg = pipe.approve(
            ing_tg["draft_id"],
            reviewer_id="sup",
            expected_payload_sha256=ing_tg["payload_sha256"],
        )
        out_tg = pipe.dispatch(ing_tg["draft_id"], tok_tg, confirm_delivered=False)
        self.assertEqual(out_tg.state, DraftState.ACCEPTED_DELIVERY.value)

        # Async WhatsApp/channel failed status transitions ACCEPTED_DELIVERY -> FAILED_DELIVERY
        st_fail = pipe.process_status_event(
            ChannelStatusEvent(
                channel="telegram",
                external_event_id="st-fail-1",
                external_message_id="7711",
                status="failed",
                timestamp=float(now_ts),
                error="blocked_by_user",
            )
        )
        self.assertEqual(st_fail["state"], DraftState.FAILED_DELIVERY.value)
        # Subsequent delivered callback on FAILED_DELIVERY must NOT claim DELIVERED
        st_late = pipe.process_status_event(
            ChannelStatusEvent(
                channel="telegram",
                external_event_id="st-late-1",
                external_message_id="7711",
                status="delivered",
                timestamp=float(now_ts),
            )
        )
        self.assertEqual(st_late["state"], DraftState.FAILED_DELIVERY.value)
