"""End-to-end product scenarios combining Arabic dialects, Cloud AI, all 4 gates, and live channel delivery."""

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

from tijaraguard.channels import ChannelRegistry, WhatsAppCloudAdapter
from tijaraguard.config import ProviderEndpointConfig, RoutingConfig, WhatsAppConfig
from tijaraguard.ledger import EphemeralRouteStore
from tijaraguard.models import DraftState, ExecutionMode
from tijaraguard.pipeline import TijaraGuardPipeline
from tijaraguard.providers import ModelRouter, OpenAICompatibleProvider

from helpers import (
    ALL_SYNTH_PII_SECRETS,
    REPO_ROOT,
    SYNTH_GCC_IBAN,
    SYNTH_PHONE_INTL,
    SYNTH_SAUDI_ID,
    load_test_catalog,
    make_secret_bytes,
    scan_sqlite_for_secrets,
)


class _E2ECloudAndWhatsAppServer:
    def __init__(self) -> None:
        self.ai_prompts: List[str] = []
        self.wa_outbound: List[Dict[str, Any]] = []
        self.hallucinate = False
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        assert self._server is not None
        return f"http://127.0.0.1:{self._server.server_port}"

    def start(self) -> "_E2ECloudAndWhatsAppServer":
        ref = self

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

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or "0")
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                if self.path.endswith("/chat/completions"):
                    ref.ai_prompts.append(json.dumps(body, ensure_ascii=False))
                    reply = (
                        "سعر ماكينة ديلونجي EC685 هو 99.00 SAR مع ضمان 10 سنوات!"
                        if ref.hallucinate
                        else "مرحباً، يسعدنا الرد بخصوص ماكينة قهوة ديلونجي EC685 (رمز المنتج: DELONGHI-EC685). المنتج متوفر لدينا حالياً بسعر 850.00 SAR."
                    )
                    self._send(
                        200,
                        {
                            "id": "cmpl-e2e",
                            "model": "gpt-4o-mini",
                            "choices": [{"message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}],
                            "usage": {"prompt_tokens": 45, "completion_tokens": 22, "total_tokens": 67},
                        },
                    )
                    return

                if self.path.endswith("/messages"):
                    ref.wa_outbound.append(body)
                    self._send(200, {"messages": [{"id": f"wamid.OUT.{len(ref.wa_outbound)}"}]})
                    return
                self._send(404, {"error": "not_found"})

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


class TestE2EProduct(unittest.TestCase):
    def setUp(self) -> None:
        base_tmp = REPO_ROOT / ".tmp_test"
        base_tmp.mkdir(parents=True, exist_ok=True)
        self.tmpdir = Path(tempfile.mkdtemp(prefix="e2eprod_", dir=str(base_tmp)))
        self.srv = _E2ECloudAndWhatsAppServer().start()

    def tearDown(self) -> None:
        self.srv.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_arabic_egyptian_and_gulf_e2e_whatsapp_with_cloud_ai_and_zero_pii(self) -> None:
        oai = OpenAICompatibleProvider(
            ProviderEndpointConfig(
                name="openai",
                kind="openai_compat",
                model="gpt-4o-mini",
                base_url=f"{self.srv.base_url}/v1",
                api_key="sk-e2e-secret-key",
            ),
            allow_loopback=True,
        )
        router = ModelRouter(
            providers={"openai": oai},
            routing=RoutingConfig(default_provider="openai"),
        )
        wa = WhatsAppCloudAdapter(
            WhatsAppConfig(
                enabled=True,
                phone_number_id="555000111",
                access_token="wa-e2e-token",
                verify_token="wa-e2e-verify",
                app_secret="wa-e2e-secret",
                base_url=self.srv.base_url,
            ),
            allow_loopback=True,
        )
        routes = EphemeralRouteStore(self.tmpdir / "routes.sqlite3")
        pipe = TijaraGuardPipeline(
            catalog=load_test_catalog(),
            ledger_db_path=self.tmpdir / "ledger.sqlite3",
            approval_secret=make_secret_bytes(),
            contact_hash_key=make_secret_bytes(),
            mode=ExecutionMode.LIVE,
            outbox_db_path=self.tmpdir / "outbox.sqlite3",
            ai_router=router,
            channel_registry=ChannelRegistry({"whatsapp": wa}),
            route_store=routes,
            allow_loopback_channels=True,
        )

        # 1. Egyptian dialect inquiry containing Saudi ID & GCC IBAN -> Gate 1 redacts -> Cloud AI -> Gate 2 passes -> Gate 3 approve -> Gate 4 WhatsApp send
        now_ts = int(time.time())
        inbound_payload = {
            "entry": [
                {
                    "changes": [
                        {
                            "value": {
                                "contacts": [{"wa_id": "966501234567", "profile": {"name": "عميل_مصري"}}],
                                "messages": [
                                    {
                                        "id": "wamid.EGY.1",
                                        "from": "966501234567",
                                        "timestamp": str(now_ts),
                                        "type": "text",
                                        "text": {
                                            "body": f"بكام ماكينة قهوة ديلونجي EC685؟ هويتي {SYNTH_SAUDI_ID} والايبان {SYNTH_GCC_IBAN}"
                                        },
                                    }
                                ],
                            }
                        }
                    ]
                }
            ]
        }
        ev_list, _ = wa.parse_inbound(inbound_payload)
        res = pipe.ingest_channel_event(ev_list[0])
        self.assertEqual(res["sku"], "DELONGHI-EC685")
        self.assertEqual(res["detected_dialect"], "EGYPTIAN")
        self.assertEqual(res["verification_status"], "PASS")
        self.assertEqual(res["ai_provider"], "openai")

        # Verify ZERO PII reached Cloud AI prompt
        for prompt_str in self.srv.ai_prompts:
            self.assertNotIn(SYNTH_SAUDI_ID, prompt_str)
            self.assertNotIn(SYNTH_GCC_IBAN, prompt_str)
            self.assertNotIn("966501234567", prompt_str)

        tok = pipe.approve(
            res["draft_id"],
            reviewer_id="supervisor_noura",
            expected_payload_sha256=res["payload_sha256"],
        )
        outcome = pipe.dispatch(res["draft_id"], tok)
        self.assertEqual(outcome.state, DraftState.DELIVERED.value)
        self.assertEqual(len(self.srv.wa_outbound), 1)
        self.assertEqual(self.srv.wa_outbound[0]["to"], "966501234567")

        # 2. Hallucinating Cloud AI is deterministically blocked by Gate 2
        self.srv.hallucinate = True
        hallu_payload = {
            "entry": [
                {
                    "changes": [
                        {
                            "value": {
                                "contacts": [{"wa_id": "966501234567", "profile": {"name": "عميل_مصري"}}],
                                "messages": [
                                    {
                                        "id": "wamid.EGY.2",
                                        "from": "966501234567",
                                        "timestamp": str(now_ts),
                                        "type": "text",
                                        "text": {"body": "بكام ماكينة قهوة ديلونجي EC685؟"},
                                    }
                                ],
                            }
                        }
                    ]
                }
            ]
        }
        ev_hallu, _ = wa.parse_inbound(hallu_payload)
        res_hallu = pipe.ingest_channel_event(ev_hallu[0])
        self.assertEqual(res_hallu["verification_status"], "FAIL")
        self.assertEqual(res_hallu["state"], DraftState.VERIFIED_BLOCKED.value)

        # Ledger and outbox DBs remain 100% free of raw PII
        for db_name in ("ledger.sqlite3", "outbox.sqlite3"):
            self.assertEqual(
                scan_sqlite_for_secrets(
                    self.tmpdir / db_name,
                    [*ALL_SYNTH_PII_SECRETS, "966501234567", SYNTH_PHONE_INTL],
                ),
                [],
            )
        chain_ok, errs = pipe.ledger.verify_audit_chain()
        self.assertTrue(chain_ok, errs)
