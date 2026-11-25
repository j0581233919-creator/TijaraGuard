"""Real local HTTP server tests for OpenAI-compat, Anthropic, Gemini, Ollama, and ModelRouter."""

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

from tijaraguard.config import ProviderEndpointConfig, RoutingConfig
from tijaraguard.models import ExecutionMode, PrivacyViolationError
from tijaraguard.pipeline import TijaraGuardPipeline
from tijaraguard.privacy import PrivacyGate
from tijaraguard.providers import (
    AIRequest,
    AnthropicProvider,
    GeminiProvider,
    ModelRouter,
    OllamaProvider,
    OpenAICompatibleProvider,
    ProviderErrorCode,
    ProviderExecutionError,
    TaskComplexity,
)

from helpers import REPO_ROOT, SYNTH_GCC_IBAN, SYNTH_SAUDI_ID, load_test_catalog, make_inbound_message, make_secret_bytes


class _MockAIHTTPServer:
    """Controlled local HTTP server implementing official provider wire contracts."""

    def __init__(self) -> None:
        self.requests: List[Dict[str, Any]] = []
        self.openai_calls = 0
        self.mode = "ok"  # ok | rate_limit_once | auth_error | timeout | server_error
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        assert self._server is not None
        return f"http://127.0.0.1:{self._server.server_port}"

    def start(self) -> "_MockAIHTTPServer":
        srv_ref = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send(self, code: int, obj: Dict[str, Any], headers: Dict[str, str] | None = None) -> None:
                raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                if headers:
                    for k, v in headers.items():
                        self.send_header(k, v)
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return

            def do_GET(self) -> None:
                if self.path.endswith("/models") or self.path.endswith("/api/tags"):
                    if srv_ref.mode == "auth_error":
                        self._send(401, {"error": {"message": "Invalid API key"}})
                        return
                    self._send(200, {"data": [{"id": "mock-model"}], "models": [{"name": "qwen2.5:7b"}]})
                    return
                self._send(404, {"error": "not_found"})

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or "0")
                raw = self.rfile.read(length) if length > 0 else b"{}"
                body = json.loads(raw.decode("utf-8"))
                srv_ref.requests.append(
                    {
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                        "body": body,
                    }
                )

                if srv_ref.mode == "auth_error":
                    self._send(401, {"error": {"message": "Unauthorized"}})
                    return
                if srv_ref.mode == "server_error":
                    self._send(500, {"error": {"message": "Upstream overloaded"}})
                    return
                if srv_ref.mode == "timeout":
                    time.sleep(1.2)
                    self._send(200, {"ok": True})
                    return

                # OpenAI-compatible (/v1/chat/completions)
                if self.path.endswith("/chat/completions"):
                    srv_ref.openai_calls += 1
                    if srv_ref.mode == "rate_limit_once" and srv_ref.openai_calls == 1:
                        self._send(
                            429,
                            {"error": {"message": "Rate limit hit"}},
                            headers={"Retry-After": "0.05"},
                        )
                        return
                    self._send(
                        200,
                        {
                            "id": "chatcmpl-mock-1",
                            "model": body.get("model", "gpt-4o-mini"),
                            "choices": [
                                {
                                    "index": 0,
                                    "message": {
                                        "role": "assistant",
                                        "content": "مرحباً، يسعدنا الرد بخصوص سماعة سوني WH-1000XM5 (رمز المنتج: SONY-WH1000XM5). المنتج متوفر لدينا حالياً بسعر 1080.00 SAR مع خصم 10% (السعر الأساسي: 1200.00 SAR).",
                                    },
                                    "finish_reason": "stop",
                                }
                            ],
                            "usage": {
                                "prompt_tokens": 50,
                                "completion_tokens": 25,
                                "total_tokens": 75,
                            },
                        },
                    )
                    return

                # Anthropic (/v1/messages)
                if self.path.endswith("/messages"):
                    self._send(
                        200,
                        {
                            "id": "msg-anth-1",
                            "model": body.get("model", "claude-3-5-haiku-latest"),
                            "content": [
                                {
                                    "type": "text",
                                    "text": "مرحباً، يسعدنا الرد بخصوص سماعة سوني WH-1000XM5 (رمز المنتج: SONY-WH1000XM5). المنتج متوفر لدينا حالياً بسعر 1080.00 SAR مع خصم 10% (السعر الأساسي: 1200.00 SAR).",
                                }
                            ],
                            "stop_reason": "end_turn",
                            "usage": {"input_tokens": 40, "output_tokens": 20},
                        },
                    )
                    return

                # Gemini (/v1beta/models/...:generateContent)
                if ":generateContent" in self.path:
                    self._send(
                        200,
                        {
                            "candidates": [
                                {
                                    "content": {
                                        "parts": [
                                            {
                                                "text": "مرحباً، ماكينة قهوة ديلونجي EC685 متوفرة بسعر 850.00 SAR."
                                            }
                                        ]
                                    },
                                    "finishReason": "STOP",
                                }
                            ],
                            "usageMetadata": {
                                "promptTokenCount": 30,
                                "candidatesTokenCount": 18,
                                "totalTokenCount": 48,
                            },
                        },
                    )
                    return

                # Ollama (/api/chat)
                if self.path.endswith("/api/chat"):
                    self._send(
                        200,
                        {
                            "model": body.get("model", "qwen2.5:7b"),
                            "message": {
                                "role": "assistant",
                                "content": "مرحباً، السعر الرسمي هو 850.00 SAR.",
                            },
                            "done_reason": "stop",
                            "prompt_eval_count": 20,
                            "eval_count": 12,
                        },
                    )
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


class TestProviders(unittest.TestCase):
    def setUp(self) -> None:
        base_tmp = REPO_ROOT / ".tmp_test"
        base_tmp.mkdir(parents=True, exist_ok=True)
        self.tmpdir = Path(tempfile.mkdtemp(prefix="prov_", dir=str(base_tmp)))
        self.srv = _MockAIHTTPServer().start()

    def tearDown(self) -> None:
        self.srv.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_all_provider_protocols_and_health_checks(self) -> None:
        # 1. OpenAI-compatible (with 429 retry-after recovery)
        self.srv.mode = "rate_limit_once"
        openai_cfg = ProviderEndpointConfig(
            name="openai",
            kind="openai_compat",
            model="gpt-4o-mini",
            base_url=f"{self.srv.base_url}/v1",
            api_key="sk-test-openai-key",
            max_retries=1,
            input_cost_per_1k=0.001,
            output_cost_per_1k=0.002,
        )
        oai = OpenAICompatibleProvider(openai_cfg, allow_loopback=True)
        resp_oai = oai.generate(AIRequest(system_prompt="sys", user_prompt="usr"))
        self.assertEqual(resp_oai.usage.total_tokens, 75)
        self.assertIsNotNone(resp_oai.usage.estimated_cost_usd)
        self.assertEqual(self.srv.openai_calls, 2)
        self.assertTrue(oai.health_check().healthy)

        # 2. Anthropic Messages API
        self.srv.mode = "ok"
        anth = AnthropicProvider(
            ProviderEndpointConfig(
                name="anthropic",
                kind="anthropic",
                model="claude-3-5-haiku-latest",
                base_url=f"{self.srv.base_url}/v1",
                api_key="sk-ant-test-key",
            ),
            allow_loopback=True,
        )
        resp_anth = anth.generate(AIRequest(system_prompt="sys", user_prompt="usr"))
        self.assertIn("1080.00 SAR", resp_anth.content)
        self.assertEqual(resp_anth.usage.total_tokens, 60)
        anth_req = self.srv.requests[-1]
        self.assertEqual(anth_req["headers"].get("x-api-key"), "sk-ant-test-key")
        self.assertEqual(anth_req["headers"].get("anthropic-version"), "2023-06-01")
        self.assertTrue(anth.health_check().healthy)

        # 3. Gemini API (API key strictly in header, never query string)
        gem = GeminiProvider(
            ProviderEndpointConfig(
                name="gemini",
                kind="gemini",
                model="gemini-2.0-flash",
                base_url=f"{self.srv.base_url}/v1beta",
                api_key="AIzaTestGeminiHeaderOnlyKey",
            ),
            allow_loopback=True,
        )
        resp_gem = gem.generate(AIRequest(system_prompt="sys", user_prompt="usr"))
        self.assertIn("850.00 SAR", resp_gem.content)
        gem_req = self.srv.requests[-1]
        self.assertNotIn("key=", gem_req["path"])
        self.assertEqual(gem_req["headers"].get("x-goog-api-key"), "AIzaTestGeminiHeaderOnlyKey")
        self.assertTrue(gem.health_check().healthy)

        # 4. Optional Ollama
        oll = OllamaProvider(
            ProviderEndpointConfig(
                name="ollama",
                kind="ollama",
                model="qwen2.5:7b",
                base_url=self.srv.base_url,
            ),
            allow_loopback=True,
        )
        resp_oll = oll.generate(AIRequest(system_prompt="sys", user_prompt="usr"))
        self.assertIn("850.00 SAR", resp_oll.content)
        self.assertTrue(oll.health_check().healthy)

    def test_timeout_auth_error_explicit_fallback_and_pre_send_pii_block(self) -> None:
        gate = PrivacyGate(contact_hash_key=make_secret_bytes())

        # Timeout classification
        self.srv.mode = "timeout"
        p_timeout = OpenAICompatibleProvider(
            ProviderEndpointConfig(
                name="primary_fast",
                kind="openai_compat",
                model="gpt-4o-mini",
                base_url=f"{self.srv.base_url}/v1",
                api_key="sk-secret-abc-1234",
                timeout_seconds=0.25,
                max_retries=0,
            ),
            allow_loopback=True,
        )
        with self.assertRaises(ProviderExecutionError) as ctx_to:
            p_timeout.generate(AIRequest(system_prompt="sys", user_prompt="usr"))
        self.assertEqual(ctx_to.exception.code, ProviderErrorCode.TIMEOUT)
        self.assertNotIn("sk-secret-abc-1234", str(ctx_to.exception))

        # Auth error classification & NO silent fallback when allow_fallback=False
        self.srv.mode = "auth_error"
        p_bad = OpenAICompatibleProvider(
            ProviderEndpointConfig(
                name="primary_auth_bad",
                kind="openai_compat",
                model="gpt-4o-mini",
                base_url=f"{self.srv.base_url}/v1",
                api_key="sk-bad-secret-9999",
                max_retries=0,
            ),
            allow_loopback=True,
        )
        p_good = GeminiProvider(
            ProviderEndpointConfig(
                name="fallback_gemini",
                kind="gemini",
                model="gemini-2.0-flash",
                base_url=f"{self.srv.base_url}/v1beta",
                api_key="AIzaValidKey99999",
                max_retries=0,
            ),
            allow_loopback=True,
        )
        router_strict = ModelRouter(
            providers={"primary_auth_bad": p_bad, "fallback_gemini": p_good},
            routing=RoutingConfig(
                default_provider="primary_auth_bad",
                allow_fallback=False,
                fallback_chain=("fallback_gemini",),
            ),
            privacy_gate=gate,
        )
        with self.assertRaises(ProviderExecutionError) as ctx_auth:
            router_strict.generate(AIRequest(system_prompt="sys", user_prompt="usr"))
        self.assertEqual(ctx_auth.exception.code, ProviderErrorCode.AUTH_ERROR)
        self.assertNotIn("sk-bad-secret-9999", str(ctx_auth.exception))

        # Pre-send PII guard blocks raw PII before any HTTP request is made
        req_count_before = len(self.srv.requests)
        with self.assertRaises(PrivacyViolationError):
            router_strict.generate(
                AIRequest(
                    system_prompt="sys",
                    user_prompt=f"Customer ID {SYNTH_SAUDI_ID} and IBAN {SYNTH_GCC_IBAN}",
                )
            )
        self.assertEqual(len(self.srv.requests), req_count_before)

    def test_pipeline_with_cloud_provider_without_ollama_and_failure_preserves_state(self) -> None:
        # Cloud-only router (zero Ollama configured) works seamlessly with 4-gate pipeline
        attempts: List[Dict[str, Any]] = []
        oai = OpenAICompatibleProvider(
            ProviderEndpointConfig(
                name="openai",
                kind="openai_compat",
                model="gpt-4o-mini",
                base_url=f"{self.srv.base_url}/v1",
                api_key="sk-cloud-only-key",
                max_retries=0,
            ),
            allow_loopback=True,
        )
        anth = AnthropicProvider(
            ProviderEndpointConfig(
                name="anthropic",
                kind="anthropic",
                model="claude-3-5-haiku-latest",
                base_url=f"{self.srv.base_url}/v1",
                api_key="sk-ant-cloud-key",
                max_retries=0,
            ),
            allow_loopback=True,
        )
        router = ModelRouter(
            providers={"openai": oai, "anthropic": anth},
            routing=RoutingConfig(
                default_provider="openai",
                tier_routes={"complex": "anthropic"},
                allow_fallback=True,
                fallback_chain=("anthropic",),
            ),
            on_attempt=attempts.append,
        )
        pipe = TijaraGuardPipeline(
            catalog=load_test_catalog(),
            ledger_db_path=self.tmpdir / "ledger.sqlite3",
            approval_secret=make_secret_bytes(),
            contact_hash_key=make_secret_bytes(),
            mode=ExecutionMode.SHADOW,
            ai_router=router,
            fallback_to_template_on_ai_error=False,
        )
        msg = make_inbound_message(
            message_id="msg-ai-cloud-1",
            raw_text=f"كم سعر سماعة سوني WH-1000XM5؟ هويتي {SYNTH_SAUDI_ID}",
        )
        res = pipe.process_inbound(msg)
        self.assertEqual(res["verification_status"], "PASS")
        self.assertEqual(res["ai_provider"], "openai")
        # Ensure raw Saudi ID was never sent in outbound AI prompt!
        last_body = json.dumps(self.srv.requests[-1]["body"], ensure_ascii=False)
        self.assertNotIn(SYNTH_SAUDI_ID, last_body)

        # Complex tier routes to Anthropic
        res_complex = pipe.process_inbound(
            make_inbound_message(
                message_id="msg-ai-complex",
                raw_text="كم سعر سماعة سوني WH-1000XM5؟",
                requested_sku="SONY-WH1000XM5",
            ),
            task_complexity=TaskComplexity.COMPLEX,
        )
        self.assertEqual(res_complex["ai_provider"], "anthropic")

        # Provider failure with fallback_to_template_on_ai_error=False must NOT corrupt ledger
        self.srv.mode = "server_error"
        drafts_before = len(pipe.ledger.list_drafts())
        with self.assertRaises(ProviderExecutionError):
            pipe.process_inbound(
                make_inbound_message(
                    message_id="msg-ai-fail",
                    raw_text="كم سعر سماعة سوني WH-1000XM5؟",
                    requested_sku="SONY-WH1000XM5",
                )
            )
        self.assertEqual(len(pipe.ledger.list_drafts()), drafts_before)
        chain_ok, _ = pipe.ledger.verify_audit_chain()
        self.assertTrue(chain_ok)
