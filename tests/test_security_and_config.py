"""Security controls and configuration validation tests."""

from __future__ import annotations

import logging
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
_TESTS_DIR = Path(__file__).resolve().parent
_ROOT = _TESTS_DIR.parent
for _p in (str(_TESTS_DIR), str(_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from tijaraguard.config import load_config, validate_config
from tijaraguard.privacy import PrivacyGate
from tijaraguard.security import (
    SSRFError,
    SecretAndPIIRedactingLogFilter,
    SlidingWindowRateLimiter,
    compute_hmac_sha256_hex,
    sanitize_csv_cell,
    scrub_secrets_from_text,
    validate_outbound_url,
    verify_bearer_or_api_key,
    verify_hmac_sha256,
    verify_timestamp_window,
)

from helpers import CATALOG_PATH, REPO_ROOT, SYNTH_GCC_IBAN, SYNTH_SAUDI_ID, make_secret_bytes


class TestSecurityAndConfig(unittest.TestCase):
    def setUp(self) -> None:
        base_tmp = REPO_ROOT / ".tmp_test"
        base_tmp.mkdir(parents=True, exist_ok=True)
        self.tmpdir = Path(tempfile.mkdtemp(prefix="sec_", dir=str(base_tmp)))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_ssrf_blocks_metadata_private_loopback_http_and_credentials(self) -> None:
        blocked_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "https://169.254.169.254/latest/meta-data/",
            "https://10.0.0.1/internal",
            "https://192.168.1.10/admin",
            "https://100.64.0.1/cgnat",
            "https://100.100.100.200/metadata",
            "https://[::ffff:127.0.0.1]/loopback",
            "https://[2002:7f00:0001::]/6to4",
            "https://127.0.0.1:8080/secret",
            "http://api.openai.com/v1",
            "https://user:pass@api.openai.com/v1",
            "https://api.openai.com/v1#frag",
            "https://localhost/api",
            "ftp://example.com/file",
            "https://example.com:99999/v1",
            "https://example.com:abc/v1",
        ]
        for bad_url in blocked_urls:
            with self.assertRaises(SSRFError, msg=f"Expected SSRFError for {bad_url}"):
                validate_outbound_url(bad_url)

        # require_dns=True must fail closed on unresolvable/non-existent hostname
        with self.assertRaises(SSRFError):
            validate_outbound_url("https://nonexistent.invalid.tijaraguard.test/v1", require_dns=True)

        # Hostname localhost still blocked even when allow_loopback=True
        with self.assertRaises(SSRFError):
            validate_outbound_url("http://localhost:11434", allow_loopback=True, allow_http_loopback=True)

        self.assertEqual(
            validate_outbound_url("https://api.openai.com/v1/"),
            "https://api.openai.com/v1",
        )
        self.assertEqual(
            validate_outbound_url(
                "http://127.0.0.1:11434/",
                allow_loopback=True,
                allow_http_loopback=True,
            ),
            "http://127.0.0.1:11434",
        )

    def test_hmac_timestamp_and_api_key_verification(self) -> None:
        secret = "test_webhook_secret_123456"
        body = b'{"hello":"world"}'
        sig = "sha256=" + compute_hmac_sha256_hex(secret, body)
        self.assertTrue(verify_hmac_sha256(secret, body, sig))
        self.assertFalse(verify_hmac_sha256(secret, b'{"hello":"evil"}', sig))
        self.assertFalse(verify_hmac_sha256(secret, body, "sha256=" + ("z" * 64)))
        self.assertFalse(verify_hmac_sha256("", body, sig))

        self.assertTrue(verify_timestamp_window(1000.0, max_skew_seconds=300, now=1200.0))
        self.assertFalse(verify_timestamp_window(1000.0, max_skew_seconds=300, now=1500.0))
        self.assertFalse(verify_timestamp_window(float("nan"), max_skew_seconds=300, now=1200.0))

        # Fail closed when expected_key is empty/None
        self.assertFalse(verify_bearer_or_api_key({"Authorization": "Bearer abc"}, None))
        self.assertFalse(verify_bearer_or_api_key({"Authorization": "Bearer abc"}, ""))
        self.assertTrue(
            verify_bearer_or_api_key({"Authorization": "Bearer my-op-key"}, "my-op-key")
        )
        self.assertTrue(verify_bearer_or_api_key({"X-API-Key": "my-op-key"}, "my-op-key"))
        self.assertFalse(verify_bearer_or_api_key({"X-API-Key": "wrong"}, "my-op-key"))

    def test_rate_limiter_csv_injection_and_secret_log_scrubbing(self) -> None:
        rl = SlidingWindowRateLimiter(max_requests=2, window_seconds=10.0)
        self.assertTrue(rl.check("1.2.3.4", now=10.0)[0])
        self.assertTrue(rl.check("1.2.3.4", now=11.0)[0])
        allowed, retry_after = rl.check("1.2.3.4", now=12.0)
        self.assertFalse(allowed)
        self.assertGreater(retry_after, 0.0)
        self.assertTrue(rl.check("1.2.3.4", now=21.0)[0])

        self.assertEqual(sanitize_csv_cell("=CMD('calc')"), "'=CMD('calc')")
        self.assertEqual(sanitize_csv_cell("+1+1"), "'+1+1")
        self.assertEqual(sanitize_csv_cell(" -2"), "' -2")
        self.assertEqual(sanitize_csv_cell("\n=1+1"), "'\n=1+1")
        self.assertEqual(sanitize_csv_cell("@SUM(A1)"), "'@SUM(A1)")
        self.assertEqual(sanitize_csv_cell("normal_id"), "normal_id")

        raw = (
            "POST https://api.telegram.org/bot123456:AAFakeBotSecretToken123/sendMessage "
            "Authorization: Bearer sk-testsecret1234567890 AIzaFakeGeminiKey1234567890 "
            "x-goog-api-key: GeminiSecretHeaderVal"
        )
        cleaned = scrub_secrets_from_text(raw, ("explicit-secret-xyz",))
        self.assertNotIn("AAFakeBotSecretToken123", cleaned)
        self.assertNotIn("sk-testsecret1234567890", cleaned)
        self.assertNotIn("AIzaFakeGeminiKey1234567890", cleaned)
        self.assertNotIn("GeminiSecretHeaderVal", cleaned)

        gate = PrivacyGate(contact_hash_key=make_secret_bytes())
        flt = SecretAndPIIRedactingLogFilter(
            privacy_gate=gate,
            secrets_provider=lambda: ["super-secret-value-99"],
        )
        try:
            raise RuntimeError(f"boom {SYNTH_SAUDI_ID} super-secret-value-99")
        except RuntimeError:
            exc_info = sys.exc_info()
            record = logging.LogRecord(
                name="tijaraguard.pipeline",
                level=logging.ERROR,
                pathname=__file__,
                lineno=1,
                msg="secret=%s id=%s iban=%s",
                args=("super-secret-value-99", SYNTH_SAUDI_ID, SYNTH_GCC_IBAN),
                exc_info=exc_info,
            )
        flt.filter(record)
        msg = record.getMessage()
        self.assertNotIn("super-secret-value-99", msg)
        self.assertNotIn(SYNTH_SAUDI_ID, msg)
        self.assertNotIn(SYNTH_GCC_IBAN, msg)
        self.assertNotIn("super-secret-value-99", record.exc_text or "")
        self.assertNotIn(SYNTH_SAUDI_ID, record.exc_text or "")

    def test_config_validation_rejects_live_ephemeral_secrets_and_unauthenticated_nonloopback(self) -> None:
        env_bad = {
            "TIJARAGUARD_MODE": "LIVE",
            "TIJARAGUARD_STATE_DIR": str(self.tmpdir / "state"),
            "TIJARAGUARD_CATALOG_PATH": str(CATALOG_PATH),
            "TIJARAGUARD_HOST": "0.0.0.0",
        }
        cfg_bad = load_config(env=env_bad)
        rep_bad = validate_config(cfg_bad)
        self.assertFalse(rep_bad["valid"])
        self.assertTrue(any("LIVE mode requires persistent secrets" in e for e in rep_bad["errors"]))
        self.assertTrue(any("TIJARAGUARD_API_KEY" in e for e in rep_bad["errors"]))

        env_good = {
            "TIJARAGUARD_MODE": "LIVE",
            "TIJARAGUARD_STATE_DIR": str(self.tmpdir / "state"),
            "TIJARAGUARD_CATALOG_PATH": str(CATALOG_PATH),
            "TIJARAGUARD_APPROVAL_SECRET": "a" * 64,
            "TIJARAGUARD_CONTACT_HASH_KEY": "b" * 64,
            "TIJARAGUARD_API_KEY": "operator-secret-key-2026",
            "TIJARAGUARD_HOST": "0.0.0.0",
            "OPENAI_API_KEY": "sk-test-1234567890",
            "OPENAI_MODEL": "gpt-4o-mini",
        }
        cfg_good = load_config(env=env_good)
        rep_good = validate_config(cfg_good)
        self.assertTrue(rep_good["valid"], f"Unexpected errors: {rep_good['errors']}")
        # Public summary must never leak secrets
        pub_str = str(rep_good["summary"])
        self.assertNotIn("operator-secret-key-2026", pub_str)
        self.assertNotIn("sk-test-1234567890", pub_str)
        self.assertNotIn("a" * 64, pub_str)

        # .env.example must NOT auto-enable Ollama
        env_ex: dict[str, str] = {}
        for line in (REPO_ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if v.strip():
                env_ex[k.strip()] = v.strip()
        env_ex["TIJARAGUARD_CATALOG_PATH"] = str(CATALOG_PATH)
        cfg_ex = load_config(env=env_ex)
        self.assertNotIn("ollama", cfg_ex.providers)

        # receipt_lookup_url SSRF rejected
        cfg_wh_bad = load_config(
            env={
                "TIJARAGUARD_CATALOG_PATH": str(CATALOG_PATH),
                "TIJARAGUARD_WEBHOOK_ENABLED": "true",
                "TIJARAGUARD_WEBHOOK_LOOKUP_URL": "http://169.254.169.254/latest",
            }
        )
        rep_wh_bad = validate_config(cfg_wh_bad)
        self.assertFalse(rep_wh_bad["valid"])
        self.assertTrue(any("receipt_lookup_url" in e for e in rep_wh_bad["errors"]))

        # String "false" in JSON provider enabled must NOT coerce via bool() to True
        import json

        cfg_file = self.tmpdir / "providers_str_bool.json"
        cfg_file.write_text(
            json.dumps(
                {
                    "providers": {
                        "p1": {
                            "kind": "openai_compat",
                            "model": "gpt-4o-mini",
                            "base_url": "https://api.openai.com/v1",
                            "api_key": "sk-test-disabled",
                            "enabled": "false",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        cfg_str_bool = load_config(
            config_file=cfg_file,
            env={"TIJARAGUARD_CATALOG_PATH": str(CATALOG_PATH)},
        )
        self.assertFalse(cfg_str_bool.providers["p1"].enabled)
