"""Gate 1 (BayanGate) privacy redaction and zero-leakage tests."""

from __future__ import annotations

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

from tijaraguard.models import ExecutionMode, InboundMessage, MalformedInputError, PrivacyViolationError
from tijaraguard.pipeline import TijaraGuardPipeline
from tijaraguard.privacy import EntityType, MaskingPolicy, PrivacyGate

from helpers import (
    ALL_SYNTH_PII_SECRETS,
    REPO_ROOT,
    SYNTH_EMAIL,
    SYNTH_GCC_IBAN,
    SYNTH_INVALID_ID,
    SYNTH_IQAMA,
    SYNTH_PHONE_AR_INDIC,
    SYNTH_PHONE_INTL,
    SYNTH_SAUDI_ID,
    capture_tijaraguard_logs,
    load_test_catalog,
    make_inbound_message,
    make_secret_bytes,
    scan_sqlite_for_secrets,
)


class TestGate1Privacy(unittest.TestCase):
    def setUp(self) -> None:
        base_tmp = REPO_ROOT / ".tmp_test"
        base_tmp.mkdir(parents=True, exist_ok=True)
        self.tmpdir = Path(tempfile.mkdtemp(prefix="g1_", dir=str(base_tmp)))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_redacts_saudi_id_iqama_iban_and_phones(self) -> None:
        gate = PrivacyGate(contact_hash_key=make_secret_bytes())
        text = (
            f"هويتي {SYNTH_SAUDI_ID} وإقامتي {SYNTH_IQAMA} "
            f"والايبان {SYNTH_GCC_IBAN} ورقمي {SYNTH_PHONE_INTL} أو {SYNTH_PHONE_AR_INDIC}"
        )
        redacted, meta = gate.redact_text(text)

        for secret_val in (
            SYNTH_SAUDI_ID,
            SYNTH_IQAMA,
            SYNTH_GCC_IBAN,
            SYNTH_PHONE_INTL,
            SYNTH_PHONE_AR_INDIC,
        ):
            self.assertNotIn(secret_val, redacted)

        self.assertGreaterEqual(meta["redaction_count"], 4)
        self.assertEqual(gate.verify_text_clean(redacted), [])
        meta_str = repr(meta)
        for secret_val in ALL_SYNTH_PII_SECRETS:
            self.assertNotIn(secret_val, meta_str)

    def test_luhn_invalid_saudi_id_not_flagged_as_national_id(self) -> None:
        gate = PrivacyGate(contact_hash_key=make_secret_bytes())
        spans = gate.engine.detect(f"رقم الطلب {SYNTH_INVALID_ID}")
        types = {s.entity_type for s in spans}
        self.assertNotIn(EntityType.SAUDI_NATIONAL_ID, types)
        self.assertNotIn(EntityType.SAUDI_IQAMA, types)

    def test_pseudonymize_hash_fails_closed_without_salt(self) -> None:
        with self.assertRaises(ValueError):
            PrivacyGate(
                policy=MaskingPolicy.PSEUDONYMIZE_HASH,
                salt=None,
                contact_hash_key=make_secret_bytes(),
            )
        with self.assertRaises(ValueError):
            PrivacyGate(
                policy=MaskingPolicy.PSEUDONYMIZE_HASH,
                salt="   ",
                contact_hash_key=make_secret_bytes(),
            )

        gate = PrivacyGate(
            policy=MaskingPolicy.PSEUDONYMIZE_HASH,
            salt="explicit-test-salt-2026",
            contact_hash_key=make_secret_bytes(),
        )
        redacted, _meta = gate.redact_text(f"هويتي {SYNTH_SAUDI_ID}")
        self.assertNotIn(SYNTH_SAUDI_ID, redacted)

    def test_zero_raw_pii_in_sqlite_logs_and_exceptions(self) -> None:
        pipe = TijaraGuardPipeline(
            catalog=load_test_catalog(),
            ledger_db_path=self.tmpdir / "ledger.sqlite3",
            approval_secret=make_secret_bytes(),
            contact_hash_key=make_secret_bytes(),
            mode=ExecutionMode.SHADOW,
        )
        msg = make_inbound_message(
            message_id="msg-pii-sweep-01",
            raw_contact_target=SYNTH_PHONE_INTL,
            consent_evidence=f"whatsapp_consent_{SYNTH_EMAIL}",
            raw_text=(
                f"هلا والله، كم سعر سماعة سوني WH-1000XM5؟ "
                f"هويتي {SYNTH_SAUDI_ID} والايبان {SYNTH_GCC_IBAN} ورقمي {SYNTH_PHONE_AR_INDIC}"
            ),
        )

        with capture_tijaraguard_logs() as log_buf:
            res = pipe.process_inbound(msg)
            self.assertEqual(res["verification_status"], "PASS")

            # Trigger an exception after ingestion and ensure PII never leaks in exception string.
            with self.assertRaises(MalformedInputError) as exc_ctx:
                InboundMessage(
                    message_id="msg-bad-channel",
                    conversation_id="conv-bad",
                    customer_handle="cust",
                    raw_contact_target=SYNTH_EMAIL,
                    contact_channel="telegram",
                    consent_to_contact=True,
                    consent_evidence="none",
                    preferred_language="ar",
                    raw_text=f"بياناتي {SYNTH_SAUDI_ID}",
                )

        exc_text = str(exc_ctx.exception)
        logs_text = log_buf.getvalue()
        for secret_val in ALL_SYNTH_PII_SECRETS:
            self.assertNotIn(secret_val, exc_text)
            self.assertNotIn(secret_val, logs_text)

        self.assertEqual(
            scan_sqlite_for_secrets(self.tmpdir / "ledger.sqlite3", ALL_SYNTH_PII_SECRETS),
            [],
        )
        self.assertTrue(pipe.audit_zero_pii(ALL_SYNTH_PII_SECRETS)["clean"])

    def test_requested_sku_with_pii_rejected_without_persistence(self) -> None:
        ledger_db = self.tmpdir / "ledger_sku_pii.sqlite3"
        pipe = TijaraGuardPipeline(
            catalog=load_test_catalog(),
            ledger_db_path=ledger_db,
            approval_secret=make_secret_bytes(),
            contact_hash_key=make_secret_bytes(),
            mode=ExecutionMode.SHADOW,
        )
        with capture_tijaraguard_logs() as log_buf:
            for bad_sku in (SYNTH_GCC_IBAN, SYNTH_SAUDI_ID):
                msg = make_inbound_message(
                    message_id=f"msg-sku-{bad_sku[:6]}",
                    raw_text="كم سعر سماعة سوني؟",
                    requested_sku=bad_sku,
                )
                with self.assertRaises(PrivacyViolationError):
                    pipe.process_inbound(msg)

            # Non-identifier ASCII/whitespace injection in requested_sku rejected cleanly
            with self.assertRaises(MalformedInputError):
                make_inbound_message(
                    message_id="msg-sku-space",
                    raw_text="كم سعر سماعة سوني؟",
                    requested_sku="SKU WITH SPACE",
                )

        logs_text = log_buf.getvalue()
        for secret_val in (SYNTH_GCC_IBAN, SYNTH_SAUDI_ID):
            self.assertNotIn(secret_val, logs_text)
        self.assertEqual(scan_sqlite_for_secrets(ledger_db, ALL_SYNTH_PII_SECRETS), [])

    def test_invalid_masking_policy_and_pseudonymize_residual_checks(self) -> None:
        with self.assertRaises(MalformedInputError):
            PrivacyGate(policy="REDACT_FULL", contact_hash_key=make_secret_bytes())

        gate = PrivacyGate(
            policy=MaskingPolicy.PSEUDONYMIZE_HASH,
            salt="salt-2026-test",
            contact_hash_key=make_secret_bytes(),
        )
        msg = make_inbound_message(
            message_id="msg-pseudo-01",
            customer_handle=f"عميل {SYNTH_SAUDI_ID}",
            consent_evidence=f"opt_in: {SYNTH_GCC_IBAN}",
            raw_text=f"استفسار رقم {SYNTH_PHONE_INTL}",
        )
        env = gate.sanitize_inbound(msg)
        self.assertNotIn(SYNTH_SAUDI_ID, env.customer_handle)
        self.assertNotIn(SYNTH_GCC_IBAN, env.consent_evidence)
        self.assertNotIn(SYNTH_PHONE_INTL, env.redacted_text)
