"""Gate 2 (CatalogCopilot) commercial claim verification & Arabic dialect tests."""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict

sys.dont_write_bytecode = True
_TESTS_DIR = Path(__file__).resolve().parent
_ROOT = _TESTS_DIR.parent
for _p in (str(_TESTS_DIR), str(_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from tijaraguard.models import DraftState, ExecutionMode, VerificationBlockedError
from tijaraguard.pipeline import TijaraGuardPipeline

from helpers import (
    ALL_SYNTH_PII_SECRETS,
    REPO_ROOT,
    SYNTH_GCC_IBAN,
    SYNTH_SAUDI_ID,
    load_test_catalog,
    make_inbound_message,
    make_secret_bytes,
    scan_sqlite_for_secrets,
)


class TestGate2Commerce(unittest.TestCase):
    def setUp(self) -> None:
        base_tmp = REPO_ROOT / ".tmp_test"
        base_tmp.mkdir(parents=True, exist_ok=True)
        self.tmpdir = Path(tempfile.mkdtemp(prefix="g2_", dir=str(base_tmp)))
        self.pipe = TijaraGuardPipeline(
            catalog=load_test_catalog(),
            ledger_db_path=self.tmpdir / "ledger.sqlite3",
            approval_secret=make_secret_bytes(),
            contact_hash_key=make_secret_bytes(),
            mode=ExecutionMode.SHADOW,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_arabic_dialect_inquiry_with_redacted_pii_resolves_sku_and_passes(self) -> None:
        msg = make_inbound_message(
            message_id="msg-g2-pass-01",
            raw_text=(
                f"هلا والله، كم سعر سماعة سوني WH-1000XM5؟ "
                f"هويتي {SYNTH_SAUDI_ID} والايبان {SYNTH_GCC_IBAN}"
            ),
        )
        res = self.pipe.process_inbound(msg)
        self.assertEqual(res["sku"], "SONY-WH1000XM5")
        self.assertEqual(res["detected_dialect"], "GULF")
        self.assertEqual(res["verification_status"], "PASS")
        self.assertEqual(res["state"], DraftState.PENDING_APPROVAL.value)
        self.assertNotIn(SYNTH_SAUDI_ID, res["redacted_inquiry"])
        self.assertNotIn(SYNTH_GCC_IBAN, res["redacted_inquiry"])

    def test_adversarial_llm_wrong_price_and_unapproved_warranty_blocked(self) -> None:
        msg = make_inbound_message(
            message_id="msg-g2-adv-price",
            raw_text="كم سعر سماعة سوني WH-1000XM5؟",
        )

        def bad_llm(_base: str, _ctx: Dict[str, Any]) -> str:
            return (
                "مرحباً، سماعة سوني WH-1000XM5 متوفرة بسعر 99.00 SAR "
                "مع ضمان 5 سنوات وشحن مجاني."
            )

        res = self.pipe.process_inbound(msg, custom_llm_callable=bad_llm)
        self.assertEqual(res["verification_status"], "FAIL")
        self.assertEqual(res["state"], DraftState.VERIFIED_BLOCKED.value)
        with self.assertRaises(VerificationBlockedError):
            self.pipe.approve(
                res["draft_id"],
                reviewer_id="reviewer_1",
                expected_payload_sha256=res["payload_sha256"],
            )

    def test_adversarial_llm_expired_discount_claim_blocked(self) -> None:
        msg = make_inbound_message(
            message_id="msg-g2-expired-discount",
            raw_text="كم سعر شاحن انكر 737؟",
            requested_sku="ANKER-737",
        )

        def expired_offer_llm(_base: str, _ctx: Dict[str, Any]) -> str:
            return "مرحباً، شاحن انكر 737 متوفر بسعر 360.00 SAR مع خصم 20%."

        res = self.pipe.process_inbound(msg, custom_llm_callable=expired_offer_llm)
        self.assertEqual(res["verification_status"], "FAIL")
        self.assertEqual(res["state"], DraftState.VERIFIED_BLOCKED.value)

    def test_adversarial_llm_out_of_stock_claimed_available_blocked(self) -> None:
        msg = make_inbound_message(
            message_id="msg-g2-oos",
            raw_text="هل مكنسة دايسون V15 متوفرة؟",
            requested_sku="DYSON-V15",
        )

        def misleading_stock_llm(_base: str, _ctx: Dict[str, Any]) -> str:
            return "مرحباً، مكنسة دايسون V15 متوفرة لدينا حالياً بسعر 2400.00 SAR."

        res = self.pipe.process_inbound(msg, custom_llm_callable=misleading_stock_llm)
        self.assertEqual(res["verification_status"], "FAIL")
        self.assertEqual(res["state"], DraftState.VERIFIED_BLOCKED.value)

    def test_adversarial_llm_pii_leak_in_draft_blocked(self) -> None:
        msg = make_inbound_message(
            message_id="msg-g2-pii-draft",
            raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
            requested_sku="DELONGHI-EC685",
        )

        def leaky_llm(base: str, _ctx: Dict[str, Any]) -> str:
            return f"{base}\n(مرجع الهوية: {SYNTH_SAUDI_ID} والايبان {SYNTH_GCC_IBAN})"

        res = self.pipe.process_inbound(msg, custom_llm_callable=leaky_llm)
        self.assertEqual(res["verification_status"], "FAIL")
        self.assertEqual(res["state"], DraftState.VERIFIED_BLOCKED.value)
        self.assertTrue(any("PRIVACY_LEAK_IN_DRAFT" in r for r in res["reasons"]))
        self.assertNotIn(SYNTH_SAUDI_ID, res["draft_body"])
        self.assertNotIn(SYNTH_GCC_IBAN, res["draft_body"])
        self.assertEqual(
            scan_sqlite_for_secrets(self.tmpdir / "ledger.sqlite3", ALL_SYNTH_PII_SECRETS),
            [],
        )

    def test_edit_draft_pii_injection_never_persists_raw_pii(self) -> None:
        msg = make_inbound_message(
            message_id="msg-g2-edit-pii",
            raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
            requested_sku="DELONGHI-EC685",
        )
        res = self.pipe.process_inbound(msg)
        self.assertEqual(res["verification_status"], "PASS")

        edited = self.pipe.edit_draft(
            res["draft_id"],
            new_body=f"مرحباً، سعر ماكينة قهوة ديلونجي EC685 هو 850.00 SAR (ايبان {SYNTH_GCC_IBAN} وهوية {SYNTH_SAUDI_ID})",
            actor="malicious_editor",
        )
        self.assertEqual(edited["verification_status"], "FAIL")
        self.assertEqual(edited["state"], DraftState.VERIFIED_BLOCKED.value)
        self.assertEqual(
            scan_sqlite_for_secrets(self.tmpdir / "ledger.sqlite3", ALL_SYNTH_PII_SECRETS),
            [],
        )

    def test_missing_or_false_string_consent_or_missing_evidence_blocked(self) -> None:
        for idx, (consent, evidence) in enumerate(
            [
                (False, "opt_in_2026"),
                ("false", "opt_in_2026"),
                ("0", "opt_in_2026"),
                (True, ""),
            ]
        ):
            msg = make_inbound_message(
                message_id=f"msg-g2-noconsent-{idx}",
                consent_to_contact=consent,
                consent_evidence=evidence,
                requested_sku="DELONGHI-EC685",
                raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
            )
            res = self.pipe.process_inbound(msg)
            self.assertEqual(res["state"], DraftState.VERIFIED_BLOCKED.value)
            with self.assertRaises(VerificationBlockedError):
                self.pipe.approve(
                    res["draft_id"],
                    reviewer_id="reviewer_1",
                    expected_payload_sha256=res["payload_sha256"],
                )
