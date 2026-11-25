"""Runnable synthetic end-to-end business demonstration for TijaraGuard."""

from __future__ import annotations

import logging
import secrets
import uuid
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List

from .commerce import CommercialGate
from .delivery import LocalLoopbackReceiver
from .deps import inspect_dependencies
from .models import ApprovalTamperError, ExecutionMode, InboundMessage
from .pipeline import TijaraGuardPipeline


_SYNTHETIC_CATALOG_PATH = Path(__file__).resolve().parents[1] / "examples" / "catalog.json"

# Checksum-valid synthetic test PII (from BayanGate synthetic benchmark vectors).
_SYNTHETIC_SAUDI_ID = "1082345677"
_SYNTHETIC_IBAN = "SA0380000000608010167519"
_SYNTHETIC_PHONE = "+966501234567"
_SYNTHETIC_EMAIL = "synth.customer.99@example.invalid"
_RAW_PII_SECRETS: List[str] = [
    _SYNTHETIC_SAUDI_ID,
    _SYNTHETIC_IBAN,
    _SYNTHETIC_PHONE,
    _SYNTHETIC_EMAIL,
]


def run_demo(state_dir: str | Path | None = None) -> Dict[str, Any]:
    """Executes all 4 gates across positive and adversarial paths and prints verification proof."""
    repo_root = Path(__file__).resolve().parents[1]
    base_dir = (
        Path(state_dir).resolve()
        if state_dir is not None
        else (repo_root / ".state" / f"demo-{uuid.uuid4().hex[:8]}").resolve()
    )
    base_dir.mkdir(parents=True, exist_ok=True)

    log_buffer = StringIO()
    handler = logging.StreamHandler(log_buffer)
    tg_logger = logging.getLogger("tijaraguard")
    old_level = tg_logger.level
    tg_logger.setLevel(logging.INFO)
    tg_logger.addHandler(handler)

    try:
        catalog = CommercialGate.from_json_file(_SYNTHETIC_CATALOG_PATH).catalog
        approval_secret = secrets.token_bytes(32)
        contact_hash_key = secrets.token_bytes(32)

        # --- Stage 1-3 in Default SHADOW Mode ---
        shadow_ledger_db = base_dir / "shadow_ledger.sqlite3"
        shadow_pipe = TijaraGuardPipeline(
            catalog=catalog,
            ledger_db_path=shadow_ledger_db,
            approval_secret=approval_secret,
            contact_hash_key=contact_hash_key,
            mode=ExecutionMode.SHADOW,
        )

        legit_msg = InboundMessage(
            message_id="msg-demo-001",
            conversation_id="conv-demo-001",
            customer_handle="عميل_تجريبي_01",
            raw_contact_target=_SYNTHETIC_PHONE,
            contact_channel="whatsapp",
            consent_to_contact=True,
            consent_evidence=f"whatsapp_opt_in_2026_ref ({_SYNTHETIC_EMAIL})",
            preferred_language="ar",
            raw_text=(
                f"هلا والله، كم سعر سماعة سوني WH1000XM5؟ "
                f"هويتي {_SYNTHETIC_SAUDI_ID} والايبان {_SYNTHETIC_IBAN}"
            ),
        )
        res_shadow = shadow_pipe.process_inbound(legit_msg)
        token_shadow = shadow_pipe.approve(
            res_shadow["draft_id"],
            reviewer_id="supervisor_ahmed",
            expected_payload_sha256=res_shadow["payload_sha256"],
            notes="Verified Arabic draft in Shadow Mode",
        )
        shadow_dispatch = shadow_pipe.dispatch(res_shadow["draft_id"], token_shadow)

        # --- Adversarial Simulated LLM Hallucination ---
        adv_msg = InboundMessage(
            message_id="msg-demo-002",
            conversation_id="conv-demo-002",
            customer_handle="عميل_تجريبي_02",
            raw_contact_target=_SYNTHETIC_PHONE,
            contact_channel="whatsapp",
            consent_to_contact=True,
            consent_evidence="whatsapp_opt_in_2026_ref",
            preferred_language="ar",
            raw_text="ابغى اعرف كم سعر سماعة سوني WH-1000XM5؟ وهل عليها ضمان؟",
            requested_sku="SONY-WH1000XM5",
        )

        def hallucinating_llm(_base: str, _ctx: Dict[str, Any]) -> str:
            return (
                "مرحباً، سماعة سوني WH-1000XM5 متوفرة بسعر 99.00 SAR فقط "
                "مع ضمان لمدة 5 سنوات وشحن مجاني فوري."
            )

        res_adv = shadow_pipe.process_inbound(adv_msg, custom_llm_callable=hallucinating_llm)

        # --- Tampered Approved Payload Rejection ---
        tamper_msg = InboundMessage(
            message_id="msg-demo-003",
            conversation_id="conv-demo-003",
            customer_handle="عميل_تجريبي_03",
            raw_contact_target=_SYNTHETIC_PHONE,
            contact_channel="whatsapp",
            consent_to_contact=True,
            consent_evidence="whatsapp_opt_in_2026_ref",
            preferred_language="ar",
            raw_text="كم سعر ماكينة قهوة ديلونجي EC685؟",
        )
        res_tamper = shadow_pipe.process_inbound(tamper_msg)
        tamper_token = shadow_pipe.approve(
            res_tamper["draft_id"],
            reviewer_id="supervisor_ahmed",
            expected_payload_sha256=res_tamper["payload_sha256"],
        )
        shadow_pipe.edit_draft(
            res_tamper["draft_id"],
            new_body="مرحباً، سعر ماكينة قهوة ديلونجي EC685 هو 1.00 SAR.",
            actor="untrusted_editor",
        )
        tamper_rejected = False
        try:
            shadow_pipe.dispatch(res_tamper["draft_id"], tamper_token)
        except ApprovalTamperError:
            tamper_rejected = True

        # --- Gate 4 Loopback Live + Lost ACK (drop_ack=True) -> UNKNOWN -> Recover ---
        receiver_db = base_dir / "receiver.sqlite3"
        outbox_db = base_dir / "outbox.sqlite3"
        live_ledger_db = base_dir / "ledger.sqlite3"

        with LocalLoopbackReceiver(receiver_db, drop_ack=True) as receiver:
            live_pipe = TijaraGuardPipeline(
                catalog=catalog,
                ledger_db_path=live_ledger_db,
                approval_secret=approval_secret,
                contact_hash_key=contact_hash_key,
                mode=ExecutionMode.LOOPBACK_LIVE,
                outbox_db_path=outbox_db,
                receiver_endpoint=receiver.endpoint_url,
                shield_timeout=0.5,
            )
            live_msg = InboundMessage(
                message_id="msg-demo-live-001",
                conversation_id="conv-demo-live-001",
                customer_handle="عميل_تجريبي_04",
                raw_contact_target=_SYNTHETIC_PHONE,
                contact_channel="whatsapp",
                consent_to_contact=True,
                consent_evidence="whatsapp_opt_in_2026_live",
                preferred_language="ar",
                raw_text=(
                    f"السلام عليكم، كم سعر سماعة سوني WH-1000XM5؟ "
                    f"رقمي {_SYNTHETIC_PHONE} وهويتي {_SYNTHETIC_SAUDI_ID}"
                ),
            )
            res_live = live_pipe.process_inbound(live_msg)
            live_token = live_pipe.approve(
                res_live["draft_id"],
                reviewer_id="supervisor_sara",
                expected_payload_sha256=res_live["payload_sha256"],
                notes="Approved for loopback delivery test",
            )

            # POST succeeds in receiver inbox, then socket drops before HTTP ACK!
            lost_ack_outcome = live_pipe.dispatch(res_live["draft_id"], live_token)

            # Read-only GET /inbox/receipts/<key> reconciliation without resending POST.
            recovered_outcome = live_pipe.recover_delivery(res_live["draft_id"], confirm_delivered=True)

            logical_rows = receiver.count_logical_deliveries(recovered_outcome.delivery_key)
            post_attempts = receiver.count_post_attempts(recovered_outcome.delivery_key)

        # --- Zero-PII & Audit Chain Verification ---
        shadow_chain_ok, shadow_chain_errs = shadow_pipe.ledger.verify_audit_chain()
        live_chain_ok, live_chain_errs = live_pipe.ledger.verify_audit_chain()
        shadow_pii = shadow_pipe.audit_zero_pii(_RAW_PII_SECRETS)
        live_pii = live_pipe.audit_zero_pii(_RAW_PII_SECRETS)

        # Scan receiver/outbox DB strings and application logs for any raw PII secret.
        log_text = log_buffer.getvalue()
        log_leaks = sum(1 for sec in _RAW_PII_SECRETS if sec in log_text)
        extra_db_leaks = _scan_sqlite_all_text(
            [receiver_db, outbox_db],
            _RAW_PII_SECRETS,
        )

        return {
            "state_dir": str(base_dir),
            "dependencies": inspect_dependencies(),
            "scenario_a_shadow": {
                "draft_id": res_shadow["draft_id"],
                "detected_dialect": res_shadow["detected_dialect"],
                "resolved_sku": res_shadow["sku"],
                "pii_entity_count": res_shadow["pii_entity_count"],
                "verification_status": res_shadow["verification_status"],
                "dispatch_mode": shadow_dispatch.mode,
                "dispatch_state": shadow_dispatch.state,
                "dispatched_externally": shadow_dispatch.dispatched,
            },
            "scenario_b_adversarial_llm": {
                "draft_id": res_adv["draft_id"],
                "verification_status": res_adv["verification_status"],
                "ledger_state": res_adv["state"],
                "reason_count": len(res_adv["reasons"]),
            },
            "scenario_c_payload_tamper": {
                "draft_id": res_tamper["draft_id"],
                "tampered_dispatch_rejected": tamper_rejected,
                "final_ledger_state": shadow_pipe.ledger.get_draft(res_tamper["draft_id"])["state"],
            },
            "scenario_d_lost_ack_recovery": {
                "draft_id": res_live["draft_id"],
                "initial_state_after_drop_ack": lost_ack_outcome.state,
                "initial_shield_state": lost_ack_outcome.message_shield_state,
                "recovered_state": recovered_outcome.state,
                "recovered_shield_state": recovered_outcome.message_shield_state,
                "receipt_id": recovered_outcome.receipt_id,
                "delivery_key": recovered_outcome.delivery_key,
                "receiver_logical_inbox_rows": logical_rows,
                "receiver_post_attempts": post_attempts,
            },
            "security_and_audit_proof": {
                "shadow_audit_chain_valid": shadow_chain_ok,
                "shadow_audit_chain_errors": shadow_chain_errs,
                "live_audit_chain_valid": live_chain_ok,
                "live_audit_chain_errors": live_chain_errs,
                "shadow_ledger_pii_leaks": shadow_pii["leak_count"],
                "live_ledger_pii_leaks": live_pii["leak_count"],
                "receiver_and_outbox_pii_leaks": extra_db_leaks,
                "application_log_pii_leaks": log_leaks,
            },
        }
    finally:
        tg_logger.removeHandler(handler)
        tg_logger.setLevel(old_level)


def _scan_sqlite_all_text(db_paths: List[Path], secrets_list: List[str]) -> int:
    import sqlite3

    leaks = 0
    for db_path in db_paths:
        if not db_path.exists():
            continue
        conn = sqlite3.connect(str(db_path))
        try:
            tables = [
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
            for table in tables:
                rows = conn.execute(f'SELECT * FROM "{table}"').fetchall()
                for row in rows:
                    for val in row:
                        if isinstance(val, str):
                            for sec in secrets_list:
                                if sec in val:
                                    leaks += 1
        finally:
            conn.close()
    return leaks
