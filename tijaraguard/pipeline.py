"""End-to-end 4-gate orchestration pipeline for TijaraGuard."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .commerce import CommercialGate
from .delivery import MessageShieldDeliveryAdapter
from .ledger import ApprovalLedger
from .models import (
    ApprovalRequiredError,
    ApprovalToken,
    CommercialEvaluation,
    DeliveryError,
    DispatchOutcome,
    DraftState,
    ExecutionMode,
    InboundMessage,
    MalformedInputError,
    PrivacyViolationError,
    canonical_json,
)
from .privacy import MaskingPolicy, PrivacyGate


logger = logging.getLogger("tijaraguard.pipeline")


class TijaraGuardPipeline:
    """Integrates BayanGate -> CatalogCopilot -> SQLite Approval -> MessageShield."""

    def __init__(
        self,
        *,
        catalog: Any,
        ledger_db_path: str | Path,
        approval_secret: bytes,
        mode: ExecutionMode = ExecutionMode.SHADOW,
        outbox_db_path: Optional[str | Path] = None,
        receiver_endpoint: Optional[str] = None,
        shield_timeout: float = 2.0,
        privacy_policy: Any = MaskingPolicy.REDACT_FULL,
        privacy_salt: Optional[str] = None,
        contact_hash_key: Optional[bytes] = None,
    ) -> None:
        if not isinstance(mode, ExecutionMode):
            raise MalformedInputError("mode must be an ExecutionMode enum value.")
        self.mode = mode
        self.privacy_gate = PrivacyGate(
            policy=privacy_policy,
            salt=privacy_salt,
            contact_hash_key=contact_hash_key,
        )
        self.commercial_gate = CommercialGate(
            catalog=catalog,
            privacy_gate=self.privacy_gate,
        )
        self.ledger = ApprovalLedger(
            db_path=ledger_db_path,
            approval_secret=approval_secret,
        )

        self.delivery: Optional[MessageShieldDeliveryAdapter] = None
        if mode == ExecutionMode.LOOPBACK_LIVE:
            if outbox_db_path is None or receiver_endpoint is None:
                raise MalformedInputError(
                    "LOOPBACK_LIVE mode requires both outbox_db_path and receiver_endpoint."
                )
            self.delivery = MessageShieldDeliveryAdapter(
                outbox_db_path=outbox_db_path,
                endpoint_url=receiver_endpoint,
                timeout=shield_timeout,
            )

    def _assert_evaluation_pii_clean(self, evaluation: CommercialEvaluation) -> None:
        if evaluation.sku:
            leaked_sku = self.privacy_gate.verify_identifier_clean(evaluation.sku)
            if leaked_sku:
                raise PrivacyViolationError(
                    f"Gate 2 evaluation retained PII in 'sku': {leaked_sku}"
                )
        checks = [
            ("body", evaluation.body),
            ("subject", evaluation.subject),
            ("reasons", canonical_json(evaluation.reasons)),
            ("verification_report", canonical_json(evaluation.verification_report_dict)),
        ]
        for field_name, content in checks:
            leaked = self.privacy_gate.verify_text_clean(content)
            if leaked:
                raise PrivacyViolationError(
                    f"Gate 2 evaluation retained PII in '{field_name}': {leaked}"
                )

    def process_inbound(
        self,
        msg: InboundMessage,
        *,
        custom_llm_callable: Optional[Callable[[str, Dict[str, Any]], str]] = None,
    ) -> Dict[str, Any]:
        """Executes Gate 1 redaction -> Gate 2 verification -> Gate 3 persistence."""
        envelope = self.privacy_gate.sanitize_inbound(msg)
        logger.info(
            "gate1_redacted message_id=%s contact_ref=%s entity_count=%d",
            envelope.message_id,
            envelope.contact_ref,
            envelope.pii_summary.get("entity_count", 0),
        )

        evaluation = self.commercial_gate.evaluate_and_draft(
            envelope,
            custom_llm_callable=custom_llm_callable,
        )
        self._assert_evaluation_pii_clean(evaluation)
        logger.info(
            "gate2_verified draft_id=%s sku=%s status=%s",
            evaluation.draft_id,
            evaluation.sku,
            evaluation.verification_status,
        )

        draft_row = self.ledger.record_ingested_draft(envelope, evaluation)
        return {
            "draft_id": draft_row["draft_id"],
            "message_id": draft_row["message_id"],
            "contact_ref": draft_row["contact_ref"],
            "state": draft_row["state"],
            "sku": draft_row["sku"],
            "verification_status": draft_row["verification_status"],
            "reasons": evaluation.reasons,
            "detected_dialect": evaluation.detected_dialect,
            "query_intents": evaluation.query_intents,
            "payload_sha256": draft_row["payload_sha256"],
            "redacted_inquiry": draft_row["redacted_inquiry"],
            "subject": draft_row["subject"],
            "draft_body": draft_row["body"],
            "pii_entity_count": envelope.pii_summary.get("entity_count", 0),
        }

    def approve(
        self,
        draft_id: str,
        *,
        reviewer_id: str,
        expected_payload_sha256: str,
        notes: str = "",
        ttl_seconds: int = 900,
    ) -> ApprovalToken:
        """Issues a cryptographic single-use human approval lease for a verified draft."""
        if not isinstance(notes, str):
            raise MalformedInputError("notes must be a string.")
        safe_notes = self.privacy_gate.redact_text_full(notes)
        token = self.ledger.approve_draft(
            draft_id=draft_id,
            reviewer_id=reviewer_id,
            expected_payload_sha256=expected_payload_sha256,
            notes=safe_notes,
            ttl_seconds=ttl_seconds,
        )
        logger.info(
            "gate3_approved draft_id=%s lease_id=%s reviewer=%s",
            draft_id,
            token.lease_id,
            token.reviewer_id,
        )
        return token

    def reject(self, draft_id: str, *, reviewer_id: str, reason: str) -> Dict[str, Any]:
        """Rejects a pending or approved draft and revokes any active lease."""
        if not isinstance(reason, str):
            raise MalformedInputError("reason must be a string.")
        safe_reason = self.privacy_gate.redact_text_full(reason)
        row = self.ledger.reject_draft(draft_id, reviewer_id=reviewer_id, reason=safe_reason)
        logger.info("gate3_rejected draft_id=%s reviewer=%s", draft_id, reviewer_id)
        return row

    def edit_draft(self, draft_id: str, *, new_body: str, actor: str) -> Dict[str, Any]:
        """Re-verifies an edited draft body and invalidates any previously issued approval."""
        draft_row = self.ledger.get_draft(draft_id)
        evaluation = self.commercial_gate.verify_edited_body(
            draft_row=draft_row,
            new_body=new_body,
        )
        self._assert_evaluation_pii_clean(evaluation)
        updated = self.ledger.edit_draft_body(draft_id, evaluation, actor=actor)
        logger.info(
            "gate3_edited draft_id=%s new_state=%s verification=%s",
            draft_id,
            updated["state"],
            updated["verification_status"],
        )
        return updated

    def dispatch(
        self,
        draft_id: str,
        approval_token: ApprovalToken,
        *,
        confirm_delivered: bool = True,
    ) -> DispatchOutcome:
        """Atomically consumes approval lease and dispatches in SHADOW or LOOPBACK_LIVE mode."""
        if not isinstance(approval_token, ApprovalToken) or approval_token.draft_id != draft_id:
            raise MalformedInputError("approval_token does not match target draft_id.")

        if self.mode == ExecutionMode.LOOPBACK_LIVE:
            pre_draft = self.ledger.get_draft(draft_id)
            if len(pre_draft["body"].encode("utf-8")) > 8192:
                raise DeliveryError(
                    "Approved payload exceeds MessageShield 8192-byte limit; lease preserved."
                )

        consumed_draft = self.ledger.consume_approval_for_dispatch(
            draft_id=draft_id,
            lease_id=approval_token.lease_id,
            approval_mac=approval_token.approval_mac,
            mode=self.mode,
        )

        if self.mode == ExecutionMode.SHADOW:
            logger.info("gate3_shadow_recorded draft_id=%s", draft_id)
            return DispatchOutcome(
                draft_id=draft_id,
                mode=self.mode.value,
                state=consumed_draft["state"],
                dispatched=False,
                reason="Shadow Mode enabled (SIMULATED_NO_SEND); outbound transport bypassed.",
            )

        if self.delivery is None:
            raise MalformedInputError("Delivery adapter is not configured.")

        try:
            shield_state = self.delivery.admit_and_send(draft_id, consumed_draft["body"])
            if shield_state["state"] == "PENDING":
                shield_state = self.delivery.drain(draft_id)
        except DeliveryError:
            self.ledger.record_delivery_state(
                draft_id,
                DraftState.FAILED_DELIVERY,
                details={"reason": "delivery_error"},
            )
            raise

        delivery_key = shield_state["key"]
        receipt_id = shield_state.get("receipt_id")
        ms_status = shield_state["state"]

        if ms_status == "ACCEPTED" and receipt_id:
            self.ledger.record_delivery_state(
                draft_id,
                DraftState.ACCEPTED_DELIVERY,
                delivery_key=delivery_key,
                receipt_id=receipt_id,
                details={"attempts": shield_state.get("attempts", 1)},
            )
            if confirm_delivered:
                delivered_state = self.delivery.confirm_delivered(draft_id, receipt_id)
                ms_status = delivered_state["state"]
                updated = self.ledger.record_delivery_state(
                    draft_id,
                    DraftState.DELIVERED,
                    delivery_key=delivery_key,
                    receipt_id=receipt_id,
                    details={"confirmed_via": "gateway_receipt"},
                )
                return DispatchOutcome(
                    draft_id=draft_id,
                    mode=self.mode.value,
                    state=updated["state"],
                    dispatched=True,
                    delivery_key=delivery_key,
                    receipt_id=receipt_id,
                    message_shield_state=ms_status,
                )
            return DispatchOutcome(
                draft_id=draft_id,
                mode=self.mode.value,
                state=DraftState.ACCEPTED_DELIVERY.value,
                dispatched=True,
                delivery_key=delivery_key,
                receipt_id=receipt_id,
                message_shield_state=ms_status,
            )

        if ms_status == "UNKNOWN":
            updated = self.ledger.record_delivery_state(
                draft_id,
                DraftState.UNKNOWN_DELIVERY,
                delivery_key=delivery_key,
                details={"reason": shield_state.get("error")},
            )
            return DispatchOutcome(
                draft_id=draft_id,
                mode=self.mode.value,
                state=updated["state"],
                dispatched=True,
                delivery_key=delivery_key,
                message_shield_state=ms_status,
                reason=shield_state.get("error"),
            )

        updated = self.ledger.record_delivery_state(
            draft_id,
            DraftState.FAILED_DELIVERY,
            delivery_key=delivery_key,
            details={"reason": shield_state.get("error"), "ms_state": ms_status},
        )
        return DispatchOutcome(
            draft_id=draft_id,
            mode=self.mode.value,
            state=updated["state"],
            dispatched=False,
            delivery_key=delivery_key,
            message_shield_state=ms_status,
            reason=shield_state.get("error"),
        )

    def recover_delivery(
        self,
        draft_id: str,
        *,
        confirm_delivered: bool = True,
    ) -> DispatchOutcome:
        """Recovers an UNKNOWN or interrupted send via read-only GET receipt lookup."""
        if self.mode != ExecutionMode.LOOPBACK_LIVE or self.delivery is None:
            raise DeliveryError("Delivery recovery is only available in LOOPBACK_LIVE mode.")

        current = self.ledger.get_draft(draft_id)
        if current["state"] == DraftState.DELIVERED.value:
            return DispatchOutcome(
                draft_id=draft_id,
                mode=self.mode.value,
                state=DraftState.DELIVERED.value,
                dispatched=True,
                delivery_key=current["delivery_key"],
                receipt_id=current["receipt_id"],
                message_shield_state="DELIVERED",
                reason="Already delivered.",
            )
        if current["state"] not in (
            DraftState.DISPATCHING.value,
            DraftState.UNKNOWN_DELIVERY.value,
            DraftState.ACCEPTED_DELIVERY.value,
        ):
            raise ApprovalRequiredError(
                f"Draft '{draft_id}' in state '{current['state']}' is not eligible for recovery."
            )

        shield_state = self.delivery.recover(draft_id)
        ms_status = shield_state["state"]
        delivery_key = shield_state["key"]
        receipt_id = shield_state.get("receipt_id")

        if ms_status in ("ACCEPTED", "DELIVERED") and receipt_id:
            if current["state"] in (DraftState.DISPATCHING.value, DraftState.UNKNOWN_DELIVERY.value):
                self.ledger.record_delivery_state(
                    draft_id,
                    DraftState.ACCEPTED_DELIVERY,
                    delivery_key=delivery_key,
                    receipt_id=receipt_id,
                    details={"recovered_via": "read_only_receipt_lookup"},
                )
            if confirm_delivered:
                if ms_status != "DELIVERED":
                    delivered_state = self.delivery.confirm_delivered(draft_id, receipt_id)
                    ms_status = delivered_state["state"]
                updated = self.ledger.record_delivery_state(
                    draft_id,
                    DraftState.DELIVERED,
                    delivery_key=delivery_key,
                    receipt_id=receipt_id,
                    details={"confirmed_via": "recovered_gateway_receipt"},
                )
                return DispatchOutcome(
                    draft_id=draft_id,
                    mode=self.mode.value,
                    state=updated["state"],
                    dispatched=True,
                    delivery_key=delivery_key,
                    receipt_id=receipt_id,
                    message_shield_state=ms_status,
                    reason="Recovered receipt without resending POST.",
                )
            return DispatchOutcome(
                draft_id=draft_id,
                mode=self.mode.value,
                state=DraftState.ACCEPTED_DELIVERY.value,
                dispatched=True,
                delivery_key=delivery_key,
                receipt_id=receipt_id,
                message_shield_state=ms_status,
                reason="Recovered receipt without resending POST.",
            )

        if ms_status == "FAILED":
            updated = self.ledger.record_delivery_state(
                draft_id,
                DraftState.FAILED_DELIVERY,
                delivery_key=delivery_key,
                details={"reason": shield_state.get("error") or "outbox_failed"},
            )
            return DispatchOutcome(
                draft_id=draft_id,
                mode=self.mode.value,
                state=updated["state"],
                dispatched=False,
                delivery_key=delivery_key,
                receipt_id=receipt_id,
                message_shield_state=ms_status,
                reason=shield_state.get("error") or "Delivery failed permanently.",
            )

        if (
            ms_status == "UNKNOWN"
            and current["state"] == DraftState.DISPATCHING.value
        ):
            self.ledger.record_delivery_state(
                draft_id,
                DraftState.UNKNOWN_DELIVERY,
                delivery_key=delivery_key,
                details={"reason": shield_state.get("error") or "interrupted_send_recovered_to_unknown"},
            )
        return DispatchOutcome(
            draft_id=draft_id,
            mode=self.mode.value,
            state=self.ledger.get_draft(draft_id)["state"],
            dispatched=False,
            delivery_key=delivery_key,
            receipt_id=receipt_id,
            message_shield_state=ms_status,
            reason=shield_state.get("error") or "Receipt still unresolved.",
        )

    def audit_zero_pii(self, raw_secrets: List[str]) -> Dict[str, Any]:
        """Verifies none of the provided raw PII strings appear in ledger persistence."""
        leaks = self.ledger.scan_for_raw_secrets(raw_secrets)
        return {"clean": len(leaks) == 0, "leak_count": len(leaks), "leaks": leaks}
