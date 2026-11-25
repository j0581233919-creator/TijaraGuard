"""End-to-end 4-gate orchestration pipeline for TijaraGuard."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .channels.base import (
    ChannelInboundEvent,
    ChannelRegistry,
    ChannelShieldTransport,
    ChannelStatusEvent,
    normalize_receipt_id,
)
from .commerce import CommercialGate
from .delivery import _OUTBOX_INIT_LOCK, MessageShieldDeliveryAdapter
from .ledger import ApprovalLedger, EphemeralRouteStore
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
    ProviderError,
    canonical_json,
    sha256_hex,
    validate_safe_id,
)
from .privacy import MaskingPolicy, PrivacyGate
from .providers.base import TaskComplexity
from .providers.router import ModelRouter

logger = logging.getLogger("tijaraguard.pipeline")

_CHATWOOT_CONV_ID_RE = re.compile(r"^[0-9]{1,20}$")


def _safe_message_id(channel: str, external_event_id: str) -> str:
    candidate = f"{channel}-{external_event_id}"
    if re.fullmatch(r"[A-Za-z0-9_-]{1,80}", candidate):
        return candidate
    return f"{channel[:8]}-{sha256_hex(f'{channel}:{external_event_id}')[:24]}"


class TijaraGuardPipeline:
    """Integrates BayanGate -> AI/CatalogCopilot -> SQLite Approval -> MessageShield/Channels."""

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
        ai_router: Optional[ModelRouter] = None,
        channel_registry: Optional[ChannelRegistry] = None,
        route_store: Optional[EphemeralRouteStore] = None,
        tenant_id: str = "default",
        retention_days: int = 30,
        fallback_to_template_on_ai_error: bool = True,
        allow_loopback_channels: bool = False,
    ) -> None:
        if not isinstance(mode, ExecutionMode):
            raise MalformedInputError("mode must be an ExecutionMode enum value.")
        self.mode = mode
        self.tenant_id = validate_safe_id(tenant_id, "tenant_id")
        self.retention_days = max(1, int(retention_days))
        self.fallback_to_template_on_ai_error = bool(fallback_to_template_on_ai_error)
        self.allow_loopback_channels = bool(allow_loopback_channels)
        self.shield_timeout = float(shield_timeout)

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
        self.ai_router = ai_router
        if self.ai_router is not None and self.ai_router.privacy_gate is None:
            self.ai_router.privacy_gate = self.privacy_gate

        self.channel_registry = channel_registry or ChannelRegistry()
        self.route_store = route_store

        self.outbox_db_path: Optional[Path] = (
            Path(outbox_db_path).resolve() if outbox_db_path is not None else None
        )
        self.delivery: Optional[MessageShieldDeliveryAdapter] = None
        if mode == ExecutionMode.LOOPBACK_LIVE:
            if self.outbox_db_path is None or receiver_endpoint is None:
                raise MalformedInputError(
                    "LOOPBACK_LIVE mode requires both outbox_db_path and receiver_endpoint."
                )
            self.delivery = MessageShieldDeliveryAdapter(
                outbox_db_path=self.outbox_db_path,
                endpoint_url=receiver_endpoint,
                timeout=self.shield_timeout,
            )
        elif mode == ExecutionMode.LIVE:
            if self.outbox_db_path is None:
                raise MalformedInputError("LIVE mode requires outbox_db_path.")
            self._ensure_live_outbox_initialized()

    def _ensure_live_outbox_initialized(self) -> None:
        from message_shield.store import Store  # type: ignore[import-not-found]

        assert self.outbox_db_path is not None
        self.outbox_db_path.parent.mkdir(parents=True, exist_ok=True)
        with _OUTBOX_INIT_LOCK:
            if not self.outbox_db_path.exists():
                try:
                    Store(self.outbox_db_path, create=True)
                except FileExistsError:
                    Store(self.outbox_db_path, create=False)

    def _persist_ai_attempts(
        self,
        attempts: List[Dict[str, Any]],
        *,
        draft_id: Optional[str],
        tenant_id: str,
    ) -> None:
        for attempt in attempts:
            self.ledger.record_provider_usage(
                draft_id=draft_id,
                tenant_id=tenant_id,
                provider=str(attempt.get("provider") or "unknown"),
                model=str(attempt.get("model") or "unknown"),
                task_tier=str(attempt.get("task_tier") or "standard"),
                status=str(attempt.get("status") or "ERROR"),
                error_category=attempt.get("error_category"),
                latency_ms=float(attempt.get("latency_ms") or 0.0),
                prompt_tokens=attempt.get("prompt_tokens"),
                completion_tokens=attempt.get("completion_tokens"),
                total_tokens=attempt.get("total_tokens"),
                estimated_cost_usd=attempt.get("estimated_cost_usd"),
                fallback_from=attempt.get("fallback_from"),
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

    def _assert_operator_id_clean(self, identifier: str, field_name: str) -> str:
        if not isinstance(identifier, str) or not identifier.strip():
            raise MalformedInputError(f"{field_name} must be a non-empty string.")
        clean = identifier.strip()
        if self.privacy_gate.verify_identifier_clean(clean):
            raise PrivacyViolationError(
                f"Supported PII detected in '{field_name}'; rejected before persistence."
            )
        return clean

    def process_inbound(
        self,
        msg: InboundMessage,
        *,
        custom_llm_callable: Optional[Callable[[str, Dict[str, Any]], str]] = None,
        task_complexity: TaskComplexity = TaskComplexity.STANDARD,
    ) -> Dict[str, Any]:
        """Executes Gate 1 redaction -> Gate 2 verification -> Gate 3 persistence."""
        envelope = self.privacy_gate.sanitize_inbound(msg)
        logger.info(
            "gate1_redacted message_id=%s contact_ref=%s entity_count=%d",
            envelope.message_id,
            envelope.contact_ref,
            envelope.pii_summary.get("entity_count", 0),
        )

        attempts_buf: List[Dict[str, Any]] = []
        try:
            evaluation = self.commercial_gate.evaluate_and_draft(
                envelope,
                custom_llm_callable=custom_llm_callable,
                ai_router=self.ai_router,
                task_complexity=task_complexity,
                fallback_to_template_on_ai_error=self.fallback_to_template_on_ai_error,
                on_ai_attempt=attempts_buf.append,
            )
        except BaseException:
            if attempts_buf:
                self._persist_ai_attempts(
                    attempts_buf,
                    draft_id=None,
                    tenant_id=envelope.tenant_id,
                )
            raise

        self._assert_evaluation_pii_clean(evaluation)
        logger.info(
            "gate2_verified draft_id=%s sku=%s status=%s provider=%s",
            evaluation.draft_id,
            evaluation.sku,
            evaluation.verification_status,
            evaluation.ai_provider,
        )

        draft_row = self.ledger.record_ingested_draft(
            envelope,
            evaluation,
            retention_days=self.retention_days,
        )
        if attempts_buf:
            self._persist_ai_attempts(
                attempts_buf,
                draft_id=draft_row["draft_id"],
                tenant_id=draft_row["tenant_id"],
            )

        return {
            "draft_id": draft_row["draft_id"],
            "tenant_id": draft_row["tenant_id"],
            "message_id": draft_row["message_id"],
            "conversation_id": draft_row["conversation_id"],
            "contact_ref": draft_row["contact_ref"],
            "contact_channel": draft_row["contact_channel"],
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
            "ai_provider": evaluation.ai_provider,
            "ai_model": evaluation.ai_model,
            "ai_metadata": evaluation.ai_metadata,
        }

    def ingest_channel_event(
        self,
        event: ChannelInboundEvent,
        *,
        post_chatwoot_private_note: bool = False,
        custom_llm_callable: Optional[Callable[[str, Dict[str, Any]], str]] = None,
    ) -> Dict[str, Any]:
        """Validates PII, deduplicates, and ingests an authenticated inbound channel event."""
        tenant = validate_safe_id(event.tenant_id or self.tenant_id, "tenant_id")
        if self.privacy_gate.verify_identifier_clean(event.external_event_id):
            raise PrivacyViolationError(
                "Supported PII detected in channel external_event_id; rejected before persistence."
            )
        if self.privacy_gate.verify_identifier_clean(event.conversation_id):
            raise PrivacyViolationError(
                "Supported PII detected in channel conversation_id; rejected before persistence."
            )

        msg = InboundMessage(
            message_id=_safe_message_id(event.channel, event.external_event_id),
            conversation_id=event.conversation_id,
            customer_handle=event.customer_handle,
            raw_contact_target=event.raw_contact_target,
            contact_channel=event.channel,
            consent_to_contact=event.consent_to_contact,
            consent_evidence=event.consent_evidence,
            preferred_language=event.preferred_language,
            raw_text=event.text,
            requested_sku=event.requested_sku,
            tenant_id=tenant,
            channel_metadata=dict(event.metadata or {}),
        )
        # Verify Gate 1 identifier safety before registering channel_events in ledger DB
        for id_val in (msg.message_id, msg.conversation_id, msg.tenant_id, msg.requested_sku or ""):
            if id_val and self.privacy_gate.verify_identifier_clean(id_val):
                raise PrivacyViolationError(
                    "Supported PII detected in identifier field; rejected before persistence."
                )

        is_new = self.ledger.register_channel_event(
            event.channel,
            event.external_event_id,
            tenant_id=tenant,
            conversation_id=event.conversation_id,
            status="PROCESSING",
        )
        if not is_new:
            return {
                "duplicate": True,
                "channel": event.channel,
                "external_event_id": event.external_event_id,
                "conversation_id": event.conversation_id,
            }

        try:
            result = self.process_inbound(msg, custom_llm_callable=custom_llm_callable)
        except ProviderError:
            self.ledger.release_channel_event(
                event.channel,
                event.external_event_id,
                tenant_id=tenant,
            )
            raise
        except BaseException:
            self.ledger.release_channel_event(
                event.channel,
                event.external_event_id,
                tenant_id=tenant,
            )
            raise

        self.ledger.update_channel_event(
            event.channel,
            event.external_event_id,
            status="INGESTED",
            draft_id=result["draft_id"],
            tenant_id=tenant,
        )

        if self.route_store is not None:
            self.route_store.put(
                tenant_id=tenant,
                channel=event.channel,
                contact_ref=result["contact_ref"],
                external_target=event.external_target,
                external_conversation_id=event.conversation_id,
            )

        if (
            post_chatwoot_private_note
            and event.channel == "chatwoot"
            and self.channel_registry.has("chatwoot")
        ):
            cw_adapter = self.channel_registry.get("chatwoot")
            if hasattr(cw_adapter, "send_private_note"):
                try:
                    cw_adapter.send_private_note(  # type: ignore[attr-defined]
                        event.external_target,
                        (
                            f"[TijaraGuard Draft {result['draft_id']}] "
                            f"Status={result['verification_status']} | SKU={result['sku'] or 'N/A'}\n"
                            f"{result['draft_body']}"
                        ),
                    )
                except Exception as exc:
                    logger.warning(
                        "chatwoot_private_note_failed draft_id=%s err=%s",
                        result["draft_id"],
                        type(exc).__name__,
                    )

        return {"duplicate": False, **result}

    def process_status_event(self, status_event: ChannelStatusEvent) -> Dict[str, Any]:
        """Reconciles inbound delivery status callbacks (delivered, read, failed)."""
        is_new = self.ledger.register_channel_event(
            f"{status_event.channel}_status",
            status_event.external_event_id,
            tenant_id=self.tenant_id,
            status="STATUS_RECEIVED",
        )
        if not is_new:
            return {
                "duplicate": True,
                "matched": False,
                "status": status_event.status,
            }

        norm_receipt = normalize_receipt_id(
            status_event.channel, status_event.external_message_id
        )
        matched_draft = self.ledger.get_draft_by_receipt_id(
            norm_receipt,
            tenant_id=self.tenant_id,
            channel=status_event.channel,
        )
        if matched_draft is None:
            return {"matched": False, "receipt_id": norm_receipt, "status": status_event.status}

        draft_id = matched_draft["draft_id"]
        current_state = matched_draft["state"]
        self.ledger.update_channel_event(
            f"{status_event.channel}_status",
            status_event.external_event_id,
            status="STATUS_APPLIED",
            draft_id=draft_id,
            tenant_id=self.tenant_id,
        )

        if status_event.status in ("delivered", "read"):
            if current_state == DraftState.ACCEPTED_DELIVERY.value:
                if self.outbox_db_path is not None and self.channel_registry.has(
                    matched_draft["contact_channel"]
                ):
                    adapter = self.channel_registry.get(matched_draft["contact_channel"])
                    ms_adapter = self._build_channel_shield_adapter(
                        adapter=adapter,
                        target="status_callback",
                        conversation_id=matched_draft["conversation_id"],
                    )
                    try:
                        ms_adapter.confirm_delivered(draft_id, norm_receipt)
                    except DeliveryError:
                        pass
                updated = self.ledger.record_delivery_state(
                    draft_id,
                    DraftState.DELIVERED,
                    receipt_id=norm_receipt,
                    details={"status_callback": status_event.status},
                    actor=f"webhook_{status_event.channel}",
                )
                return {"matched": True, "draft_id": draft_id, "state": updated["state"]}
            return {"matched": True, "draft_id": draft_id, "state": current_state}

        if status_event.status == "failed":
            if current_state == DraftState.ACCEPTED_DELIVERY.value:
                updated = self.ledger.record_delivery_state(
                    draft_id,
                    DraftState.FAILED_DELIVERY,
                    receipt_id=norm_receipt,
                    details={"status_callback": "failed", "error": status_event.error},
                    actor=f"webhook_{status_event.channel}",
                )
                return {"matched": True, "draft_id": draft_id, "state": updated["state"]}
            return {"matched": True, "draft_id": draft_id, "state": current_state}

        return {"matched": True, "draft_id": draft_id, "state": current_state}

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
        clean_reviewer = self._assert_operator_id_clean(reviewer_id, "reviewer_id")
        if not isinstance(notes, str):
            raise MalformedInputError("notes must be a string.")
        safe_notes = self.privacy_gate.redact_text_full(notes)
        token = self.ledger.approve_draft(
            draft_id=draft_id,
            reviewer_id=clean_reviewer,
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
        clean_reviewer = self._assert_operator_id_clean(reviewer_id, "reviewer_id")
        if not isinstance(reason, str):
            raise MalformedInputError("reason must be a string.")
        safe_reason = self.privacy_gate.redact_text_full(reason)
        row = self.ledger.reject_draft(draft_id, reviewer_id=clean_reviewer, reason=safe_reason)
        logger.info("gate3_rejected draft_id=%s reviewer=%s", draft_id, clean_reviewer)
        return row

    def escalate(self, draft_id: str, *, actor: str, reason: str) -> Dict[str, Any]:
        """Escalates a draft to human operator handoff and notifies Chatwoot if applicable."""
        clean_actor = self._assert_operator_id_clean(actor, "actor")
        if not isinstance(reason, str):
            raise MalformedInputError("reason must be a string.")
        safe_reason = self.privacy_gate.redact_text_full(reason)
        row = self.ledger.escalate_draft(draft_id, actor=clean_actor, reason=safe_reason)
        if row["contact_channel"] == "chatwoot" and self.channel_registry.has("chatwoot"):
            adapter = self.channel_registry.get("chatwoot")
            if self.route_store is not None and hasattr(adapter, "handoff_to_human"):
                route = self.route_store.get(
                    tenant_id=row["tenant_id"],
                    channel="chatwoot",
                    contact_ref=row["contact_ref"],
                    external_conversation_id=row["conversation_id"],
                )
                if route:
                    try:
                        adapter.handoff_to_human(route["external_target"], safe_reason)  # type: ignore[attr-defined]
                    except Exception as exc:
                        logger.warning(
                            "chatwoot_handoff_failed draft_id=%s err=%s",
                            draft_id,
                            type(exc).__name__,
                        )
        logger.info("gate3_escalated draft_id=%s actor=%s", draft_id, clean_actor)
        return row

    def edit_draft(self, draft_id: str, *, new_body: str, actor: str) -> Dict[str, Any]:
        """Re-verifies an edited draft body and invalidates any previously issued approval."""
        clean_actor = self._assert_operator_id_clean(actor, "actor")
        draft_row = self.ledger.get_draft(draft_id)
        evaluation = self.commercial_gate.verify_edited_body(
            draft_row=draft_row,
            new_body=new_body,
        )
        self._assert_evaluation_pii_clean(evaluation)
        updated = self.ledger.edit_draft_body(draft_id, evaluation, actor=clean_actor)
        logger.info(
            "gate3_edited draft_id=%s new_state=%s verification=%s",
            draft_id,
            updated["state"],
            updated["verification_status"],
        )
        return updated

    def _build_channel_shield_adapter(
        self,
        *,
        adapter: Any,
        target: str,
        conversation_id: Optional[str],
        tenant: Optional[str] = None,
    ) -> MessageShieldDeliveryAdapter:
        assert self.outbox_db_path is not None
        transport = ChannelShieldTransport(
            adapter=adapter,
            target=target,
            conversation_id=conversation_id,
        )
        ms_tenant = tenant or self.tenant_id
        return MessageShieldDeliveryAdapter(
            outbox_db_path=self.outbox_db_path,
            endpoint_url=adapter.endpoint_url,
            tenant=ms_tenant,
            timeout=self.shield_timeout,
            allow_remote_https=True,
            allow_loopback_http=self.allow_loopback_channels,
            transport=transport,
        )

    def _resolve_live_target(
        self,
        draft: Dict[str, Any],
        explicit_target: Optional[str],
    ) -> str:
        channel = draft["contact_channel"]
        if not self.channel_registry.has(channel):
            raise DeliveryError(f"Channel '{channel}' is not configured for LIVE dispatch.")

        if explicit_target is not None:
            clean = explicit_target.strip()
            if not clean:
                raise MalformedInputError("recipient_target must not be empty.")
            if self.route_store is not None:
                route = self.route_store.get(
                    tenant_id=draft["tenant_id"],
                    channel=channel,
                    contact_ref=draft["contact_ref"],
                    external_conversation_id=draft["conversation_id"],
                )
                if route is not None:
                    if route["external_target"] != clean:
                        raise DeliveryError(
                            "Cross-customer or cross-channel recipient_target mismatch rejected."
                        )
                    return clean

            if channel == "chatwoot":
                if not _CHATWOOT_CONV_ID_RE.fullmatch(clean) or f"cw-{clean}" != draft["conversation_id"]:
                    raise DeliveryError(
                        "Chatwoot recipient_target does not match draft conversation_id; cross-customer send blocked."
                    )
                return clean

            if self.privacy_gate.opaque_contact_ref(clean) != draft["contact_ref"]:
                raise DeliveryError(
                    "recipient_target does not match draft contact_ref; cross-customer send blocked."
                )
            return clean

        if self.route_store is not None:
            route = self.route_store.get(
                tenant_id=draft["tenant_id"],
                channel=channel,
                contact_ref=draft["contact_ref"],
                external_conversation_id=draft["conversation_id"],
            )
            if route is not None:
                return str(route["external_target"])

        raise DeliveryError(
            f"No active route mapping for tenant='{draft['tenant_id']}' channel='{channel}' contact_ref='{draft['contact_ref']}'."
        )

    def dispatch(
        self,
        draft_id: str,
        approval_token: ApprovalToken,
        *,
        confirm_delivered: bool = True,
        recipient_target: Optional[str] = None,
    ) -> DispatchOutcome:
        """Atomically consumes approval lease and dispatches in SHADOW, LOOPBACK_LIVE, or LIVE mode."""
        if not isinstance(approval_token, ApprovalToken) or approval_token.draft_id != draft_id:
            raise MalformedInputError("approval_token does not match target draft_id.")

        pre_draft = self.ledger.get_draft(draft_id)
        if self.mode in (ExecutionMode.LOOPBACK_LIVE, ExecutionMode.LIVE):
            if len(pre_draft["body"].encode("utf-8")) > 8192:
                raise DeliveryError(
                    "Approved payload exceeds MessageShield 8192-byte limit; lease preserved."
                )

        live_adapter: Optional[MessageShieldDeliveryAdapter] = None
        if self.mode == ExecutionMode.LIVE:
            target = self._resolve_live_target(pre_draft, recipient_target)
            ch_adapter = self.channel_registry.get(pre_draft["contact_channel"])
            live_adapter = self._build_channel_shield_adapter(
                adapter=ch_adapter,
                target=target,
                conversation_id=pre_draft["conversation_id"],
                tenant=pre_draft["tenant_id"],
            )

        consumed_draft = self.ledger.consume_approval_for_dispatch(
            draft_id=draft_id,
            lease_id=approval_token.lease_id,
            approval_mac=approval_token.approval_mac,
            mode=self.mode,
            expected_payload_sha256=approval_token.payload_sha256,
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

        active_delivery = self.delivery if self.mode == ExecutionMode.LOOPBACK_LIVE else live_adapter
        if active_delivery is None:
            raise MalformedInputError("Delivery adapter is not configured.")

        try:
            shield_state = active_delivery.admit_and_send(draft_id, consumed_draft["body"])
            if shield_state["state"] == "PENDING":
                shield_state = active_delivery.drain(draft_id)
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
                delivered_state = active_delivery.confirm_delivered(draft_id, receipt_id)
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
        """Recovers an UNKNOWN or interrupted send via read-only receipt lookup."""
        if self.mode not in (ExecutionMode.LOOPBACK_LIVE, ExecutionMode.LIVE):
            raise DeliveryError("Delivery recovery is only available in LOOPBACK_LIVE or LIVE mode.")

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

        if self.mode == ExecutionMode.LOOPBACK_LIVE:
            active_delivery = self.delivery
        else:
            ch_adapter = self.channel_registry.get(current["contact_channel"])
            active_delivery = self._build_channel_shield_adapter(
                adapter=ch_adapter,
                target="recovery_lookup",
                conversation_id=current["conversation_id"],
                tenant=current["tenant_id"],
            )

        if active_delivery is None:
            raise DeliveryError("Delivery adapter is not configured.")

        shield_state = active_delivery.recover(draft_id)
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
                    delivered_state = active_delivery.confirm_delivered(draft_id, receipt_id)
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

        if ms_status == "UNKNOWN" and current["state"] == DraftState.DISPATCHING.value:
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
