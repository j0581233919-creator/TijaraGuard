"""Gate 2 — CatalogCopilot commercial verification, Arabic dialect & grounded AI drafting adapter."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .deps import load_dependencies
from .models import (
    CommercialEvaluation,
    MalformedInputError,
    PrivacyViolationError,
    RedactedEnvelope,
    canonical_json,
)
from .privacy import PrivacyGate, strip_redaction_markers
from .providers.base import AIRequest, ProviderExecutionError, TaskComplexity
from .providers.router import ModelRouter

_DEPS = load_dependencies()
_cc = _DEPS.catalog_copilot

Catalog = _cc.Catalog
CatalogItem = _cc.CatalogItem
CatalogLoader = _cc.CatalogLoader
ClaimType = _cc.ClaimType
CommercialClaimVerifier = _cc.CommercialClaimVerifier
DraftGenerator = _cc.DraftGenerator
DraftMessage = _cc.DraftMessage
FuzzyCatalogMatcher = _cc.FuzzyCatalogMatcher
LeadInquiry = _cc.LeadInquiry
VerificationReport = _cc.VerificationReport
VerificationStatus = _cc.VerificationStatus
parse_dialectal_inquiry = _cc.parse_dialectal_inquiry


def build_grounded_ai_callable(
    ai_router: ModelRouter,
    privacy_gate: Optional[PrivacyGate] = None,
    *,
    task_complexity: TaskComplexity = TaskComplexity.STANDARD,
    fallback_to_template: bool = True,
    on_metadata: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Callable[[str, Dict[str, Any]], str]:
    """Builds a CatalogCopilot custom_llm_callable backed by ModelRouter.

    AI output is ALWAYS a draft and never an authoritative source of commercial facts;
    CatalogCopilot's deterministic verifier validates every claim afterward.
    """

    def _call(base_draft: str, context: Dict[str, Any]) -> str:
        lang = str(context.get("preferred_language") or "ar")
        inquiry_text = str(context.get("inquiry_text") or "")
        item_dict = dict(context.get("item") or {})
        customer_name = str(context.get("customer_name") or "Customer")

        if privacy_gate is not None:
            for field_name, val in (("inquiry_text", inquiry_text), ("customer_name", customer_name)):
                leaked = privacy_gate.verify_text_clean(val)
                if leaked:
                    raise PrivacyViolationError(
                        f"Blocked outbound AI prompt with residual PII in {field_name}: {leaked}"
                    )

        system_prompt = (
            "You are TijaraGuard, a polite commercial customer-support assistant. "
            "Respond strictly in the customer's language ("
            + ("Arabic (MSA/clear polite tone)" if lang == "ar" else "English")
            + "). You MUST ONLY state prices, currency, stock availability, discounts, and offer "
            "details that appear verbatim in the provided JSON catalog item. NEVER invent discounts, "
            "warranties, free shipping, or lower prices. NEVER include personal identifiers."
        )
        user_prompt = (
            f"Customer Handle: {customer_name}\n"
            f"Redacted Customer Inquiry: {inquiry_text}\n"
            f"Verified Catalog Fact Sheet (JSON): {json.dumps(item_dict, ensure_ascii=False)}\n"
            f"Grounded Reference Template:\n{base_draft}\n\n"
            "Write a concise, helpful response strictly adhering to the Verified Catalog Fact Sheet."
        )

        req = AIRequest(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            task_complexity=task_complexity,
            temperature=0.2,
            max_tokens=450,
            metadata={"sku": item_dict.get("sku"), "language": lang},
        )
        try:
            resp = ai_router.generate(req)
            if on_metadata is not None:
                on_metadata(
                    {
                        "ai_provider": resp.provider,
                        "ai_model": resp.model,
                        "usage": resp.usage.to_dict(),
                        "latency_ms": round(resp.latency_ms, 2),
                        "fallback_events": list(resp.fallback_events),
                        "finish_reason": resp.finish_reason,
                        "mode": "ai_generated",
                    }
                )
            return resp.content
        except ProviderExecutionError as exc:
            if not fallback_to_template:
                raise
            if on_metadata is not None:
                on_metadata(
                    {
                        "ai_provider": "deterministic_template_fallback",
                        "ai_model": "catalog_copilot_template",
                        "mode": "template_fallback",
                        "fallback_from": exc.provider,
                        "error_code": exc.code.value,
                        "error_message": str(exc),
                    }
                )
            return base_draft

    return _call


class CommercialGate:
    """Resolves Arabic dialect inquiries and deterministically verifies commercial claims."""

    def __init__(
        self,
        catalog: Any,
        *,
        privacy_gate: Optional[PrivacyGate] = None,
    ) -> None:
        if not isinstance(catalog, Catalog):
            raise MalformedInputError("catalog must be a CatalogCopilot Catalog instance.")
        self.catalog = catalog
        self.verifier = CommercialClaimVerifier()
        self.generator = DraftGenerator(verifier=self.verifier)
        self.privacy_gate = privacy_gate

    @classmethod
    def from_json_file(
        cls,
        path: str | Path,
        *,
        privacy_gate: Optional[PrivacyGate] = None,
    ) -> "CommercialGate":
        """Loads a catalog from a JSON file using CatalogCopilot's CatalogLoader."""
        catalog = CatalogLoader.load_json(str(path))
        return cls(catalog, privacy_gate=privacy_gate)

    @classmethod
    def from_csv_file(
        cls,
        path: str | Path,
        *,
        privacy_gate: Optional[PrivacyGate] = None,
    ) -> "CommercialGate":
        """Loads a catalog from a CSV file using CatalogCopilot's CatalogLoader."""
        catalog = CatalogLoader.load_csv(str(path))
        return cls(catalog, privacy_gate=privacy_gate)

    def evaluate_and_draft(
        self,
        envelope: RedactedEnvelope,
        *,
        custom_llm_callable: Optional[Callable[[str, Dict[str, Any]], str]] = None,
        ai_router: Optional[ModelRouter] = None,
        task_complexity: TaskComplexity = TaskComplexity.STANDARD,
        fallback_to_template_on_ai_error: bool = True,
    ) -> CommercialEvaluation:
        """Matches redacted inquiry to catalog and verifies the generated/LLM draft."""
        cleaned_query = strip_redaction_markers(envelope.redacted_text)
        dialect_analysis = (
            parse_dialectal_inquiry(cleaned_query)
            if envelope.preferred_language == "ar" and cleaned_query
            else None
        )

        # Resolve product without sending raw PII into CatalogCopilot.
        resolved_sku = envelope.requested_sku
        resolution_notes: Optional[str] = None
        if not resolved_sku and cleaned_query:
            search_text = (
                dialect_analysis.cleaned_product_query
                if dialect_analysis and dialect_analysis.cleaned_product_query
                else cleaned_query
            )
            fuzzy_res = self.catalog.resolve_item_fuzzy(search_text, lang=envelope.preferred_language)
            resolution_notes = fuzzy_res.resolution_notes
            if fuzzy_res.has_match and not fuzzy_res.is_ambiguous and fuzzy_res.resolved_item:
                resolved_sku = fuzzy_res.resolved_item.sku
            elif not fuzzy_res.is_ambiguous:
                clauses = [c.strip() for c in re.split(r"[؟?!.\n]+", cleaned_query) if c.strip()]
                clause_matches: Dict[str, Any] = {}
                for clause in clauses:
                    clause_query = clause
                    if envelope.preferred_language == "ar":
                        clause_da = parse_dialectal_inquiry(clause)
                        if clause_da.cleaned_product_query:
                            clause_query = clause_da.cleaned_product_query
                    c_res = self.catalog.resolve_item_fuzzy(
                        clause_query, lang=envelope.preferred_language
                    )
                    if c_res.has_match and not c_res.is_ambiguous and c_res.resolved_item:
                        clause_matches[c_res.resolved_item.sku] = c_res
                if len(clause_matches) == 1:
                    only_res = next(iter(clause_matches.values()))
                    resolved_sku = only_res.resolved_item.sku
                    resolution_notes = only_res.resolution_notes

        lead = LeadInquiry(
            lead_id=envelope.message_id,
            customer_name=envelope.customer_handle,
            contact_channel="chat",
            contact_target=envelope.contact_ref,
            consent_to_contact=envelope.consent_to_contact,
            consent_evidence=envelope.consent_evidence,
            preferred_language=envelope.preferred_language,
            inquiry_text=cleaned_query or envelope.redacted_text,
            requested_sku=resolved_sku,
        )

        ai_meta_box: Dict[str, Any] = {}
        active_llm_callable = custom_llm_callable
        if active_llm_callable is None and ai_router is not None:
            active_llm_callable = build_grounded_ai_callable(
                ai_router,
                self.privacy_gate,
                task_complexity=task_complexity,
                fallback_to_template=fallback_to_template_on_ai_error,
                on_metadata=lambda m: ai_meta_box.update(m),
            )

        # Note: CatalogCopilot's DraftGenerator swallows exceptions from custom_llm_callable;
        # when fallback_to_template_on_ai_error is False we want explicit ProviderExecutionError propagation.
        captured_fatal_error: list[BaseException] = []

        def _guarded_callable(base_body: str, ctx: Dict[str, Any]) -> str:
            assert active_llm_callable is not None
            try:
                return active_llm_callable(base_body, ctx)
            except (ProviderExecutionError, PrivacyViolationError) as exc:
                if not fallback_to_template_on_ai_error or isinstance(exc, PrivacyViolationError):
                    captured_fatal_error.append(exc)
                raise

        callable_for_generator = _guarded_callable if active_llm_callable is not None else None
        draft: DraftMessage = self.generator.generate_draft(
            lead=lead,
            catalog=self.catalog,
            custom_llm_callable=callable_for_generator,
        )
        if captured_fatal_error:
            raise captured_fatal_error[0]

        report: VerificationReport = draft.verification_report
        report_dict = report.to_dict()
        status = report.status.value
        reasons = list(report.reasons)
        final_subject = draft.subject
        final_body = draft.body

        if self.privacy_gate is not None:
            leaked_in_body = self.privacy_gate.verify_text_clean(final_body)
            leaked_in_subject = self.privacy_gate.verify_text_clean(final_subject)
            leaked_in_report = self.privacy_gate.verify_text_clean(canonical_json(report_dict))
            leaked_types = sorted(set(leaked_in_body + leaked_in_subject + leaked_in_report))
            if leaked_types:
                final_body = self.privacy_gate.redact_text_full(final_body)
                final_subject = self.privacy_gate.redact_text_full(final_subject)
                report_dict = self.privacy_gate.redact_structure(report_dict)
                reasons = [self.privacy_gate.redact_text_full(r) for r in reasons]
                status = VerificationStatus.FAIL.value
                leak_note = f"PRIVACY_LEAK_IN_DRAFT: {leaked_types}"
                if leak_note not in reasons:
                    reasons.append(leak_note)
                report_dict["status"] = status
                report_dict["reasons"] = list(reasons)

        checks = list(report_dict["checks"])
        fuzzy_note = draft.fuzzy_match_notes or resolution_notes
        detected_dialect = (
            draft.detected_dialect
            or (dialect_analysis.detected_dialect.value if dialect_analysis else None)
        )
        intents = draft.query_intents or (
            [i.value for i in dialect_analysis.intents] if dialect_analysis else []
        )

        ai_provider = ai_meta_box.get("ai_provider")
        ai_model = ai_meta_box.get("ai_model")
        if ai_provider is None and custom_llm_callable is not None:
            ai_provider = "custom_callable"
            ai_model = "custom"
        elif ai_provider is None:
            ai_provider = "deterministic_template"
            ai_model = "catalog_copilot_template"

        return CommercialEvaluation(
            draft_id=draft.draft_id,
            sku=draft.sku,
            language=draft.language,
            subject=final_subject,
            body=final_body,
            verification_status=status,
            reasons=reasons,
            checks=checks,
            requires_human_intervention=bool(report.requires_human_intervention),
            detected_dialect=detected_dialect,
            query_intents=intents,
            fuzzy_match_notes=fuzzy_note,
            verification_report_dict=report_dict,
            ai_provider=ai_provider,
            ai_model=ai_model,
            ai_metadata=ai_meta_box,
        )

    def verify_edited_body(
        self,
        *,
        draft_row: Dict[str, Any],
        new_body: str,
    ) -> CommercialEvaluation:
        """Re-verifies a human-edited draft body against consent, catalog claims, and privacy."""
        if not isinstance(new_body, str) or not new_body.strip():
            raise MalformedInputError("Edited draft body must be a non-empty string.")

        lead = LeadInquiry(
            lead_id=draft_row["message_id"],
            customer_name=draft_row["customer_handle"],
            contact_channel="chat",
            contact_target=draft_row["contact_ref"],
            consent_to_contact=bool(draft_row["consent_to_contact"]),
            consent_evidence=draft_row["consent_evidence"],
            preferred_language=draft_row["language"],
            inquiry_text=draft_row["redacted_inquiry"],
            requested_sku=draft_row["sku"],
        )

        report = self.verifier.verify(
            lead=lead,
            catalog=self.catalog,
            draft_text=new_body,
            target_sku=draft_row["sku"],
        )
        report_dict = report.to_dict()
        status = report.status.value
        reasons = list(report.reasons)
        final_body = new_body

        if self.privacy_gate is not None:
            leaked_in_body = self.privacy_gate.verify_text_clean(final_body)
            leaked_in_report = self.privacy_gate.verify_text_clean(canonical_json(report_dict))
            leaked_types = sorted(set(leaked_in_body + leaked_in_report))
            if leaked_types:
                final_body = self.privacy_gate.redact_text_full(final_body)
                report_dict = self.privacy_gate.redact_structure(report_dict)
                reasons = [self.privacy_gate.redact_text_full(r) for r in reasons]
                status = VerificationStatus.FAIL.value
                leak_note = f"PRIVACY_LEAK_IN_DRAFT: {leaked_types}"
                if leak_note not in reasons:
                    reasons.append(leak_note)
                report_dict["status"] = status
                report_dict["reasons"] = list(reasons)

        return CommercialEvaluation(
            draft_id=draft_row["draft_id"],
            sku=draft_row["sku"],
            language=draft_row["language"],
            subject=draft_row["subject"],
            body=final_body,
            verification_status=status,
            reasons=reasons,
            checks=list(report_dict["checks"]),
            requires_human_intervention=bool(report.requires_human_intervention),
            detected_dialect=None,
            query_intents=[],
            fuzzy_match_notes=None,
            verification_report_dict=report_dict,
        )
