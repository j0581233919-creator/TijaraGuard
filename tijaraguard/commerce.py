"""Gate 2 — CatalogCopilot commercial verification & Arabic dialect adapter."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Callable, Dict, Optional

from .deps import load_dependencies
from .models import CommercialEvaluation, MalformedInputError, RedactedEnvelope, canonical_json
from .privacy import PrivacyGate, strip_redaction_markers

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
                # If extra PII-bearing clauses diluted full-message score, check individual clauses.
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

        # Use channel='chat' + opaque contact_ref so LeadInquiry never needs raw phone/email.
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

        draft: DraftMessage = self.generator.generate_draft(
            lead=lead,
            catalog=self.catalog,
            custom_llm_callable=custom_llm_callable,
        )

        # Reuse DraftGenerator's deterministic verification report without redundant re-run.
        report: VerificationReport = draft.verification_report
        report_dict = report.to_dict()
        status = report.status.value
        reasons = list(report.reasons)
        final_subject = draft.subject
        final_body = draft.body

        # Defense-in-depth: ensure simulated LLM never persists raw PII into body, subject, or report.
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

        # Preserve explicit inquiry/resolution metadata cleanly.
        fuzzy_note = draft.fuzzy_match_notes or resolution_notes
        detected_dialect = (
            draft.detected_dialect
            or (dialect_analysis.detected_dialect.value if dialect_analysis else None)
        )
        intents = draft.query_intents or (
            [i.value for i in dialect_analysis.intents] if dialect_analysis else []
        )

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
