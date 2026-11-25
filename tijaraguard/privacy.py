"""Gate 1 — BayanGate privacy redaction adapter for TijaraGuard."""

from __future__ import annotations

import hashlib
import hmac
import math
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple

from .deps import load_dependencies
from .models import InboundMessage, MalformedInputError, PrivacyViolationError, RedactedEnvelope

_DEPS = load_dependencies()
_bayan_gate = _DEPS.bayan_gate

EntityType = _bayan_gate.EntityType
MaskingPolicy = _bayan_gate.MaskingPolicy
PIIRedactor = _bayan_gate.PIIRedactor
RegionalPIIEngine = _bayan_gate.RegionalPIIEngine
SUPPORTED_ENTITY_TYPES = _bayan_gate.SUPPORTED_ENTITY_TYPES
UNSUPPORTED_ENTITY_TYPES = _bayan_gate.UNSUPPORTED_ENTITY_TYPES

_REDACTION_MARKER_RE = re.compile(
    r"\[REDACTED_[A-Z0-9_]+\]|\[ID_[0-9a-fA-F]+\]|\[SYNTHETIC_[A-Z0-9_]+\]"
)
_PSEUDO_MARKER_RE = re.compile(r"\[[A-Z0-9_]+_[0-9a-fA-F]{6,32}\]")


def strip_redaction_markers(redacted_text: str) -> str:
    """Removes BayanGate placeholder tags so Gate 2 fuzzy catalog search stays accurate."""
    cleaned = _REDACTION_MARKER_RE.sub(" ", redacted_text)
    cleaned = _PSEUDO_MARKER_RE.sub(" ", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


_SAFE_METADATA_KEYS = frozenset(
    {
        "country",
        "country_code",
        "country_name",
        "id_type",
        "first_digit",
        "is_valid_checksum",
        "is_gcc",
        "card_network",
        "custom_pattern_name",
    }
)


def _scrub_redaction_metadata(meta: Dict[str, Any]) -> Dict[str, Any]:
    """Keeps structural/country metadata while stripping raw identifier values."""
    cleaned_entities: List[Dict[str, Any]] = []
    for ent in meta.get("entities", []):
        raw_submeta = ent.get("metadata") or {}
        safe_submeta = {k: v for k, v in raw_submeta.items() if k in _SAFE_METADATA_KEYS}
        cleaned_ent = dict(ent)
        cleaned_ent["metadata"] = safe_submeta
        cleaned_entities.append(cleaned_ent)
    cleaned = dict(meta)
    cleaned["entities"] = cleaned_entities
    return cleaned


class PrivacyGate:
    """Redacts MENA/GCC PII via BayanGate before persistence, logging, or Gate 2."""

    def __init__(
        self,
        policy: Any = MaskingPolicy.REDACT_FULL,
        *,
        salt: Optional[str] = None,
        contact_hash_key: Optional[bytes] = None,
        min_confidence: float = 0.5,
    ) -> None:
        if not isinstance(policy, MaskingPolicy):
            raise MalformedInputError("policy must be a valid MaskingPolicy enum value.")
        self.policy = policy
        self.min_confidence = float(min_confidence)
        self.engine = RegionalPIIEngine()
        self.redactor = PIIRedactor(engine=self.engine, salt=salt)
        self._salt = salt
        if contact_hash_key is None:
            self._contact_hash_key = secrets.token_bytes(32)
        else:
            if not isinstance(contact_hash_key, (bytes, bytearray)) or len(contact_hash_key) < 16:
                raise MalformedInputError("contact_hash_key must be bytes of at least 16 bytes.")
            self._contact_hash_key = bytes(contact_hash_key)

        # Fail closed up-front when PSEUDONYMIZE_HASH is selected without a valid salt.
        if self.policy == MaskingPolicy.PSEUDONYMIZE_HASH:
            self.redactor._resolve_effective_salt(salt)

    def _assert_clean_after_redaction(self, redacted_text: str, field_name: str) -> None:
        if self.policy in (MaskingPolicy.REDACT_FULL, MaskingPolicy.PSEUDONYMIZE_HASH):
            residual = self.verify_text_clean(redacted_text)
            if residual:
                raise PrivacyViolationError(
                    f"Residual PII categories remain in '{field_name}' after {self.policy.value}: {residual}"
                )

    def redact_text_full(self, text: str) -> str:
        """Deterministically redacts any supported PII in arbitrary text using REDACT_FULL."""
        if not isinstance(text, str) or not text.strip():
            return text
        res = self.redactor.redact(
            text,
            policy=MaskingPolicy.REDACT_FULL,
            min_confidence=self.min_confidence,
        )
        if self.verify_text_clean(res.redacted_text):
            return "[REDACTED_PII_CONTENT]"
        return res.redacted_text

    def redact_structure(self, value: Any) -> Any:
        """Recursively redacts all strings and numeric PII within nested structures."""
        if isinstance(value, str):
            return self.redact_text_full(value)
        if not isinstance(value, bool) and isinstance(value, (int, float)):
            candidates = [str(value)]
            if isinstance(value, float) and math.isfinite(value) and value.is_integer():
                candidates.append(str(int(value)))
            for candidate in candidates:
                if self.verify_text_clean(candidate):
                    return "[REDACTED_PII_VALUE]"
            return value
        if isinstance(value, list):
            return [self.redact_structure(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.redact_structure(item) for item in value)
        if isinstance(value, dict):
            return {
                (self.redact_text_full(k) if isinstance(k, str) else k): self.redact_structure(v)
                for k, v in value.items()
            }
        return value

    def redact_text(self, text: str) -> Tuple[str, Dict[str, Any]]:
        """Redacts PII from text and returns (redacted_text, zero_raw_pii_metadata)."""
        if not isinstance(text, str) or not text.strip():
            raise MalformedInputError("Text to redact must be a non-empty string.")
        result = self.redactor.redact(
            text,
            policy=self.policy,
            min_confidence=self.min_confidence,
            salt=self._salt,
        )
        metadata = _scrub_redaction_metadata(result.to_dict(include_raw_spans=False))
        self._assert_clean_after_redaction(result.redacted_text, "raw_text")
        return result.redacted_text, metadata

    def verify_text_clean(self, text: str) -> List[str]:
        """Returns sorted entity type names if supported PII appears in text (never values)."""
        if not isinstance(text, str) or not text:
            return []
        spans = self.engine.detect(text, min_confidence=self.min_confidence)
        return sorted({span.entity_type.value for span in spans})

    def verify_identifier_clean(self, value: str) -> List[str]:
        """Detects PII inside identifier tokens including '_' or '-' separated segments."""
        if not isinstance(value, str) or not value:
            return []
        normalized = re.sub(r"[_-]+", " ", value)
        direct = self.verify_text_clean(value)
        split = self.verify_text_clean(normalized) if normalized != value else []
        return sorted(set(direct + split))

    def opaque_contact_ref(self, raw_contact_target: str) -> str:
        """Converts raw phone/email into an irreversible opaque handle for safe persistence."""
        digest = hmac.new(
            self._contact_hash_key,
            raw_contact_target.strip().encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:16]
        return f"ref-{digest}"

    def sanitize_inbound(self, msg: InboundMessage) -> RedactedEnvelope:
        """Applies Gate 1 redaction across inbound text, handle, evidence, and contact target."""
        if not isinstance(msg, InboundMessage):
            raise MalformedInputError("Expected InboundMessage instance.")

        for id_value in (msg.message_id, msg.conversation_id, msg.requested_sku or ""):
            if id_value and self.verify_identifier_clean(id_value):
                raise PrivacyViolationError(
                    "Supported PII detected in identifier field; rejected before persistence."
                )

        redacted_text, text_meta = self.redact_text(msg.raw_text)

        handle_res = self.redactor.redact(
            msg.customer_handle,
            policy=self.policy,
            min_confidence=self.min_confidence,
            salt=self._salt,
        )
        self._assert_clean_after_redaction(handle_res.redacted_text, "customer_handle")

        evidence_redacted = ""
        evidence_entities: List[str] = []
        if msg.consent_evidence:
            ev_res = self.redactor.redact(
                msg.consent_evidence,
                policy=self.policy,
                min_confidence=self.min_confidence,
                salt=self._salt,
            )
            evidence_redacted = ev_res.redacted_text
            evidence_entities = sorted({s.entity_type.value for s in ev_res.entities_detected})
            self._assert_clean_after_redaction(evidence_redacted, "consent_evidence")

        contact_ref = self.opaque_contact_ref(msg.raw_contact_target)

        # Ensure metadata never carries raw PII strings.
        summary = {
            "policy_applied": text_meta["policy_applied"],
            "entity_count": text_meta["redaction_count"],
            "entity_type_counts": text_meta["entity_type_counts"],
            "entities": text_meta["entities"],
            "audit_hash": text_meta["audit_hash"],
            "handle_entities_redacted": len(handle_res.entities_detected),
            "evidence_entity_types_redacted": evidence_entities,
            "supported_entity_types": sorted(e.value for e in SUPPORTED_ENTITY_TYPES),
            "unsupported_entity_types": sorted(e.value for e in UNSUPPORTED_ENTITY_TYPES),
        }

        return RedactedEnvelope(
            message_id=msg.message_id,
            conversation_id=msg.conversation_id,
            customer_handle=handle_res.redacted_text,
            contact_ref=contact_ref,
            contact_channel=msg.contact_channel,
            consent_to_contact=msg.consent_to_contact,
            consent_evidence=evidence_redacted,
            preferred_language=msg.preferred_language,
            redacted_text=redacted_text,
            requested_sku=msg.requested_sku,
            pii_summary=summary,
        )
