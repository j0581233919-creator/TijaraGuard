"""Core data models, canonical hashing helpers, and PII-safe exceptions for TijaraGuard."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


_SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
_SUPPORTED_CHANNELS = frozenset({"whatsapp", "chat", "sms", "email", "phone"})
_SUPPORTED_LANGS = frozenset({"ar", "en"})


class TijaraGuardError(Exception):
    """Base PII-safe exception for TijaraGuard."""


class MalformedInputError(TijaraGuardError, ValueError):
    """Raised when caller input fails validation without echoing raw PII."""


class PrivacyViolationError(TijaraGuardError):
    """Raised when unredacted PII is detected past a redaction boundary."""


class VerificationBlockedError(TijaraGuardError):
    """Raised when an operation attempts to approve or dispatch a blocked draft."""


class ApprovalRequiredError(TijaraGuardError):
    """Raised when dispatch lacks a valid active approval lease."""


class ApprovalTamperError(TijaraGuardError):
    """Raised when stored draft payload or approval MAC fails verification."""


class ApprovalAlreadyConsumedError(TijaraGuardError):
    """Raised when a single-use approval lease is replayed."""


class ApprovalExpiredError(TijaraGuardError):
    """Raised when an approval lease has expired."""


class DeliveryError(TijaraGuardError):
    """Raised on delivery configuration or gateway protocol failures."""


class ExecutionMode(str, Enum):
    """Controls outbound delivery behavior; defaults to Shadow Mode."""

    SHADOW = "SIMULATED_NO_SEND"
    LOOPBACK_LIVE = "LOOPBACK_LIVE"


class DraftState(str, Enum):
    """Authoritative lifecycle states persisted in the TijaraGuard ledger."""

    INGESTED = "INGESTED"
    VERIFIED_BLOCKED = "VERIFIED_BLOCKED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    SHADOW_RECORDED = "SHADOW_RECORDED"
    DISPATCHING = "DISPATCHING"
    UNKNOWN_DELIVERY = "UNKNOWN_DELIVERY"
    ACCEPTED_DELIVERY = "ACCEPTED_DELIVERY"
    DELIVERED = "DELIVERED"
    FAILED_DELIVERY = "FAILED_DELIVERY"


def canonical_json(value: Any) -> str:
    """Deterministically serializes JSON, rejecting NaN/Infinity."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def sha256_hex(text: str) -> str:
    """Returns lowercase SHA-256 hex digest of UTF-8 text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_sha256(value: Any) -> str:
    """Returns deterministic SHA-256 hex digest of a canonical JSON structure."""
    return sha256_hex(canonical_json(value))


def is_valid_sha256_hex(value: Any) -> bool:
    """Validates strict 64-char ASCII hex format before constant-time compare."""
    return isinstance(value, str) and bool(_SHA256_HEX_RE.fullmatch(value))


def validate_safe_id(value: Any, field_name: str) -> str:
    """Validates ASCII identifiers compatible with ledger and MessageShield constraints."""
    if not isinstance(value, str) or not _SAFE_ID_RE.fullmatch(value):
        raise MalformedInputError(
            f"Field '{field_name}' must be 1-80 ASCII letters, digits, '_' or '-'."
        )
    return value


def parse_bool_strict(value: Any, field_name: str = "value") -> bool:
    """Strictly parses explicit booleans; treats 'false'/'0'/'no'/'n' as False."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        norm = value.strip().lower()
        if norm in ("true", "1", "yes", "y"):
            return True
        if norm in ("false", "0", "no", "n"):
            return False
        raise MalformedInputError(
            f"Field '{field_name}' contains invalid boolean token."
        )
    if type(value) is int and value in (0, 1):
        return bool(value)
    raise MalformedInputError(f"Field '{field_name}' must be an explicit boolean.")


@dataclass(frozen=True)
class InboundMessage:
    """Unredacted inbound customer message before Gate 1 processing."""

    message_id: str
    conversation_id: str
    customer_handle: str
    raw_contact_target: str
    contact_channel: str
    consent_to_contact: Any
    consent_evidence: str
    preferred_language: str
    raw_text: str
    requested_sku: Optional[str] = None

    def __post_init__(self) -> None:
        validate_safe_id(self.message_id, "message_id")
        validate_safe_id(self.conversation_id, "conversation_id")
        if not isinstance(self.customer_handle, str) or not self.customer_handle.strip():
            raise MalformedInputError("Field 'customer_handle' must be a non-empty string.")
        if not isinstance(self.raw_contact_target, str) or not self.raw_contact_target.strip():
            raise MalformedInputError("Field 'raw_contact_target' must be a non-empty string.")
        if not isinstance(self.contact_channel, str):
            raise MalformedInputError("Field 'contact_channel' must be a string.")
        channel = self.contact_channel.strip().lower()
        if channel not in _SUPPORTED_CHANNELS:
            raise MalformedInputError("Field 'contact_channel' is not supported.")
        object.__setattr__(self, "contact_channel", channel)

        parsed_consent = parse_bool_strict(self.consent_to_contact, "consent_to_contact")
        object.__setattr__(self, "consent_to_contact", parsed_consent)

        if self.consent_evidence is None:
            object.__setattr__(self, "consent_evidence", "")
        elif not isinstance(self.consent_evidence, str):
            raise MalformedInputError("Field 'consent_evidence' must be a string.")

        if not isinstance(self.preferred_language, str):
            raise MalformedInputError("Field 'preferred_language' must be a string.")
        lang = self.preferred_language.strip().lower()
        normalized_lang = "ar" if lang in ("ar", "arabic", "ar-sa", "ar-eg", "عربي") else (
            "en" if lang in ("en", "english") else ""
        )
        if normalized_lang not in _SUPPORTED_LANGS:
            raise MalformedInputError("Field 'preferred_language' must be 'ar' or 'en'.")
        object.__setattr__(self, "preferred_language", normalized_lang)

        if not isinstance(self.raw_text, str) or not self.raw_text.strip():
            raise MalformedInputError("Field 'raw_text' must be a non-empty string.")

        if self.requested_sku is not None:
            if not isinstance(self.requested_sku, str):
                raise MalformedInputError("Field 'requested_sku' must be a string or None.")
            sku = self.requested_sku.strip().upper()
            object.__setattr__(self, "requested_sku", sku or None)


@dataclass(frozen=True)
class RedactedEnvelope:
    """Gate 1 output containing zero raw PII and an opaque contact reference."""

    message_id: str
    conversation_id: str
    customer_handle: str
    contact_ref: str
    contact_channel: str
    consent_to_contact: bool
    consent_evidence: str
    preferred_language: str
    redacted_text: str
    requested_sku: Optional[str]
    pii_summary: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CommercialEvaluation:
    """Gate 2 verification and grounded draft evaluation output."""

    draft_id: str
    sku: Optional[str]
    language: str
    subject: str
    body: str
    verification_status: str
    reasons: List[str]
    checks: List[Dict[str, Any]]
    requires_human_intervention: bool
    detected_dialect: Optional[str]
    query_intents: List[str]
    fuzzy_match_notes: Optional[str]
    verification_report_dict: Dict[str, Any]


@dataclass(frozen=True)
class ApprovalToken:
    """Cryptographic HMAC-SHA256 single-use approval lease bound to payload_sha256."""

    lease_id: str
    draft_id: str
    payload_sha256: str
    reviewer_id: str
    approved_at: float
    expires_at: float
    approval_mac: str


@dataclass(frozen=True)
class DispatchOutcome:
    """Result of Gate 3 consumption and Gate 4 delivery/recovery."""

    draft_id: str
    mode: str
    state: str
    dispatched: bool
    delivery_key: Optional[str] = None
    receipt_id: Optional[str] = None
    message_shield_state: Optional[str] = None
    reason: Optional[str] = None
