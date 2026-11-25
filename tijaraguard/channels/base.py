"""Base channel adapter contracts, MessageShield transport bridge, and channel registry."""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

from ..models import ChannelError, TijaraGuardError


@dataclass(frozen=True)
class ChannelInboundEvent:
    """Normalized inbound message event produced by a channel adapter."""

    channel: str
    external_event_id: str
    conversation_id: str
    customer_handle: str
    raw_contact_target: str
    external_target: str
    text: str
    preferred_language: str
    consent_to_contact: Any
    consent_evidence: str
    timestamp: float
    tenant_id: str = "default"
    requested_sku: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ChannelStatusEvent:
    """Normalized delivery status callback event (e.g., WhatsApp sent/delivered/read/failed)."""

    channel: str
    external_event_id: str
    external_message_id: str
    status: str  # sent | delivered | read | failed
    timestamp: float
    error: Optional[str] = None


@dataclass(frozen=True)
class OutboundSendResult:
    """Normalized result of sending an approved message through an official channel API."""

    accepted: bool
    external_message_id: Optional[str] = None
    receipt_id: Optional[str] = None
    retryable: bool = False
    uncertain: bool = False
    status_code: Optional[int] = None
    error: Optional[str] = None


def normalize_receipt_id(channel: str, raw_id: str) -> str:
    """Maps an arbitrary external message ID into MessageShield's [A-Za-z0-9_-]{1,80} format."""
    digest = hashlib.sha256(f"{channel}:{raw_id}".encode("utf-8")).hexdigest()[:24]
    prefix = "".join(c for c in channel.lower() if c.isalnum())[:8] or "ch"
    return f"{prefix}-{digest}"


def detect_preferred_language(text: str) -> str:
    """Detects 'ar' if Arabic Unicode characters are present, otherwise 'en'."""
    for ch in text:
        if "\u0600" <= ch <= "\u06FF" or "\u0750" <= ch <= "\u077F" or "\u08A0" <= ch <= "\u08FF":
            return "ar"
    return "en"


class ChannelAdapter(ABC):
    """Abstract base class for official messaging channel integrations."""

    channel_name: str
    endpoint_url: str

    @abstractmethod
    def verify_inbound_request(
        self,
        headers: Mapping[str, str],
        raw_body: bytes,
        query_params: Optional[Mapping[str, str]] = None,
    ) -> None:
        """Verifies webhook authentication/signature/replay headers (fail closed)."""

    @abstractmethod
    def parse_inbound(
        self,
        payload: Dict[str, Any],
        *,
        tenant_id: str = "default",
    ) -> Tuple[List[ChannelInboundEvent], List[ChannelStatusEvent]]:
        """Parses an authenticated inbound webhook JSON payload into normalized events."""

    @abstractmethod
    def send_message(
        self,
        target: str,
        text: str,
        *,
        idempotency_key: str,
        conversation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> OutboundSendResult:
        """Sends an approved text message to `target` via the channel's official API."""

    def lookup_receipt(self, delivery_key: str) -> Optional[OutboundSendResult]:
        """Optional read-only delivery status lookup if supported by the channel."""
        return None

    @abstractmethod
    def public_status(self) -> Dict[str, Any]:
        """Returns non-secret channel status metadata."""


class ChannelShieldTransport:
    """Bridges MessageShield's Transport protocol to a ChannelAdapter for a specific target."""

    def __init__(
        self,
        *,
        adapter: ChannelAdapter,
        target: str,
        conversation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.adapter = adapter
        self.target = target
        self.conversation_id = conversation_id
        self.metadata = dict(metadata or {})
        self.timeout = float(getattr(adapter, "timeout_seconds", 5.0))

    def submit(self, message: Dict[str, Any]) -> Any:
        import json
        from message_shield.model import Outcome  # type: ignore[import-not-found]
        from message_shield.transport import delivery_key  # type: ignore[import-not-found]

        wire = json.loads(message["wire_json"])
        text = wire["text"]
        key = delivery_key(message)
        try:
            res = self.adapter.send_message(
                self.target,
                text,
                idempotency_key=key,
                conversation_id=self.conversation_id,
                metadata=self.metadata,
            )
        except Exception as exc:
            return Outcome("UNKNOWN", reason=f"Channel send error: {type(exc).__name__}")

        if res.accepted and res.receipt_id:
            return Outcome("ACCEPTED", receipt_id=res.receipt_id)
        if res.retryable and not res.uncertain:
            return Outcome("RETRYABLE", reason=res.error or "Transient pre-request failure")
        return Outcome("UNKNOWN", reason=res.error or "Channel delivery outcome unresolved")

    def lookup(self, message: Dict[str, Any]) -> Any:
        from message_shield.model import Outcome  # type: ignore[import-not-found]
        from message_shield.transport import delivery_key  # type: ignore[import-not-found]

        key = delivery_key(message)
        try:
            res = self.adapter.lookup_receipt(key)
        except Exception:
            res = None
        if res is not None and res.accepted and res.receipt_id:
            return Outcome("ACCEPTED", receipt_id=res.receipt_id)
        return Outcome("UNKNOWN", reason="Channel receipt unavailable via readback")


class ChannelRegistry:
    """Registry of configured official messaging channel adapters."""

    def __init__(self, adapters: Optional[Dict[str, ChannelAdapter]] = None) -> None:
        self._adapters: Dict[str, ChannelAdapter] = {}
        if adapters:
            for name, adapter in adapters.items():
                self.register(adapter, name=name)

    def register(self, adapter: ChannelAdapter, *, name: Optional[str] = None) -> None:
        key = (name or adapter.channel_name).strip().lower()
        self._adapters[key] = adapter

    def get(self, channel_name: str) -> ChannelAdapter:
        key = channel_name.strip().lower()
        if key not in self._adapters:
            raise ChannelError(f"Channel '{channel_name}' is not configured or enabled.")
        return self._adapters[key]

    def has(self, channel_name: str) -> bool:
        return channel_name.strip().lower() in self._adapters

    def list_status(self) -> Dict[str, Dict[str, Any]]:
        return {name: adapter.public_status() for name, adapter in self._adapters.items()}
