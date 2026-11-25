"""Official Chatwoot webhook & REST API channel adapter."""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from ..config import ChatwootConfig
from ..models import ChannelError, parse_bool_strict
from ..security import (
    ReplayError,
    SSRFError,
    WebhookSignatureError,
    scrub_secrets_from_text,
    validate_outbound_url,
    verify_hmac_sha256,
    verify_timestamp_window,
)
from .base import (
    ChannelAdapter,
    ChannelInboundEvent,
    ChannelStatusEvent,
    OutboundSendResult,
    detect_preferred_language,
    normalize_receipt_id,
)


def _header_ci(headers: Mapping[str, str], name: str) -> Optional[str]:
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return None


class ChatwootAdapter(ChannelAdapter):
    """Chatwoot inbound webhook + REST API adapter (public replies, private notes, handoff)."""

    channel_name = "chatwoot"

    def __init__(
        self,
        config: ChatwootConfig,
        *,
        allow_loopback: bool = False,
        replay_window_seconds: int = 300,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.config = config
        self.allow_loopback = bool(allow_loopback)
        self.replay_window_seconds = max(30, int(replay_window_seconds))
        self.timeout_seconds = max(0.5, float(timeout_seconds))
        base = (config.base_url or "https://app.chatwoot.com").rstrip("/")
        try:
            self.base_url = validate_outbound_url(
                base,
                allow_loopback=self.allow_loopback,
                allow_http_loopback=self.allow_loopback,
            )
        except SSRFError as exc:
            raise ChannelError(f"Invalid Chatwoot base_url: {exc}") from exc
        self.account_id = str(config.account_id or "1").strip()
        self.endpoint_url = f"{self.base_url}/api/v1/accounts/{self.account_id}/conversations"

    def verify_inbound_request(
        self,
        headers: Mapping[str, str],
        raw_body: bytes,
        query_params: Optional[Mapping[str, str]] = None,
    ) -> None:
        secret = (self.config.webhook_secret or "").strip()
        if not secret:
            raise WebhookSignatureError("Chatwoot webhook_secret is not configured (fail closed).")

        ts_hdr = _header_ci(headers, "X-Chatwoot-Timestamp")
        if ts_hdr is not None:
            try:
                ts_val = float(ts_hdr)
            except ValueError as exc:
                raise ReplayError("Invalid X-Chatwoot-Timestamp header.") from exc
            if not verify_timestamp_window(ts_val, max_skew_seconds=self.replay_window_seconds):
                raise ReplayError("Chatwoot webhook timestamp outside replay window.")

        sig = _header_ci(headers, "X-Chatwoot-Signature")
        if not sig:
            raise WebhookSignatureError("Missing X-Chatwoot-Signature header.")

        # Accept either sha256=<hex> or raw hex HMAC over raw_body (or "{ts}.{body}" when ts present).
        body_ok = verify_hmac_sha256(secret, raw_body, sig, prefix="sha256=") or verify_hmac_sha256(
            secret, raw_body, sig, prefix=""
        )
        ts_body_ok = False
        if ts_hdr is not None:
            signed_bytes = f"{ts_hdr}.".encode("utf-8") + raw_body
            ts_body_ok = verify_hmac_sha256(
                secret, signed_bytes, sig, prefix="sha256="
            ) or verify_hmac_sha256(secret, signed_bytes, sig, prefix="")
        if not (body_ok or ts_body_ok):
            raise WebhookSignatureError("Invalid X-Chatwoot-Signature header.")

    def parse_inbound(
        self,
        payload: Dict[str, Any],
        *,
        tenant_id: str = "default",
    ) -> Tuple[List[ChannelInboundEvent], List[ChannelStatusEvent]]:
        if not isinstance(payload, dict):
            raise ChannelError("Chatwoot webhook payload must be a JSON object.")

        event_type = str(payload.get("event") or "").strip().lower()
        if event_type != "message_created":
            return [], []

        msg_type = payload.get("message_type")
        is_private = bool(payload.get("private", False))
        # Ignore outgoing messages & private notes to prevent infinite echo loops.
        if is_private or str(msg_type).lower() not in ("incoming", "0"):
            return [], []

        content = str(payload.get("content") or "").strip()
        if not content:
            return [], []

        msg_id = str(payload.get("id") or "").strip()
        conv = payload.get("conversation") or {}
        conv_id_raw = str(conv.get("id") or payload.get("conversation_id") or "").strip()
        if not msg_id or not conv_id_raw:
            return [], []

        raw_ts = payload.get("created_at")
        if raw_ts is not None:
            try:
                ts = float(raw_ts)
            except (TypeError, ValueError) as exc:
                raise ReplayError("Invalid Chatwoot created_at timestamp.") from exc
            if not verify_timestamp_window(ts, max_skew_seconds=self.replay_window_seconds):
                raise ReplayError("Chatwoot message created_at outside replay window.")
        else:
            ts = time.time()

        sender = payload.get("sender") or {}
        handle = str(sender.get("name") or f"cw_contact_{conv_id_raw}")
        contact_target = str(
            sender.get("phone_number")
            or sender.get("email")
            or sender.get("identifier")
            or f"chatwoot:{conv_id_raw}"
        )

        custom_attrs = (
            (conv.get("custom_attributes") or {})
            if isinstance(conv.get("custom_attributes"), dict)
            else {}
        )
        raw_consent = custom_attrs.get("consent_to_contact", True)
        try:
            consent_bool = parse_bool_strict(raw_consent, "consent_to_contact")
        except Exception:
            consent_bool = False

        safe_conv = (
            f"cw-{conv_id_raw}"
            if conv_id_raw.replace("_", "").replace("-", "").isalnum()
            else normalize_receipt_id("cw", conv_id_raw)
        )
        return [
            ChannelInboundEvent(
                channel="chatwoot",
                external_event_id=msg_id,
                conversation_id=safe_conv[:80],
                customer_handle=handle,
                raw_contact_target=contact_target,
                external_target=conv_id_raw,
                text=content,
                preferred_language=detect_preferred_language(content),
                consent_to_contact=consent_bool,
                consent_evidence=f"chatwoot_conversation:{conv_id_raw}",
                timestamp=ts,
                tenant_id=tenant_id,
                metadata={"chatwoot_conversation_id": conv_id_raw},
            )
        ], []

    def _post_chatwoot(self, path_suffix: str, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        token = (self.config.api_access_token or "").strip()
        if not token:
            raise ChannelError("Chatwoot api_access_token is not configured.")
        url = validate_outbound_url(
            f"{self.base_url}/api/v1/accounts/{self.account_id}{path_suffix}",
            allow_loopback=self.allow_loopback,
            allow_http_loopback=self.allow_loopback,
        )
        parsed = urlsplit(url)
        raw_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {
            "api_access_token": token,
            "Content-Type": "application/json",
            "Content-Length": str(len(raw_body)),
            "Connection": "close",
        }
        conn = (
            http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=self.timeout_seconds)
            if parsed.scheme == "https"
            else http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=self.timeout_seconds)
        )
        try:
            conn.connect()
            conn.request("POST", parsed.path, body=raw_body, headers=headers)
            resp = conn.getresponse()
            raw_resp = resp.read(65536)
            data = json.loads(raw_resp.decode("utf-8")) if raw_resp else {}
            return resp.status, data
        finally:
            conn.close()

    def send_message(
        self,
        target: str,
        text: str,
        *,
        idempotency_key: str,
        conversation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> OutboundSendResult:
        conv_ref = target or (conversation_id or "").removeprefix("cw-")
        token = (self.config.api_access_token or "").strip()
        try:
            status, data = self._post_chatwoot(
                f"/conversations/{conv_ref}/messages",
                {"content": text, "message_type": "outgoing", "private": False},
            )
            if status in (200, 201):
                ext_id = str(data.get("id") or idempotency_key[:24])
                return OutboundSendResult(
                    accepted=True,
                    external_message_id=ext_id,
                    receipt_id=normalize_receipt_id("chatwoot", ext_id),
                    status_code=status,
                )
            return OutboundSendResult(
                accepted=False,
                retryable=False,
                uncertain=True,
                status_code=status,
                error=f"Chatwoot API HTTP {status}",
            )
        except ChannelError:
            raise
        except (TimeoutError, socket.timeout, OSError, http.client.HTTPException, ssl.SSLError, ValueError) as exc:
            # Distinguish connection-before-request vs uncertain if needed; conservative UNKNOWN on transport failure
            return OutboundSendResult(
                accepted=False,
                retryable=False,
                uncertain=True,
                error=scrub_secrets_from_text(str(exc), (token,)),
            )

    def send_private_note(self, conversation_id: str, content: str) -> Dict[str, Any]:
        """Posts a private operator note invisible to the end customer."""
        conv_ref = conversation_id.removeprefix("cw-")
        status, data = self._post_chatwoot(
            f"/conversations/{conv_ref}/messages",
            {"content": content, "message_type": "outgoing", "private": True},
        )
        if status >= 400:
            raise ChannelError(f"Chatwoot private note failed with HTTP {status}.")
        return data

    def handoff_to_human(self, conversation_id: str, reason: str) -> Dict[str, Any]:
        """Marks conversation open for human agent attention and adds a private escalation note."""
        conv_ref = conversation_id.removeprefix("cw-")
        self._post_chatwoot(
            f"/conversations/{conv_ref}/toggle_status",
            {"status": "open"},
        )
        return self.send_private_note(
            conv_ref,
            f"[TijaraGuard Human Handoff] {reason}",
        )

    def public_status(self) -> Dict[str, Any]:
        return {
            "channel": self.channel_name,
            **self.config.to_public_dict(),
        }
