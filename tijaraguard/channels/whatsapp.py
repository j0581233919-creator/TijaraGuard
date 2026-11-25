"""Official WhatsApp Business Cloud API adapter (Meta Graph API)."""

from __future__ import annotations

import hmac
import http.client
import json
import socket
import ssl
from typing import Any, Dict, List, Mapping, Optional, Tuple

from ..config import WhatsAppConfig
from ..models import ChannelError
from ..security import (
    ReplayError,
    SSRFError,
    WebhookSignatureError,
    open_validated_connection,
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


class WhatsAppCloudAdapter(ChannelAdapter):
    """Meta WhatsApp Business Cloud API v21.0 adapter."""

    channel_name = "whatsapp"

    def __init__(
        self,
        config: WhatsAppConfig,
        *,
        allow_loopback: bool = False,
        replay_window_seconds: int = 300,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.config = config
        self.allow_loopback = bool(allow_loopback)
        self.replay_window_seconds = max(30, int(replay_window_seconds))
        self.timeout_seconds = max(0.5, float(timeout_seconds))
        base = (config.base_url or "https://graph.facebook.com").rstrip("/")
        try:
            self.base_url = validate_outbound_url(
                base,
                allow_loopback=self.allow_loopback,
                allow_http_loopback=self.allow_loopback,
                require_dns=False,
            )
        except SSRFError as exc:
            raise ChannelError(f"Invalid WhatsApp base_url: {exc}") from exc
        self.api_version = (config.api_version or "v21.0").strip("/")
        self.phone_number_id = config.phone_number_id.strip()
        self.endpoint_url = (
            f"{self.base_url}/{self.api_version}/{self.phone_number_id or 'unconfigured'}/messages"
        )

    def verify_challenge(self, query_params: Mapping[str, str]) -> str:
        """Handles Meta webhook GET verification challenge (hub.mode, hub.verify_token, hub.challenge)."""
        verify_token = (self.config.verify_token or "").strip()
        if not verify_token:
            raise WebhookSignatureError("WhatsApp verify_token is not configured.")
        mode = query_params.get("hub.mode", "")
        token = query_params.get("hub.verify_token", "")
        challenge = query_params.get("hub.challenge", "")
        if mode != "subscribe" or not token or not hmac.compare_digest(token, verify_token):
            raise WebhookSignatureError("Invalid WhatsApp webhook verification challenge.")
        if not challenge:
            raise WebhookSignatureError("Missing hub.challenge parameter.")
        return challenge

    def verify_inbound_request(
        self,
        headers: Mapping[str, str],
        raw_body: bytes,
        query_params: Optional[Mapping[str, str]] = None,
    ) -> None:
        app_secret = (self.config.app_secret or "").strip()
        if not app_secret:
            raise WebhookSignatureError("WhatsApp app_secret is not configured (fail closed).")
        sig = _header_ci(headers, "X-Hub-Signature-256")
        if not verify_hmac_sha256(app_secret, raw_body, sig, prefix="sha256="):
            raise WebhookSignatureError("Invalid or missing X-Hub-Signature-256 header.")

    def parse_inbound(
        self,
        payload: Dict[str, Any],
        *,
        tenant_id: str = "default",
    ) -> Tuple[List[ChannelInboundEvent], List[ChannelStatusEvent]]:
        if not isinstance(payload, dict):
            raise ChannelError("WhatsApp webhook payload must be a JSON object.")

        inbound_events: List[ChannelInboundEvent] = []
        status_events: List[ChannelStatusEvent] = []

        for entry in payload.get("entry") or []:
            if not isinstance(entry, dict):
                continue
            for change in entry.get("changes") or []:
                if not isinstance(change, dict):
                    continue
                val = change.get("value") or {}
                if not isinstance(val, dict):
                    continue

                contacts_map: Dict[str, str] = {}
                for c in val.get("contacts") or []:
                    if isinstance(c, dict) and c.get("wa_id"):
                        prof = c.get("profile") or {}
                        contacts_map[str(c["wa_id"])] = str(prof.get("name") or "wa_customer")

                for msg in val.get("messages") or []:
                    if not isinstance(msg, dict):
                        continue
                    msg_id = str(msg.get("id") or "").strip()
                    sender = str(msg.get("from") or "").strip()
                    if not msg_id or not sender:
                        continue
                    try:
                        ts = float(msg.get("timestamp", 0))
                    except (TypeError, ValueError) as exc:
                        raise ReplayError("Invalid WhatsApp message timestamp.") from exc
                    if not verify_timestamp_window(ts, max_skew_seconds=self.replay_window_seconds):
                        raise ReplayError("WhatsApp message timestamp outside replay window.")

                    msg_type = str(msg.get("type") or "text").lower()
                    if msg_type == "text":
                        text_val = str((msg.get("text") or {}).get("body") or "").strip()
                    elif msg_type == "interactive":
                        inter = msg.get("interactive") or {}
                        btn = inter.get("button_reply") or inter.get("list_reply") or {}
                        text_val = str(btn.get("title") or "").strip()
                    else:
                        continue
                    if not text_val:
                        continue

                    handle = contacts_map.get(sender) or f"wa_{sender[-4:]}"
                    conv_id = normalize_receipt_id("wa", sender)
                    inbound_events.append(
                        ChannelInboundEvent(
                            channel="whatsapp",
                            external_event_id=msg_id,
                            conversation_id=conv_id[:80],
                            customer_handle=handle,
                            raw_contact_target=sender,
                            external_target=sender,
                            text=text_val,
                            preferred_language=detect_preferred_language(text_val),
                            consent_to_contact=True,
                            consent_evidence=f"whatsapp_inbound_session:{msg_id}",
                            timestamp=ts,
                            tenant_id=tenant_id,
                            metadata={"message_type": msg_type},
                        )
                    )

                for st in val.get("statuses") or []:
                    if not isinstance(st, dict):
                        continue
                    st_id = str(st.get("id") or "").strip()
                    st_name = str(st.get("status") or "").strip().lower()
                    if not st_id or st_name not in ("sent", "delivered", "read", "failed"):
                        continue
                    try:
                        ts = float(st.get("timestamp", 0))
                    except (TypeError, ValueError) as exc:
                        raise ReplayError("Invalid WhatsApp status timestamp.") from exc
                    if not verify_timestamp_window(ts, max_skew_seconds=self.replay_window_seconds):
                        raise ReplayError("WhatsApp status timestamp outside replay window.")
                    errors = st.get("errors") or []
                    err_msg = (
                        str(errors[0].get("title"))
                        if errors and isinstance(errors[0], dict)
                        else None
                    )
                    status_events.append(
                        ChannelStatusEvent(
                            channel="whatsapp",
                            external_event_id=f"{st_id}:{st_name}",
                            external_message_id=st_id,
                            status=st_name,
                            timestamp=ts,
                            error=err_msg,
                        )
                    )

        return inbound_events, status_events

    def send_message(
        self,
        target: str,
        text: str,
        *,
        idempotency_key: str,
        conversation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> OutboundSendResult:
        token = (self.config.access_token or "").strip()
        if not token or not self.phone_number_id:
            raise ChannelError("WhatsApp access_token or phone_number_id is not configured.")

        try:
            conn, path, host_header = open_validated_connection(
                self.endpoint_url,
                timeout=self.timeout_seconds,
                allow_loopback=self.allow_loopback,
            )
        except SSRFError as exc:
            raise ChannelError(f"WhatsApp endpoint blocked by SSRF policy: {exc}") from exc

        body = {
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": target,
            "type": "text",
            "text": {"preview_url": False, "body": text},
        }
        raw_body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers = {
            "Host": host_header,
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Content-Length": str(len(raw_body)),
            "X-Idempotency-Key": idempotency_key,
            "Connection": "close",
        }
        try:
            try:
                conn.connect()
            except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
                return OutboundSendResult(
                    accepted=False,
                    retryable=True,
                    uncertain=False,
                    error=scrub_secrets_from_text(str(exc), (token,)),
                )
            conn.request("POST", path, body=raw_body, headers=headers)
            resp = conn.getresponse()
            raw_resp = resp.read(65536)
            if resp.status in (200, 201):
                data = json.loads(raw_resp.decode("utf-8")) if raw_resp else {}
                msgs = data.get("messages") or []
                ext_id = (
                    str(msgs[0].get("id") or idempotency_key[:32])
                    if msgs and isinstance(msgs[0], dict)
                    else idempotency_key[:32]
                )
                return OutboundSendResult(
                    accepted=True,
                    external_message_id=ext_id,
                    receipt_id=normalize_receipt_id("whatsapp", ext_id),
                    status_code=resp.status,
                )
            if resp.status == 429 or resp.status >= 500:
                return OutboundSendResult(
                    accepted=False,
                    retryable=False,
                    uncertain=True,
                    status_code=resp.status,
                    error=f"WhatsApp gateway HTTP {resp.status}",
                )
            return OutboundSendResult(
                accepted=False,
                retryable=False,
                uncertain=True,
                status_code=resp.status,
                error=scrub_secrets_from_text(
                    raw_resp.decode("utf-8", errors="replace")[:200], (token,)
                ),
            )
        except (TimeoutError, socket.timeout, OSError, http.client.HTTPException, ValueError) as exc:
            return OutboundSendResult(
                accepted=False,
                retryable=False,
                uncertain=True,
                error=scrub_secrets_from_text(str(exc), (token,)),
            )
        finally:
            conn.close()

    def public_status(self) -> Dict[str, Any]:
        return {
            "channel": self.channel_name,
            **self.config.to_public_dict(),
        }
