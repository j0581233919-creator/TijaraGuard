"""Official Telegram Bot API adapter."""

from __future__ import annotations

import hmac
import http.client
import json
import socket
import ssl
from typing import Any, Dict, List, Mapping, Optional, Tuple

from ..config import TelegramConfig
from ..models import ChannelError
from ..security import (
    ReplayError,
    SSRFError,
    WebhookSignatureError,
    open_validated_connection,
    scrub_secrets_from_text,
    validate_outbound_url,
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


class TelegramBotAdapter(ChannelAdapter):
    """Official Telegram Bot API adapter (webhooks + getUpdates + sendMessage)."""

    channel_name = "telegram"

    def __init__(
        self,
        config: TelegramConfig,
        *,
        allow_loopback: bool = False,
        replay_window_seconds: int = 300,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.config = config
        self.allow_loopback = bool(allow_loopback)
        self.replay_window_seconds = max(30, int(replay_window_seconds))
        self.timeout_seconds = max(0.5, float(timeout_seconds))
        base = (config.base_url or "https://api.telegram.org").rstrip("/")
        try:
            self.base_url = validate_outbound_url(
                base,
                allow_loopback=self.allow_loopback,
                allow_http_loopback=self.allow_loopback,
                require_dns=False,
            )
        except SSRFError as exc:
            raise ChannelError(f"Invalid Telegram base_url: {exc}") from exc
        self.endpoint_url = f"{self.base_url}/bot_api"

    def verify_inbound_request(
        self,
        headers: Mapping[str, str],
        raw_body: bytes,
        query_params: Optional[Mapping[str, str]] = None,
    ) -> None:
        secret = (self.config.webhook_secret_token or "").strip()
        if not secret:
            raise WebhookSignatureError(
                "Telegram webhook_secret_token is not configured (fail closed)."
            )
        provided = _header_ci(headers, "X-Telegram-Bot-Api-Secret-Token")
        if not provided or not hmac.compare_digest(provided.strip(), secret):
            raise WebhookSignatureError("Invalid or missing X-Telegram-Bot-Api-Secret-Token.")

    def parse_inbound(
        self,
        payload: Dict[str, Any],
        *,
        tenant_id: str = "default",
        enforce_replay_window: bool = True,
    ) -> Tuple[List[ChannelInboundEvent], List[ChannelStatusEvent]]:
        if not isinstance(payload, dict):
            raise ChannelError("Telegram update payload must be a JSON object.")

        if "result" in payload and isinstance(payload["result"], list):
            updates = payload["result"]
        else:
            updates = [payload]

        events: List[ChannelInboundEvent] = []
        for upd in updates:
            if not isinstance(upd, dict) or "update_id" not in upd:
                continue
            update_id = str(upd["update_id"])
            msg = upd.get("message") or upd.get("edited_message")
            if not isinstance(msg, dict):
                continue
            text = str(msg.get("text") or "").strip()
            chat = msg.get("chat") or {}
            chat_id = chat.get("id")
            if not text or chat_id is None:
                continue

            try:
                ts = float(msg.get("date", 0))
            except (TypeError, ValueError) as exc:
                raise ReplayError("Invalid Telegram message.date timestamp.") from exc
            if enforce_replay_window and not verify_timestamp_window(
                ts, max_skew_seconds=self.replay_window_seconds
            ):
                raise ReplayError("Telegram update timestamp outside replay window.")

            sender = msg.get("from") or {}
            if sender.get("is_bot"):
                continue
            chat_str = str(chat_id)
            handle = str(
                sender.get("username")
                or sender.get("first_name")
                or normalize_receipt_id("tg_user", chat_str)
            )
            safe_conv = normalize_receipt_id("tg", chat_str)

            events.append(
                ChannelInboundEvent(
                    channel="telegram",
                    external_event_id=update_id,
                    conversation_id=safe_conv[:80],
                    customer_handle=handle,
                    raw_contact_target=f"tg:{chat_str}",
                    external_target=chat_str,
                    text=text,
                    preferred_language=detect_preferred_language(text),
                    consent_to_contact=True,
                    consent_evidence=f"telegram_chat_opt_in:{update_id}",
                    timestamp=ts,
                    tenant_id=tenant_id,
                    metadata={"message_id": msg.get("message_id")},
                )
            )
        return events, []

    def send_message(
        self,
        target: str,
        text: str,
        *,
        idempotency_key: str,
        conversation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> OutboundSendResult:
        token = (self.config.bot_token or "").strip()
        if not token:
            raise ChannelError("Telegram bot_token is not configured.")

        try:
            conn, base_path, host_header = open_validated_connection(
                self.base_url,
                timeout=self.timeout_seconds,
                allow_loopback=self.allow_loopback,
            )
        except SSRFError as exc:
            raise ChannelError(f"Telegram endpoint blocked by SSRF policy: {exc}") from exc

        api_path = f"{base_path.rstrip('/')}/bot{token}/sendMessage"
        payload = {"chat_id": target, "text": text}
        raw_body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {
            "Host": host_header,
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
            conn.request("POST", api_path, body=raw_body, headers=headers)
            resp = conn.getresponse()
            raw_resp = resp.read(65536)
            data = json.loads(raw_resp.decode("utf-8")) if raw_resp else {}
            if resp.status == 200 and data.get("ok") is True:
                result_obj = data.get("result") or {}
                ext_id = str(result_obj.get("message_id") or idempotency_key[:24])
                return OutboundSendResult(
                    accepted=True,
                    external_message_id=ext_id,
                    receipt_id=normalize_receipt_id("telegram", ext_id),
                    status_code=200,
                )
            err_desc = scrub_secrets_from_text(
                str(data.get("description") or f"Telegram HTTP {resp.status}"),
                (token,),
            )
            return OutboundSendResult(
                accepted=False,
                retryable=False,
                uncertain=True,
                status_code=resp.status,
                error=err_desc,
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

    def fetch_updates(
        self,
        *,
        offset: Optional[int] = None,
        limit: int = 20,
        tenant_id: str = "default",
        enforce_replay_window: bool = False,
    ) -> List[ChannelInboundEvent]:
        """Polls Telegram getUpdates API (alternative to webhook mode)."""
        token = (self.config.bot_token or "").strip()
        if not token:
            raise ChannelError("Telegram bot_token is not configured.")
        try:
            conn, base_path, host_header = open_validated_connection(
                self.base_url,
                timeout=self.timeout_seconds,
                allow_loopback=self.allow_loopback,
            )
        except SSRFError as exc:
            raise ChannelError(f"Telegram endpoint blocked by SSRF policy: {exc}") from exc

        api_path = f"{base_path.rstrip('/')}/bot{token}/getUpdates"
        params = {"limit": max(1, min(100, int(limit))), "timeout": 0}
        if offset is not None:
            params["offset"] = int(offset)
        raw_body = json.dumps(params).encode("utf-8")
        headers = {
            "Host": host_header,
            "Content-Type": "application/json",
            "Content-Length": str(len(raw_body)),
            "Connection": "close",
        }
        try:
            conn.request("POST", api_path, body=raw_body, headers=headers)
            resp = conn.getresponse()
            raw_resp = resp.read(262144)
            data = json.loads(raw_resp.decode("utf-8")) if raw_resp else {}
            if resp.status != 200 or not data.get("ok"):
                raise ChannelError(
                    scrub_secrets_from_text(
                        f"Telegram getUpdates failed ({resp.status})", (token,)
                    )
                )
            events, _ = self.parse_inbound(
                data,
                tenant_id=tenant_id,
                enforce_replay_window=enforce_replay_window,
            )
            return events
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError) as exc:
            raise ChannelError(
                scrub_secrets_from_text(f"Telegram getUpdates error: {exc}", (token,))
            ) from exc
        finally:
            conn.close()

    def public_status(self) -> Dict[str, Any]:
        return {
            "channel": self.channel_name,
            **self.config.to_public_dict(),
        }
