"""Documented Generic Webhook / REST channel adapter with HMAC signature & replay protection."""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple

from ..config import GenericWebhookConfig
from ..models import ChannelError, MalformedInputError, parse_bool_strict
from ..security import (
    ReplayError,
    SSRFError,
    WebhookSignatureError,
    compute_hmac_sha256_hex,
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


class GenericWebhookAdapter(ChannelAdapter):
    """Generic signed Webhook/REST integration channel."""

    channel_name = "webhook"

    def __init__(
        self,
        config: GenericWebhookConfig,
        *,
        allow_loopback: bool = False,
        replay_window_seconds: int = 300,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.config = config
        self.allow_loopback = bool(allow_loopback)
        self.replay_window_seconds = max(30, int(replay_window_seconds))
        self.timeout_seconds = max(0.5, float(timeout_seconds))
        self.outbound_url = ""
        if config.outbound_url.strip():
            try:
                self.outbound_url = validate_outbound_url(
                    config.outbound_url.strip(),
                    allow_loopback=self.allow_loopback,
                    allow_http_loopback=self.allow_loopback,
                    require_dns=False,
                )
            except SSRFError as exc:
                raise ChannelError(f"Invalid webhook outbound_url: {exc}") from exc
        self.receipt_lookup_url = ""
        if config.receipt_lookup_url.strip():
            try:
                self.receipt_lookup_url = validate_outbound_url(
                    config.receipt_lookup_url.strip(),
                    allow_loopback=self.allow_loopback,
                    allow_http_loopback=self.allow_loopback,
                    require_dns=False,
                )
            except SSRFError as exc:
                raise ChannelError(f"Invalid webhook receipt_lookup_url: {exc}") from exc
        self.endpoint_url = self.outbound_url or "https://webhook.invalid/disabled"

    def verify_inbound_request(
        self,
        headers: Mapping[str, str],
        raw_body: bytes,
        query_params: Optional[Mapping[str, str]] = None,
    ) -> None:
        secret = (self.config.inbound_secret or "").strip()
        if not secret:
            raise WebhookSignatureError(
                "Generic webhook inbound_secret is not configured (fail closed)."
            )
        ts_hdr = _header_ci(headers, "X-TijaraGuard-Timestamp")
        sig_hdr = _header_ci(headers, "X-TijaraGuard-Signature")
        if not ts_hdr or not sig_hdr:
            raise WebhookSignatureError(
                "Missing X-TijaraGuard-Timestamp or X-TijaraGuard-Signature header."
            )
        try:
            ts_val = float(ts_hdr)
        except ValueError as exc:
            raise ReplayError("Invalid X-TijaraGuard-Timestamp header.") from exc
        if not verify_timestamp_window(ts_val, max_skew_seconds=self.replay_window_seconds):
            raise ReplayError("Webhook timestamp outside replay window.")

        signed_payload = f"{ts_hdr}.".encode("utf-8") + raw_body
        if not verify_hmac_sha256(secret, signed_payload, sig_hdr, prefix="sha256="):
            raise WebhookSignatureError("Invalid X-TijaraGuard-Signature.")

    def parse_inbound(
        self,
        payload: Dict[str, Any],
        *,
        tenant_id: str = "default",
    ) -> Tuple[List[ChannelInboundEvent], List[ChannelStatusEvent]]:
        if not isinstance(payload, dict):
            raise ChannelError("Generic webhook payload must be a JSON object.")
        event_id = str(payload.get("event_id") or payload.get("message_id") or "").strip()
        conv_id = str(payload.get("conversation_id") or "").strip()
        text = str(payload.get("text") or "").strip()
        target = str(payload.get("target") or payload.get("contact") or "").strip()
        if not event_id or not conv_id or not text or not target:
            raise MalformedInputError(
                "Generic webhook payload requires event_id, conversation_id, target, and text."
            )

        raw_ts = payload.get("timestamp")
        if raw_ts is None:
            ts = time.time()
        elif isinstance(raw_ts, bool):
            raise MalformedInputError("Generic webhook 'timestamp' must be numeric.")
        else:
            try:
                ts = float(raw_ts)
            except (TypeError, ValueError) as exc:
                raise MalformedInputError("Generic webhook 'timestamp' must be numeric.") from exc

        raw_meta = payload.get("metadata")
        if raw_meta is None:
            meta: Dict[str, Any] = {}
        elif isinstance(raw_meta, dict):
            meta = dict(raw_meta)
        else:
            raise MalformedInputError("Generic webhook 'metadata' must be a JSON object.")

        lang = str(payload.get("preferred_language") or detect_preferred_language(text))
        consent = parse_bool_strict(payload.get("consent_to_contact", True), "consent_to_contact")
        evidence = str(payload.get("consent_evidence") or f"webhook_event:{event_id}")
        handle = str(payload.get("customer_handle") or f"wh_{conv_id[:16]}")
        req_sku = payload.get("requested_sku")

        # Always use authoritative server-supplied tenant_id (never trust payload["tenant_id"]).
        return [
            ChannelInboundEvent(
                channel="webhook",
                external_event_id=event_id,
                conversation_id=conv_id[:80],
                customer_handle=handle,
                raw_contact_target=target,
                external_target=target,
                text=text,
                preferred_language=lang,
                consent_to_contact=consent,
                consent_evidence=evidence,
                timestamp=ts,
                tenant_id=tenant_id,
                requested_sku=str(req_sku) if req_sku else None,
                metadata=meta,
            )
        ], []

    def send_message(
        self,
        target: str,
        text: str,
        *,
        idempotency_key: str,
        conversation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> OutboundSendResult:
        if not self.outbound_url:
            raise ChannelError("Generic webhook outbound_url is not configured.")
        try:
            conn, path, host_header = open_validated_connection(
                self.outbound_url,
                timeout=self.timeout_seconds,
                allow_loopback=self.allow_loopback,
            )
        except SSRFError as exc:
            raise ChannelError(f"Webhook outbound_url blocked by SSRF policy: {exc}") from exc

        payload = {
            "idempotency_key": idempotency_key,
            "target": target,
            "conversation_id": conversation_id,
            "text": text,
            "metadata": metadata or {},
        }
        raw_body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ts = str(int(time.time()))
        headers = {
            "Host": host_header,
            "Content-Type": "application/json",
            "Content-Length": str(len(raw_body)),
            "Idempotency-Key": idempotency_key,
            "X-TijaraGuard-Timestamp": ts,
            "Connection": "close",
        }
        out_secret = (self.config.outbound_secret or "").strip()
        if out_secret:
            sig = compute_hmac_sha256_hex(out_secret, f"{ts}.".encode("utf-8") + raw_body)
            headers["X-TijaraGuard-Signature"] = f"sha256={sig}"

        try:
            try:
                conn.connect()
            except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
                return OutboundSendResult(
                    accepted=False,
                    retryable=True,
                    uncertain=False,
                    error=scrub_secrets_from_text(str(exc), (out_secret,)),
                )
            conn.request("POST", path, body=raw_body, headers=headers)
            resp = conn.getresponse()
            raw_resp = resp.read(65536)
            if resp.status in (200, 201, 202):
                data = json.loads(raw_resp.decode("utf-8")) if raw_resp else {}
                ext_id = str(data.get("receipt_id") or data.get("message_id") or idempotency_key[:24])
                return OutboundSendResult(
                    accepted=True,
                    external_message_id=ext_id,
                    receipt_id=normalize_receipt_id("webhook", ext_id),
                    status_code=resp.status,
                )
            return OutboundSendResult(
                accepted=False,
                retryable=False,
                uncertain=True,
                status_code=resp.status,
                error=f"Webhook gateway HTTP {resp.status}",
            )
        except (TimeoutError, socket.timeout, OSError, http.client.HTTPException, ValueError) as exc:
            return OutboundSendResult(
                accepted=False,
                retryable=False,
                uncertain=True,
                error=scrub_secrets_from_text(str(exc), (out_secret,)),
            )
        finally:
            conn.close()

    def lookup_receipt(self, delivery_key: str) -> Optional[OutboundSendResult]:
        if not self.receipt_lookup_url:
            return None
        lookup_url = f"{self.receipt_lookup_url.rstrip('/')}/{delivery_key}"
        try:
            conn, path, host_header = open_validated_connection(
                lookup_url,
                timeout=self.timeout_seconds,
                allow_loopback=self.allow_loopback,
            )
        except SSRFError:
            return None
        try:
            conn.request(
                "GET",
                path,
                headers={"Host": host_header, "Accept": "application/json", "Connection": "close"},
            )
            resp = conn.getresponse()
            raw_resp = resp.read(65536)
            if resp.status == 200:
                data = json.loads(raw_resp.decode("utf-8")) if raw_resp else {}
                ext_id = str(data.get("receipt_id") or delivery_key[:24])
                return OutboundSendResult(
                    accepted=True,
                    external_message_id=ext_id,
                    receipt_id=normalize_receipt_id("webhook", ext_id),
                    status_code=200,
                )
            return None
        except Exception:
            return None
        finally:
            conn.close()

    def public_status(self) -> Dict[str, Any]:
        return {
            "channel": self.channel_name,
            **self.config.to_public_dict(),
        }
