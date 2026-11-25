"""Secure stdlib REST API, webhook endpoints, and lightweight operator dashboard server."""

from __future__ import annotations

import csv
import io
import json
import logging
import socket
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

from .config import TijaraGuardConfig
from .models import (
    ApprovalAlreadyConsumedError,
    ApprovalExpiredError,
    ApprovalRequiredError,
    ApprovalTamperError,
    ApprovalToken,
    ChannelError,
    DeliveryError,
    InboundMessage,
    MalformedInputError,
    PrivacyViolationError,
    ProviderError,
    VerificationBlockedError,
    canonical_json,
)
from .pipeline import TijaraGuardPipeline
from .runtime import build_pipeline_from_config
from .security import (
    ReplayError,
    SlidingWindowRateLimiter,
    WebhookSignatureError,
    sanitize_csv_cell,
    verify_bearer_or_api_key,
)

logger = logging.getLogger("tijaraguard.api")

_MAX_REQUEST_BODY_BYTES = 1_048_576  # 1 MiB
_DASHBOARD_HTML_PATH = Path(__file__).resolve().parent / "web" / "index.html"


def _query_map(raw_query: str) -> Dict[str, str]:
    parsed = parse_qs(raw_query, keep_blank_values=True)
    return {k: v[0] for k, v in parsed.items() if v}


def _safe_draft_view(row: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(row)
    for json_col, target_key in (
        ("pii_summary_json", "pii_summary"),
        ("verification_report_json", "verification_report"),
        ("ai_metadata_json", "ai_metadata"),
        ("channel_metadata_json", "channel_metadata"),
    ):
        raw = out.pop(json_col, None)
        if isinstance(raw, str):
            try:
                out[target_key] = json.loads(raw)
            except json.JSONDecodeError:
                out[target_key] = {}
    out["consent_to_contact"] = bool(out.get("consent_to_contact", 0))
    return out


class TijaraGuardHTTPServer:
    """Production-oriented ThreadingHTTPServer exposing REST API, webhooks, and dashboard."""

    def __init__(
        self,
        config: TijaraGuardConfig,
        *,
        pipeline: Optional[TijaraGuardPipeline] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
    ) -> None:
        self.config = config
        self.pipeline = pipeline or build_pipeline_from_config(config)
        self.host = host or config.bind_host
        self.port = config.bind_port if port is None else int(port)
        self.rate_limiter = SlidingWindowRateLimiter(
            max_requests=max(1, config.rate_limit_per_minute),
            window_seconds=60.0,
        )
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._dashboard_bytes = _DASHBOARD_HTML_PATH.read_bytes()

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("Server is not started.")
        host_fmt = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host_fmt}:{self._server.server_port}"

    def _authenticate_api(self, headers: Mapping[str, str]) -> bool:
        return verify_bearer_or_api_key(headers, self.config.operator_api_key)

    def start(self) -> "TijaraGuardHTTPServer":
        if self._server is not None:
            return self
        app = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(15.0)

            def log_message(self, format: str, *args: Any) -> None:
                # Privacy-safe structured logging only; never dump raw request lines/queries.
                return

            def _send_bytes(
                self,
                status_code: int,
                content_type: str,
                raw: bytes,
                *,
                extra_headers: Optional[Dict[str, str]] = None,
            ) -> None:
                self.close_connection = True
                try:
                    self.send_response(status_code)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(raw)))
                    self.send_header("Connection", "close")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("X-Frame-Options", "DENY")
                    self.send_header("Referrer-Policy", "no-referrer")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header(
                        "Content-Security-Policy",
                        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
                    )
                    if extra_headers:
                        for hk, hv in extra_headers.items():
                            self.send_header(hk, hv)
                    self.end_headers()
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return

            def _send_json(
                self,
                status_code: int,
                obj: Any,
                *,
                extra_headers: Optional[Dict[str, str]] = None,
            ) -> None:
                raw = canonical_json(obj).encode("utf-8")
                self._send_bytes(
                    status_code,
                    "application/json; charset=utf-8",
                    raw,
                    extra_headers=extra_headers,
                )

            def _read_body(self) -> Tuple[bytes, Dict[str, Any]]:
                if self.headers.get_all("Transfer-Encoding"):
                    raise MalformedInputError("Transfer-Encoding is not supported.")
                cl_headers = self.headers.get_all("Content-Length") or []
                if len(cl_headers) == 0:
                    return b"", {}
                if len(cl_headers) != 1:
                    raise MalformedInputError("Multiple Content-Length headers rejected.")
                raw_len = cl_headers[0].strip()
                if not raw_len or not raw_len.isascii() or not raw_len.isdigit():
                    raise MalformedInputError("Invalid Content-Length header.")
                length = int(raw_len)
                if length == 0:
                    return b"", {}
                if length > _MAX_REQUEST_BODY_BYTES:
                    raise MalformedInputError("Request payload exceeds 1 MiB limit.")
                raw_bytes = self.rfile.read(length)
                if len(raw_bytes) != length:
                    raise MalformedInputError("Incomplete request body.")
                try:
                    data = json.loads(raw_bytes.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise MalformedInputError("Malformed JSON payload.") from exc
                if not isinstance(data, dict):
                    raise MalformedInputError("JSON payload must be an object.")
                return raw_bytes, data

            def _check_rate_limit(self) -> bool:
                client_ip = self.client_address[0] if self.client_address else "unknown"
                allowed, retry_after = app.rate_limiter.check(client_ip)
                if not allowed:
                    self._send_json(
                        429,
                        {"error": "rate_limited", "retry_after_seconds": round(retry_after, 2)},
                        extra_headers={"Retry-After": str(max(1, int(retry_after)))},
                    )
                    return False
                return True

            def _require_auth(self) -> bool:
                if not app._authenticate_api(self.headers):
                    self._send_json(401, {"error": "unauthorized"})
                    return False
                return True

            def _handle_error(self, exc: Exception) -> None:
                if isinstance(exc, (WebhookSignatureError, ReplayError)):
                    self._send_json(401, {"error": "webhook_auth_failed", "detail": str(exc)})
                elif isinstance(exc, MalformedInputError):
                    self._send_json(400, {"error": "bad_request", "detail": str(exc)})
                elif isinstance(exc, PrivacyViolationError):
                    self._send_json(422, {"error": "privacy_violation", "detail": str(exc)})
                elif isinstance(
                    exc,
                    (
                        VerificationBlockedError,
                        ApprovalRequiredError,
                        ApprovalTamperError,
                        ApprovalAlreadyConsumedError,
                        ApprovalExpiredError,
                    ),
                ):
                    self._send_json(409, {"error": type(exc).__name__, "detail": str(exc)})
                elif isinstance(exc, (DeliveryError, ChannelError, ProviderError)):
                    self._send_json(502, {"error": type(exc).__name__, "detail": str(exc)})
                else:
                    logger.error("api_unhandled_error type=%s", type(exc).__name__)
                    self._send_json(500, {"error": "internal_error"})

            def do_GET(self) -> None:
                if not self._check_rate_limit():
                    return
                parsed = urlsplit(self.path)
                path = parsed.path
                q = _query_map(parsed.query)

                try:
                    if path == "/":
                        self._send_bytes(200, "text/html; charset=utf-8", app._dashboard_bytes)
                        return
                    if path == "/health":
                        self._send_json(
                            200,
                            {
                                "status": "ok",
                                "service": "tijaraguard",
                                "mode": app.pipeline.mode.value,
                            },
                        )
                        return
                    if path == "/ready":
                        chain_ok, chain_errs = app.pipeline.ledger.verify_audit_chain()
                        code = 200 if chain_ok else 503
                        self._send_json(
                            code,
                            {
                                "ready": chain_ok,
                                "audit_chain_valid": chain_ok,
                                "audit_errors": len(chain_errs),
                            },
                        )
                        return

                    # Meta WhatsApp webhook GET verification challenge
                    if path == "/webhooks/whatsapp":
                        if not app.pipeline.channel_registry.has("whatsapp"):
                            self._send_json(404, {"error": "whatsapp_not_enabled"})
                            return
                        wa = app.pipeline.channel_registry.get("whatsapp")
                        challenge = wa.verify_challenge(q)  # type: ignore[attr-defined]
                        self._send_bytes(200, "text/plain; charset=utf-8", challenge.encode("utf-8"))
                        return

                    if not path.startswith("/api/v1/"):
                        self._send_json(404, {"error": "not_found"})
                        return
                    if not self._require_auth():
                        return

                    if path == "/api/v1/status":
                        chain_ok, chain_errs = app.pipeline.ledger.verify_audit_chain()
                        self._send_json(
                            200,
                            {
                                "mode": app.pipeline.mode.value,
                                "tenant_id": app.pipeline.tenant_id,
                                "audit_chain_valid": chain_ok,
                                "audit_chain_errors": chain_errs,
                                "state_counts": app.pipeline.ledger.get_state_counts(
                                    tenant_id=app.pipeline.tenant_id
                                ),
                                "providers": (
                                    app.pipeline.ai_router.public_summary()
                                    if app.pipeline.ai_router
                                    else {"providers": [], "routing": {}}
                                ),
                                "channels": app.pipeline.channel_registry.list_status(),
                                "catalog_size": len(app.pipeline.commercial_gate.catalog.list_all()),
                            },
                        )
                        return

                    if path == "/api/v1/catalog":
                        items = [i.to_dict() for i in app.pipeline.commercial_gate.catalog.list_all()]
                        self._send_json(200, {"items": items})
                        return

                    if path == "/api/v1/catalog/search":
                        query = q.get("q", "").strip()
                        lang = q.get("lang", "ar").strip() or "ar"
                        if not query:
                            self._send_json(400, {"error": "missing_query"})
                            return
                        res = app.pipeline.commercial_gate.catalog.resolve_item_fuzzy(
                            query, lang=lang
                        )
                        self._send_json(
                            200,
                            {
                                "query": query,
                                "has_match": res.has_match,
                                "is_ambiguous": res.is_ambiguous,
                                "resolved_item": res.resolved_item.to_dict()
                                if res.resolved_item
                                else None,
                                "candidates": [
                                    {"sku": c.item.sku, "score": c.score, "match_type": c.match_type.value}
                                    for c in res.candidates
                                ],
                                "notes": res.resolution_notes,
                            },
                        )
                        return

                    if path == "/api/v1/conversations":
                        convs = app.pipeline.ledger.list_conversations(
                            tenant_id=q.get("tenant_id") or app.pipeline.tenant_id,
                            limit=int(q.get("limit", "100")),
                        )
                        self._send_json(200, {"conversations": convs})
                        return

                    if path == "/api/v1/drafts":
                        drafts = app.pipeline.ledger.list_drafts(
                            tenant_id=q.get("tenant_id") or app.pipeline.tenant_id,
                            state=q.get("state") or None,
                            conversation_id=q.get("conversation_id") or None,
                            limit=int(q.get("limit", "100")),
                        )
                        self._send_json(200, {"drafts": [_safe_draft_view(d) for d in drafts]})
                        return

                    if path.startswith("/api/v1/drafts/"):
                        draft_id = path[len("/api/v1/drafts/"):].strip("/")
                        if "/" in draft_id or not draft_id:
                            self._send_json(404, {"error": "not_found"})
                            return
                        draft = app.pipeline.ledger.get_draft(draft_id)
                        events = app.pipeline.ledger.list_audit_events(draft_id=draft_id)
                        active_app = app.pipeline.ledger.get_active_approval(draft_id)
                        self._send_json(
                            200,
                            {
                                "draft": _safe_draft_view(draft),
                                "active_approval": {
                                    "lease_id": active_app["lease_id"],
                                    "reviewer_id": active_app["reviewer_id"],
                                    "expires_at": active_app["expires_at"],
                                }
                                if active_app
                                else None,
                                "audit_events": events,
                            },
                        )
                        return

                    if path == "/api/v1/audit":
                        draft_id = q.get("draft_id") or None
                        events = app.pipeline.ledger.list_audit_events(draft_id=draft_id)
                        valid, errors = app.pipeline.ledger.verify_audit_chain()
                        self._send_json(
                            200,
                            {"valid": valid, "errors": errors, "events": events},
                        )
                        return

                    if path == "/api/v1/audit/export.csv":
                        events = app.pipeline.ledger.list_audit_events(
                            draft_id=q.get("draft_id") or None
                        )
                        buf = io.StringIO()
                        writer = csv.writer(buf)
                        writer.writerow(
                            [
                                "seq",
                                "draft_id",
                                "event_type",
                                "from_state",
                                "to_state",
                                "actor",
                                "payload_sha256",
                                "created_at",
                                "event_hash",
                            ]
                        )
                        for ev in events:
                            writer.writerow(
                                [
                                    sanitize_csv_cell(ev["seq"]),
                                    sanitize_csv_cell(ev["draft_id"]),
                                    sanitize_csv_cell(ev["event_type"]),
                                    sanitize_csv_cell(ev["from_state"] or ""),
                                    sanitize_csv_cell(ev["to_state"]),
                                    sanitize_csv_cell(ev["actor"]),
                                    sanitize_csv_cell(ev["payload_sha256"] or ""),
                                    sanitize_csv_cell(ev["created_at"]),
                                    sanitize_csv_cell(ev["event_hash"]),
                                ]
                            )
                        self._send_bytes(
                            200,
                            "text/csv; charset=utf-8",
                            buf.getvalue().encode("utf-8"),
                            extra_headers={
                                "Content-Disposition": 'attachment; filename="tijaraguard_audit.csv"'
                            },
                        )
                        return

                    if path == "/api/v1/providers":
                        self._send_json(
                            200,
                            app.pipeline.ai_router.public_summary()
                            if app.pipeline.ai_router
                            else {"providers": [], "routing": {}},
                        )
                        return

                    if path == "/api/v1/channels":
                        self._send_json(200, {"channels": app.pipeline.channel_registry.list_status()})
                        return

                    if path == "/api/v1/usage":
                        self._send_json(
                            200,
                            app.pipeline.ledger.get_provider_usage_summary(
                                tenant_id=q.get("tenant_id") or app.pipeline.tenant_id
                            ),
                        )
                        return

                    self._send_json(404, {"error": "not_found"})
                except Exception as exc:
                    self._handle_error(exc)

            def do_POST(self) -> None:
                if not self._check_rate_limit():
                    return
                parsed = urlsplit(self.path)
                path = parsed.path
                q = _query_map(parsed.query)

                try:
                    raw_body, data = self._read_body()

                    # Channel Webhooks (authenticated by channel-specific cryptographic checks)
                    if path.startswith("/webhooks/"):
                        channel_name = path[len("/webhooks/"):].strip("/").lower()
                        if channel_name == "generic":
                            channel_name = "webhook"
                        if not app.pipeline.channel_registry.has(channel_name):
                            self._send_json(404, {"error": f"channel_{channel_name}_not_enabled"})
                            return
                        adapter = app.pipeline.channel_registry.get(channel_name)
                        adapter.verify_inbound_request(self.headers, raw_body, q)
                        inbound_events, status_events = adapter.parse_inbound(
                            data, tenant_id=app.pipeline.tenant_id
                        )
                        ingested = [
                            app.pipeline.ingest_channel_event(ev) for ev in inbound_events
                        ]
                        statuses = [
                            app.pipeline.process_status_event(st) for st in status_events
                        ]
                        self._send_json(
                            200,
                            {
                                "ok": True,
                                "ingested_count": len(ingested),
                                "status_count": len(statuses),
                                "ingested": ingested,
                                "statuses": statuses,
                            },
                        )
                        return

                    if not path.startswith("/api/v1/"):
                        self._send_json(404, {"error": "not_found"})
                        return
                    if not self._require_auth():
                        return

                    if path == "/api/v1/inquiries":
                        msg = InboundMessage(
                            message_id=str(data.get("message_id") or f"msg-{int(time.time()*1000)}"),
                            conversation_id=str(data.get("conversation_id") or f"conv-{int(time.time()*1000)}"),
                            customer_handle=str(data.get("customer_handle") or "customer"),
                            raw_contact_target=str(data.get("raw_contact_target") or "api-client"),
                            contact_channel=str(data.get("contact_channel") or "chat"),
                            consent_to_contact=data.get("consent_to_contact", False),
                            consent_evidence=str(data.get("consent_evidence") or ""),
                            preferred_language=str(data.get("preferred_language") or "ar"),
                            raw_text=str(data.get("raw_text") or ""),
                            requested_sku=data.get("requested_sku"),
                            tenant_id=str(data.get("tenant_id") or app.pipeline.tenant_id),
                        )
                        res = app.pipeline.process_inbound(msg)
                        self._send_json(201, res)
                        return

                    if path == "/api/v1/providers/health":
                        results = (
                            [r.to_dict() for r in app.pipeline.ai_router.health_check_all()]
                            if app.pipeline.ai_router
                            else []
                        )
                        self._send_json(200, {"results": results})
                        return

                    if path == "/api/v1/maintenance/backup":
                        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                        dest = app.config.backup_dir / f"ledger-{stamp}.sqlite3"
                        info = app.pipeline.ledger.backup_to(dest)
                        self._send_json(200, info)
                        return

                    if path == "/api/v1/maintenance/purge":
                        res = app.pipeline.ledger.purge_expired_retention(
                            channel_event_max_age_seconds=app.config.retention.channel_event_retention_days
                            * 86400
                        )
                        if app.pipeline.route_store is not None:
                            res["purged_routes"] = app.pipeline.route_store.purge_expired()
                        self._send_json(200, res)
                        return

                    if path.startswith("/api/v1/drafts/"):
                        parts = [p for p in path[len("/api/v1/drafts/"):].split("/") if p]
                        if len(parts) != 2:
                            self._send_json(404, {"error": "not_found"})
                            return
                        draft_id, action = parts

                        if action == "approve":
                            token = app.pipeline.approve(
                                draft_id,
                                reviewer_id=str(data.get("reviewer_id") or "operator"),
                                expected_payload_sha256=str(data.get("expected_payload_sha256") or ""),
                                notes=str(data.get("notes") or ""),
                                ttl_seconds=int(data.get("ttl_seconds") or 900),
                            )
                            self._send_json(
                                200,
                                {
                                    "lease_id": token.lease_id,
                                    "draft_id": token.draft_id,
                                    "payload_sha256": token.payload_sha256,
                                    "reviewer_id": token.reviewer_id,
                                    "approved_at": token.approved_at,
                                    "expires_at": token.expires_at,
                                    "approval_mac": token.approval_mac,
                                },
                            )
                            return

                        if action == "reject":
                            row = app.pipeline.reject(
                                draft_id,
                                reviewer_id=str(data.get("reviewer_id") or "operator"),
                                reason=str(data.get("reason") or "rejected"),
                            )
                            self._send_json(200, {"draft": _safe_draft_view(row)})
                            return

                        if action == "edit":
                            row = app.pipeline.edit_draft(
                                draft_id,
                                new_body=str(data.get("new_body") or ""),
                                actor=str(data.get("actor") or "operator"),
                            )
                            self._send_json(200, {"draft": _safe_draft_view(row)})
                            return

                        if action == "escalate":
                            row = app.pipeline.escalate(
                                draft_id,
                                actor=str(data.get("actor") or "operator"),
                                reason=str(data.get("reason") or "human_handoff"),
                            )
                            self._send_json(200, {"draft": _safe_draft_view(row)})
                            return

                        if action == "dispatch":
                            active = app.pipeline.ledger.get_active_approval(draft_id)
                            if active is None:
                                raise ApprovalRequiredError(
                                    f"No active approval lease found for '{draft_id}'."
                                )
                            token = ApprovalToken(
                                lease_id=str(data.get("lease_id") or active["lease_id"]),
                                draft_id=draft_id,
                                payload_sha256=str(
                                    data.get("payload_sha256") or active["payload_sha256"]
                                ),
                                reviewer_id=active["reviewer_id"],
                                approved_at=float(active["approved_at"]),
                                expires_at=float(active["expires_at"]),
                                approval_mac=str(data.get("approval_mac") or active["approval_mac"]),
                            )
                            outcome = app.pipeline.dispatch(
                                draft_id,
                                token,
                                confirm_delivered=bool(data.get("confirm_delivered", True)),
                                recipient_target=data.get("recipient_target"),
                            )
                            self._send_json(
                                200,
                                {
                                    "draft_id": outcome.draft_id,
                                    "mode": outcome.mode,
                                    "state": outcome.state,
                                    "dispatched": outcome.dispatched,
                                    "delivery_key": outcome.delivery_key,
                                    "receipt_id": outcome.receipt_id,
                                    "message_shield_state": outcome.message_shield_state,
                                    "reason": outcome.reason,
                                },
                            )
                            return

                        if action == "recover":
                            outcome = app.pipeline.recover_delivery(
                                draft_id,
                                confirm_delivered=bool(data.get("confirm_delivered", True)),
                            )
                            self._send_json(
                                200,
                                {
                                    "draft_id": outcome.draft_id,
                                    "mode": outcome.mode,
                                    "state": outcome.state,
                                    "dispatched": outcome.dispatched,
                                    "delivery_key": outcome.delivery_key,
                                    "receipt_id": outcome.receipt_id,
                                    "message_shield_state": outcome.message_shield_state,
                                    "reason": outcome.reason,
                                },
                            )
                            return

                    self._send_json(404, {"error": "not_found"})
                except Exception as exc:
                    self._handle_error(exc)

        class ServerImpl(ThreadingHTTPServer):
            allow_reuse_address = True
            address_family = socket.AF_INET6 if ":" in self.host else socket.AF_INET

        self._server = ServerImpl((self.host, self.port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="tijaraguard-http-api",
            daemon=True,
        )
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        if self._server is None:
            self.start()
        assert self._thread is not None
        self._thread.join()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=3.0)
            self._thread = None

    def __enter__(self) -> "TijaraGuardHTTPServer":
        return self.start()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
