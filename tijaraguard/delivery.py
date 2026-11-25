"""Gate 4 — MessageShield durable outbox adapter and local-only loopback receiver."""

from __future__ import annotations

import json
import socket
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from .deps import load_dependencies
from .models import DeliveryError, MalformedInputError, validate_safe_id

_DEPS = load_dependencies()
_ms = _DEPS.message_shield

from message_shield.engine import Shield  # type: ignore[import-not-found]
from message_shield.model import (  # type: ignore[import-not-found]
    Conflict as MessageShieldConflict,
    Missing as MessageShieldMissing,
    Outcome as MessageShieldOutcome,
    canonical as ms_canonical,
    endpoint as ms_endpoint,
    fingerprint as ms_fingerprint,
    identifier as ms_identifier,
)
from message_shield.transport import delivery_key as ms_delivery_key  # type: ignore[import-not-found]


def validate_loopback_endpoint(url: str) -> str:
    """Validates endpoint through MessageShield rules and restricts MVP to literal loopback."""
    try:
        normalized = ms_endpoint(url)
    except ValueError as exc:
        raise DeliveryError(f"Invalid delivery endpoint: {exc}") from exc
    parsed = urlsplit(normalized)
    if parsed.hostname not in ("127.0.0.1", "::1"):
        raise DeliveryError(
            "TijaraGuard MVP restricts Gate 4 delivery to literal loopback endpoints (127.0.0.1 or ::1)."
        )
    return normalized


def build_shield_identity(
    draft_id: str,
    *,
    tenant: str = "tijaraguard",
    source: str = "approved_draft",
) -> Tuple[str, str, str]:
    """Builds MessageShield-compatible (tenant, source, message_id) identity tuple."""
    ms_identifier(tenant)
    ms_identifier(source)
    validate_safe_id(draft_id, "draft_id")
    ms_identifier(draft_id)
    return tenant, source, draft_id


def compute_delivery_key(
    draft_id: str,
    *,
    tenant: str = "tijaraguard",
    source: str = "approved_draft",
) -> str:
    """Computes the exact deterministic SHA-256 idempotency key used by MessageShield."""
    t, s, m = build_shield_identity(draft_id, tenant=tenant, source=source)
    return ms_delivery_key({"tenant": t, "source": s, "message_id": m})


class MessageShieldDeliveryAdapter:
    """Wraps MessageShield Shield outbox for bounded send and read-only receipt recovery."""

    def __init__(
        self,
        *,
        outbox_db_path: str | Path,
        endpoint_url: str,
        tenant: str = "tijaraguard",
        source: str = "approved_draft",
        timeout: float = 2.0,
    ) -> None:
        self.outbox_db_path = Path(outbox_db_path).resolve()
        self.outbox_db_path.parent.mkdir(parents=True, exist_ok=True)
        self.endpoint_url = validate_loopback_endpoint(endpoint_url)
        ms_identifier(tenant)
        ms_identifier(source)
        self.tenant = tenant
        self.source = source
        self.timeout = float(timeout)
        self.shield = Shield(
            self.outbox_db_path,
            self.endpoint_url,
            create=not self.outbox_db_path.exists(),
            timeout=self.timeout,
        )

    def admit_and_send(
        self,
        draft_id: str,
        text: str,
        *,
        ttl_seconds: int = 3600,
        max_attempts: int = 3,
        backoff_seconds: float = 0.05,
    ) -> Dict[str, Any]:
        """Admits an approved payload to MessageShield and executes one send attempt."""
        if not isinstance(text, str) or not text.strip():
            raise MalformedInputError("Delivery text must be non-empty.")
        if len(text.encode("utf-8")) > 8192:
            raise DeliveryError("Delivery text exceeds MessageShield 8192-byte limit.")

        tenant, source, msg_id = build_shield_identity(
            draft_id, tenant=self.tenant, source=self.source
        )
        expires_at = int(time.time()) + int(ttl_seconds)
        request = {
            "source": source,
            "message_id": msg_id,
            "text": text,
            "expires_at": expires_at,
            "max_attempts": max_attempts,
            "backoff_seconds": backoff_seconds,
        }
        try:
            self.shield.admit(tenant, request)
            return self.shield.send(tenant, source, msg_id)
        except (ValueError, MessageShieldConflict) as exc:
            raise DeliveryError(f"MessageShield rejected delivery admission/send: {exc}") from exc

    def recover(self, draft_id: str) -> Dict[str, Any]:
        """Performs read-only GET receipt reconciliation without replaying POST."""
        tenant, source, msg_id = build_shield_identity(
            draft_id, tenant=self.tenant, source=self.source
        )
        try:
            return self.shield.recover(tenant, source, msg_id)
        except (ValueError, MessageShieldMissing, MessageShieldConflict) as exc:
            raise DeliveryError(f"MessageShield recovery failed: {exc}") from exc

    def drain(self, draft_id: str) -> Dict[str, Any]:
        """Executes bounded MessageShield pre-request connection retries."""
        tenant, source, msg_id = build_shield_identity(
            draft_id, tenant=self.tenant, source=self.source
        )
        try:
            return self.shield.drain(tenant, source, msg_id)
        except (ValueError, MessageShieldMissing, MessageShieldConflict) as exc:
            raise DeliveryError(f"MessageShield drain failed: {exc}") from exc

    def confirm_delivered(self, draft_id: str, receipt_id: str) -> Dict[str, Any]:
        """Records DELIVERED confirmation against the verified gateway receipt_id."""
        tenant, source, msg_id = build_shield_identity(
            draft_id, tenant=self.tenant, source=self.source
        )
        try:
            return self.shield.receipt(tenant, source, msg_id, receipt_id, "DELIVERED")
        except (ValueError, MessageShieldMissing, MessageShieldConflict) as exc:
            raise DeliveryError(f"MessageShield receipt confirmation failed: {exc}") from exc

    def status(self, draft_id: str) -> Dict[str, Any]:
        """Reads current MessageShield outbox record without network calls."""
        tenant, source, msg_id = build_shield_identity(
            draft_id, tenant=self.tenant, source=self.source
        )
        try:
            return self.shield.get(tenant, source, msg_id)
        except (ValueError, MessageShieldMissing) as exc:
            raise DeliveryError(f"MessageShield lookup failed: {exc}") from exc


def _no_duplicate_json_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    obj: Dict[str, Any] = {}
    for key, val in pairs:
        if key in obj:
            raise ValueError("Duplicate JSON key")
        obj[key] = val
    return obj


def _parse_json_no_duplicate_keys(raw_bytes: bytes) -> Any:
    return json.loads(
        raw_bytes.decode("utf-8"),
        object_pairs_hook=_no_duplicate_json_keys,
    )


class LocalLoopbackReceiver:
    """Durable 127.0.0.1 loopback gateway inbox implementing MessageShield's receipt contract.

    Maintains SQLite WAL storage with PRIMARY KEY(key) deduplication and optional
    drop_ack / post_delay_before_ack fault injection for lost-ACK and crash tests.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        drop_ack: bool = False,
        drop_ack_keys: Optional[Set[str]] = None,
        post_delay_before_ack: float = 0.0,
    ) -> None:
        if host not in ("127.0.0.1", "::1"):
            raise DeliveryError("LocalLoopbackReceiver only binds literal loopback addresses.")
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.host = host
        self.port = int(port)
        self.drop_ack = bool(drop_ack)
        self.drop_ack_keys: Set[str] = set(drop_ack_keys or ())
        self.post_delay_before_ack = float(post_delay_before_ack)
        self._lock = threading.Lock()
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS inbox (
                    key TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    receipt_id TEXT NOT NULL UNIQUE,
                    first_received_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS delivery_attempts (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT NOT NULL,
                    duplicate INTEGER NOT NULL CHECK(duplicate IN (0, 1)),
                    at REAL NOT NULL
                );
                """
            )
        finally:
            conn.close()

    @property
    def endpoint_url(self) -> str:
        """Returns the bound loopback HTTP endpoint URL."""
        if self._server is None:
            raise DeliveryError("LocalLoopbackReceiver is not started.")
        host_fmt = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host_fmt}:{self._server.server_port}/inbox"

    def start(self) -> "LocalLoopbackReceiver":
        """Starts the loopback HTTP server on a background daemon thread."""
        if self._server is not None:
            return self
        receiver_ref = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(3.0)

            def log_message(self, format: str, *args: Any) -> None:
                # Never write HTTP logs that might echo payload metadata.
                return

            def _send_json(self, status_code: int, obj: Dict[str, Any]) -> None:
                self.close_connection = True
                raw = ms_canonical(obj).encode("utf-8")
                try:
                    self.send_response(status_code)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return

            def do_POST(self) -> None:
                if self.path != "/inbox":
                    self._send_json(404, {"error": "Not found"})
                    return

                conn = None
                try:
                    if self.headers.get_all("Transfer-Encoding"):
                        raise ValueError("Transfer-Encoding is not supported")
                    cl_headers = self.headers.get_all("Content-Length") or []
                    if len(cl_headers) != 1:
                        raise ValueError("Single Content-Length header required")
                    raw_len = cl_headers[0].strip()
                    if not raw_len or not raw_len.isascii() or not raw_len.isdigit():
                        raise ValueError("Missing or invalid Content-Length")
                    length = int(raw_len)
                    if length <= 0 or length > 16384:
                        raise ValueError("Body length out of bounds")
                    if self.headers.get_content_type() != "application/json":
                        raise ValueError("Content-Type must be application/json")
                    raw_body = self.rfile.read(length)
                    if len(raw_body) != length:
                        raise ValueError("Incomplete request body")
                    data = _parse_json_no_duplicate_keys(raw_body)
                    if not isinstance(data, dict) or set(data) != {"key", "payload", "payload_sha256"}:
                        raise ValueError("Invalid gateway envelope")
                    payload = data["payload"]
                    if not isinstance(payload, dict) or set(payload) != {
                        "tenant",
                        "source",
                        "message_id",
                        "text",
                    }:
                        raise ValueError("Invalid gateway payload")
                    for field in ("tenant", "source", "message_id"):
                        ms_identifier(payload[field])
                    if (
                        not isinstance(payload["text"], str)
                        or not payload["text"].strip()
                        or len(payload["text"].encode("utf-8")) > 8192
                        or data["payload_sha256"] != ms_fingerprint(payload)
                        or data["key"]
                        != ms_fingerprint([payload[k] for k in ("tenant", "source", "message_id")])
                    ):
                        raise ValueError("Gateway identity mismatch")

                    idem_headers = self.headers.get_all("Idempotency-Key") or []
                    if len(idem_headers) != 1 or idem_headers[0] != data["key"]:
                        raise ValueError("Missing or mismatched Idempotency-Key")

                    canon_payload = ms_canonical(payload)
                    payload_hash = ms_fingerprint(payload)

                    conn = receiver_ref._connect()
                    conn.execute("BEGIN IMMEDIATE")
                    existing = conn.execute(
                        "SELECT * FROM inbox WHERE key=?", (data["key"],)
                    ).fetchone()
                    if existing is not None:
                        if existing["payload_json"] != canon_payload:
                            conn.rollback()
                            self._send_json(409, {"error": "Conflicting gateway content"})
                            return
                        duplicate = 1
                        row = existing
                    else:
                        duplicate = 0
                        receipt_id = f"rcpt-{uuid.uuid4().hex[:16]}"
                        conn.execute(
                            "INSERT INTO inbox(key, payload_json, payload_sha256, receipt_id, first_received_at) "
                            "VALUES (?, ?, ?, ?, ?)",
                            (data["key"], canon_payload, payload_hash, receipt_id, time.time()),
                        )
                        row = conn.execute(
                            "SELECT * FROM inbox WHERE key=?", (data["key"],)
                        ).fetchone()

                    conn.execute(
                        "INSERT INTO delivery_attempts(key, duplicate, at) VALUES (?, ?, ?)",
                        (data["key"], duplicate, time.time()),
                    )
                    result = {
                        "key": row["key"],
                        "payload_sha256": row["payload_sha256"],
                        "receipt_id": row["receipt_id"],
                        "state": "ACCEPTED",
                    }
                    conn.commit()
                except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
                    if conn is not None:
                        try:
                            conn.rollback()
                        except sqlite3.Error:
                            pass
                    self._send_json(400, {"error": "Invalid gateway request"})
                    return
                finally:
                    if conn is not None:
                        conn.close()

                with receiver_ref._lock:
                    delay = receiver_ref.post_delay_before_ack
                    should_drop = (
                        receiver_ref.drop_ack or data["key"] in receiver_ref.drop_ack_keys
                    )

                if delay > 0:
                    time.sleep(delay)

                if should_drop:
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    self.close_connection = True
                    return

                self._send_json(200, result)

            def do_GET(self) -> None:
                prefix = "/inbox/receipts/"
                if not self.path.startswith(prefix):
                    self._send_json(404, {"error": "Not found"})
                    return
                key = self.path[len(prefix):]
                conn = receiver_ref._connect()
                try:
                    row = conn.execute("SELECT * FROM inbox WHERE key=?", (key,)).fetchone()
                    if row is None:
                        self._send_json(404, {"error": "Receipt not found"})
                        return
                    if ms_fingerprint(json.loads(row["payload_json"])) != row["payload_sha256"]:
                        self._send_json(500, {"error": "Stored inbox corruption"})
                        return
                    self._send_json(
                        200,
                        {
                            "key": row["key"],
                            "payload_sha256": row["payload_sha256"],
                            "receipt_id": row["receipt_id"],
                            "state": "ACCEPTED",
                        },
                    )
                finally:
                    conn.close()

        class LoopbackHTTPServer(ThreadingHTTPServer):
            allow_reuse_address = True
            address_family = socket.AF_INET6 if self.host == "::1" else socket.AF_INET

        self._server = LoopbackHTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="tijaraguard-loopback-receiver",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        """Stops the loopback HTTP server cleanly."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def __enter__(self) -> "LocalLoopbackReceiver":
        return self.start()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()

    @contextmanager
    def _read_conn(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def inspect_inbox(self) -> List[Dict[str, Any]]:
        """Returns all logically deduplicated rows in the receiver SQLite inbox."""
        with self._read_conn() as conn:
            rows = conn.execute("SELECT * FROM inbox ORDER BY first_received_at ASC").fetchall()
            return [dict(r) for r in rows]

    def count_logical_deliveries(self, key: Optional[str] = None) -> int:
        """Counts unique delivered logical messages (by key or total)."""
        with self._read_conn() as conn:
            if key is None:
                row = conn.execute("SELECT COUNT(*) AS c FROM inbox").fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) AS c FROM inbox WHERE key=?", (key,)).fetchone()
            return int(row["c"])

    def count_post_attempts(self, key: Optional[str] = None) -> int:
        """Counts HTTP POST attempts processed by the receiver."""
        with self._read_conn() as conn:
            if key is None:
                row = conn.execute("SELECT COUNT(*) AS c FROM delivery_attempts").fetchone()
            else:
                row = conn.execute(
                    "SELECT COUNT(*) AS c FROM delivery_attempts WHERE key=?", (key,)
                ).fetchone()
            return int(row["c"])
