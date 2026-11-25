"""Core security controls: SSRF validation, HMAC signatures, auth, rate limiting, and scrubbing."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import math
import os
import re
import socket
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, Mapping, Optional, Set, Tuple
from urllib.parse import urlsplit

from .models import TijaraGuardError, is_valid_sha256_hex


class SecurityError(TijaraGuardError):
    """Base exception for security control failures."""


class SSRFError(SecurityError, ValueError):
    """Raised when an outbound URL violates SSRF or transport security rules."""


class AuthError(SecurityError):
    """Raised when API authentication fails or is unconfigured."""


class WebhookSignatureError(SecurityError):
    """Raised when an inbound webhook signature or verification token fails."""


class ReplayError(SecurityError):
    """Raised when a timestamp or event ID violates replay protection."""


class RateLimitError(SecurityError):
    """Raised when a caller exceeds the configured rate limit."""


_SECRET_PATTERNS = [
    re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(r"(/bot)[0-9]{5,}:[A-Za-z0-9_-]{10,}"),
    re.compile(r"\b(sk-[A-Za-z0-9_-]{10,})\b"),
    re.compile(r"\b(AIza[0-9A-Za-z_-]{16,})\b"),
    re.compile(r"(x-(?:api|goog)-key\s*[:=]\s*)\S+", re.IGNORECASE),
]

_FORMULA_PREFIX_CHARS = frozenset({"=", "+", "-", "@", "\t", "\r"})


def _is_forbidden_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_loopback: bool) -> bool:
    if ip_obj.is_loopback:
        return not allow_loopback
    return (
        ip_obj.is_private
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def validate_outbound_url(
    url: str,
    *,
    allow_loopback: bool = False,
    allow_http_loopback: bool = False,
    allowed_hosts: Optional[Set[str]] = None,
) -> str:
    """Validates an outbound URL against SSRF, credentials-in-URL, and unsafe scheme rules."""
    if not isinstance(url, str) or not url.strip():
        raise SSRFError("Outbound URL must be a non-empty string.")
    if len(url) > 2048 or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise SSRFError("Outbound URL contains invalid control characters or exceeds 2048 bytes.")

    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("https", "http"):
        raise SSRFError("Outbound URL scheme must be HTTPS (or HTTP for explicit loopback).")
    if not parsed.hostname:
        raise SSRFError("Outbound URL must include a valid hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise SSRFError("Outbound URL must not embed credentials.")
    if parsed.fragment:
        raise SSRFError("Outbound URL must not contain a fragment.")
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise SSRFError("Outbound URL port is out of range.")

    host = parsed.hostname.lower()
    is_literal_loopback = host in ("127.0.0.1", "::1")
    if scheme == "http":
        if not (allow_http_loopback and is_literal_loopback):
            raise SSRFError("Plain HTTP is prohibited except for explicit literal loopback testing.")

    explicitly_allowed = allowed_hosts is not None and host in {h.lower() for h in allowed_hosts}
    if explicitly_allowed:
        return url.rstrip("/")

    # Check literal IP first
    try:
        literal_ip = ipaddress.ip_address(host)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        if _is_forbidden_ip(literal_ip, allow_loopback=(allow_loopback and is_literal_loopback)):
            raise SSRFError(f"Outbound IP address '{host}' is blocked by SSRF policy.")
        return url.rstrip("/")

    # Reject localhost hostname unless explicitly allowed via literal loopback
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        raise SSRFError(f"Outbound hostname '{host}' is blocked by SSRF policy.")

    # Resolve DNS if available and verify all resolved addresses are safe
    try:
        addr_infos = socket.getaddrinfo(host, parsed.port or (443 if scheme == "https" else 80), type=socket.SOCK_STREAM)
    except OSError:
        # Offline environments without DNS cannot resolve external hostnames; hostname rules above still hold.
        return url.rstrip("/")

    for info in addr_infos:
        sockaddr = info[4]
        ip_str = sockaddr[0].split("%")[0]
        try:
            resolved_ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_forbidden_ip(resolved_ip, allow_loopback=allow_loopback):
            raise SSRFError(f"Resolved IP '{ip_str}' for '{host}' is blocked by SSRF policy.")

    return url.rstrip("/")


def compute_hmac_sha256_hex(secret: str | bytes, payload: bytes) -> str:
    """Computes lowercase hex HMAC-SHA256 signature."""
    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    return hmac.new(secret_bytes, payload, hashlib.sha256).hexdigest()


def verify_hmac_sha256(
    secret: str | bytes,
    payload: bytes,
    signature: Optional[str],
    *,
    prefix: str = "sha256=",
) -> bool:
    """Constant-time verification of hex HMAC-SHA256 signature (optional prefix)."""
    if not secret or not isinstance(signature, str):
        return False
    sig = signature.strip()
    if prefix and sig.lower().startswith(prefix.lower()):
        sig = sig[len(prefix):]
    elif prefix and "=" in sig:
        return False
    if not is_valid_sha256_hex(sig):
        return False
    expected = compute_hmac_sha256_hex(secret, payload)
    return hmac.compare_digest(expected.lower(), sig.lower())


def verify_timestamp_window(
    timestamp_seconds: float,
    *,
    max_skew_seconds: int = 300,
    now: Optional[float] = None,
) -> bool:
    """Returns True if timestamp is finite and within +/- max_skew_seconds of current time."""
    if not isinstance(timestamp_seconds, (int, float)) or isinstance(timestamp_seconds, bool):
        return False
    if not math.isfinite(float(timestamp_seconds)):
        return False
    current = float(time.time() if now is None else now)
    return abs(current - float(timestamp_seconds)) <= max(1, int(max_skew_seconds))


def _get_header_ci(headers: Mapping[str, str], name: str) -> Optional[str]:
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return None


def verify_bearer_or_api_key(headers: Mapping[str, str], expected_key: Optional[str]) -> bool:
    """Verifies Authorization: Bearer or X-API-Key header in constant time (fail closed)."""
    if not expected_key or not isinstance(expected_key, str) or not expected_key.strip():
        return False
    expected_bytes = expected_key.strip().encode("utf-8")

    auth_hdr = _get_header_ci(headers, "Authorization")
    if isinstance(auth_hdr, str) and auth_hdr.strip().lower().startswith("bearer "):
        token = auth_hdr.strip()[7:].strip()
        if token and hmac.compare_digest(token.encode("utf-8"), expected_bytes):
            return True

    api_key_hdr = _get_header_ci(headers, "X-API-Key")
    if isinstance(api_key_hdr, str) and api_key_hdr.strip():
        if hmac.compare_digest(api_key_hdr.strip().encode("utf-8"), expected_bytes):
            return True

    return False


class SlidingWindowRateLimiter:
    """Thread-safe bounded sliding-window rate limiter."""

    def __init__(self, max_requests: int = 120, window_seconds: float = 60.0, max_keys: int = 4096) -> None:
        self.max_requests = max(1, int(max_requests))
        self.window_seconds = max(0.1, float(window_seconds))
        self.max_keys = max(16, int(max_keys))
        self._lock = threading.Lock()
        self._buckets: Dict[str, Deque[float]] = {}

    def check(self, key: str, *, now: Optional[float] = None) -> Tuple[bool, float]:
        """Checks and records one hit for `key`. Returns (allowed, retry_after_seconds)."""
        current = float(time.monotonic() if now is None else now)
        cutoff = current - self.window_seconds
        with self._lock:
            if key not in self._buckets and len(self._buckets) >= self.max_keys:
                # Evict oldest idle bucket to bound memory
                oldest_key = min(
                    self._buckets.keys(),
                    key=lambda k: self._buckets[k][-1] if self._buckets[k] else -1.0,
                )
                del self._buckets[oldest_key]
            q = self._buckets.setdefault(key, deque())
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= self.max_requests:
                retry_after = max(0.05, q[0] + self.window_seconds - current)
                return False, retry_after
            q.append(current)
            return True, 0.0


def sanitize_csv_cell(value: Any) -> str:
    """Prevents CSV/spreadsheet formula injection by neutralizing leading formula characters."""
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    stripped = text.lstrip(" ")
    if text[0] in _FORMULA_PREFIX_CHARS or (stripped and stripped[0] in _FORMULA_PREFIX_CHARS):
        return "'" + text
    return text


def scrub_secrets_from_text(text: str, secrets_to_mask: Iterable[str] = ()) -> str:
    """Redacts API keys, Bearer tokens, Telegram bot tokens, and explicit secrets from text."""
    if not isinstance(text, str) or not text:
        return text
    masked = text
    for secret_val in secrets_to_mask:
        if isinstance(secret_val, str) and len(secret_val) >= 4:
            masked = masked.replace(secret_val, "[REDACTED_SECRET]")
    masked = _SECRET_PATTERNS[0].sub(r"\1[REDACTED_TOKEN]", masked)
    masked = _SECRET_PATTERNS[1].sub(r"\1[REDACTED_BOT_TOKEN]", masked)
    masked = _SECRET_PATTERNS[2].sub("[REDACTED_API_KEY]", masked)
    masked = _SECRET_PATTERNS[3].sub("[REDACTED_API_KEY]", masked)
    masked = _SECRET_PATTERNS[4].sub(r"\1[REDACTED_API_KEY]", masked)
    return masked


class SecretAndPIIRedactingLogFilter(logging.Filter):
    """Logging filter that strips secrets and optional BayanGate PII from log messages."""

    def __init__(self, *, privacy_gate: Any = None, secrets_provider: Any = None) -> None:
        super().__init__()
        self._privacy_gate = privacy_gate
        self._secrets_provider = secrets_provider

    def set_privacy_gate(self, privacy_gate: Any) -> None:
        self._privacy_gate = privacy_gate

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:
            rendered = str(record.msg)
        secrets_list = self._secrets_provider() if callable(self._secrets_provider) else ()
        cleaned = scrub_secrets_from_text(rendered, secrets_list)
        if self._privacy_gate is not None:
            try:
                cleaned = self._privacy_gate.redact_text_full(cleaned)
            except Exception:
                pass
        record.msg = cleaned
        record.args = ()
        return True


def harden_state_permissions(path: Path, *, is_dir: bool = False) -> Dict[str, Any]:
    """Applies strict 0700/0600 permissions when supported by the underlying filesystem."""
    target_mode = 0o700 if is_dir else 0o600
    resolved = Path(path).resolve()
    try:
        os.chmod(resolved, target_mode)
        actual_mode = resolved.stat().st_mode & 0o777
        posix_enforced = actual_mode == target_mode
        warning = (
            None
            if posix_enforced
            else (
                f"Filesystem ignored chmod {oct(target_mode)} on '{resolved}' "
                f"(actual={oct(actual_mode)}); store production state on a POSIX filesystem."
            )
        )
        return {"applied": True, "posix_enforced": posix_enforced, "warning": warning}
    except OSError as exc:
        return {"applied": False, "posix_enforced": False, "warning": f"chmod failed: {exc}"}
