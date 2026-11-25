"""Wire identity, bounded validation and the transport contract."""

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Literal, Protocol
from urllib.parse import urlsplit


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False)


def fingerprint(value: object) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value):
        raise ValueError("IDs require 1–80 ASCII letters, digits, _ or -")
    return value


def endpoint(value: str) -> str:
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ValueError("Invalid endpoint")
    parsed = urlsplit(value)
    if (parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("Endpoint must be HTTPS without credentials, query or fragment")
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "::1"):
        raise ValueError("Plain HTTP is allowed only for literal loopback IPs")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("Invalid endpoint port")
    return value.rstrip("/")


def event(value: dict) -> dict:
    required = {"source", "message_id", "text", "expires_at"}
    optional = {"max_attempts", "backoff_seconds"}
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise ValueError("Invalid message fields; tenant and endpoint come from operator configuration")
    result = {"max_attempts": 3, "backoff_seconds": 0.05, **value}
    identifier(result["source"])
    identifier(result["message_id"])
    text = result["text"]
    if not isinstance(text, str) or not text.strip() or len(text.encode()) > 8192:
        raise ValueError("Text must contain 1–8192 UTF-8 bytes")
    if type(result["expires_at"]) is not int or result["expires_at"] <= 0:
        raise ValueError("expires_at must be a positive integer Unix timestamp")
    if type(result["max_attempts"]) is not int or not 1 <= result["max_attempts"] <= 3:
        raise ValueError("max_attempts must be 1–3")
    delay = result["backoff_seconds"]
    if type(delay) not in (int, float) or not 0.01 <= delay <= 2:
        raise ValueError("backoff_seconds must be 0.01–2")
    result["backoff_seconds"] = float(delay)
    return result


@dataclass(frozen=True)
class Outcome:
    kind: Literal["ACCEPTED", "RETRYABLE", "UNKNOWN"]
    receipt_id: str | None = None
    reason: str | None = None


class Transport(Protocol):
    """RETRYABLE promises that no application request was sent. Adapters are trusted."""

    def submit(self, message: dict) -> Outcome: ...

    def lookup(self, message: dict) -> Outcome: ...


class Conflict(ValueError):
    pass


class Missing(LookupError):
    pass
