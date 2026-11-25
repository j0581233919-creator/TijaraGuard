"""Hardened stdlib HTTP/HTTPS JSON client with SSRF validation, bounded retries, and no redirects."""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import time
from typing import Any, Dict, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from ..security import SSRFError, scrub_secrets_from_text, validate_outbound_url
from .base import ProviderErrorCode, ProviderExecutionError

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MiB


class HardenedJSONHttpClient:
    """Executes JSON HTTP requests with strict SSRF checks, timeouts, and bounded retries."""

    def __init__(
        self,
        *,
        provider_name: str,
        model_name: str,
        timeout_seconds: float = 20.0,
        max_retries: int = 2,
        allow_loopback: bool = False,
        secrets_to_mask: Tuple[str, ...] = (),
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self.provider_name = provider_name
        self.model_name = model_name
        self.timeout_seconds = max(0.2, float(timeout_seconds))
        self.max_retries = max(0, min(5, int(max_retries)))
        self.allow_loopback = bool(allow_loopback)
        self._secrets = tuple(s for s in secrets_to_mask if s)
        self._ssl_context = ssl_context

    def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Mapping[str, str]] = None,
        body: Optional[Dict[str, Any]] = None,
        retry_on_errors: bool = True,
    ) -> Tuple[int, Dict[str, Any], float, Dict[str, str]]:
        try:
            clean_url = validate_outbound_url(
                url,
                allow_loopback=self.allow_loopback,
                allow_http_loopback=self.allow_loopback,
            )
        except SSRFError as exc:
            raise ProviderExecutionError(
                provider=self.provider_name,
                model=self.model_name,
                code=ProviderErrorCode.CONFIG_ERROR,
                message=str(exc),
                retryable=False,
            ) from exc

        parsed = urlsplit(clean_url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        req_headers = {
            "Accept": "application/json",
            "Connection": "close",
            "User-Agent": "TijaraGuard/0.2",
        }
        if headers:
            req_headers.update(headers)

        payload_bytes: Optional[bytes] = None
        if body is not None:
            payload_bytes = json.dumps(body, ensure_ascii=False).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
            req_headers["Content-Length"] = str(len(payload_bytes))

        attempts = (self.max_retries + 1) if retry_on_errors else 1
        last_exc: Optional[ProviderExecutionError] = None
        t0 = time.monotonic()

        for attempt in range(attempts):
            try:
                status, resp_headers, raw = self._single_request(
                    method=method.upper(),
                    scheme=parsed.scheme,
                    host=parsed.hostname or "",
                    port=parsed.port,
                    path=path,
                    headers=req_headers,
                    body_bytes=payload_bytes,
                )
                elapsed_ms = (time.monotonic() - t0) * 1000.0
                if status in (301, 302, 303, 307, 308):
                    raise ProviderExecutionError(
                        provider=self.provider_name,
                        model=self.model_name,
                        code=ProviderErrorCode.CONFIG_ERROR,
                        status_code=status,
                        message="HTTP redirects are disabled for outbound provider requests.",
                        retryable=False,
                    )

                parsed_json: Dict[str, Any] = {}
                if raw:
                    try:
                        decoded = json.loads(raw.decode("utf-8"))
                        if isinstance(decoded, dict):
                            parsed_json = decoded
                        else:
                            parsed_json = {"data": decoded}
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        if 200 <= status < 300:
                            raise ProviderExecutionError(
                                provider=self.provider_name,
                                model=self.model_name,
                                code=ProviderErrorCode.INVALID_RESPONSE,
                                status_code=status,
                                message=f"Provider returned malformed JSON: {exc}",
                                retryable=False,
                            ) from exc
                        parsed_json = {
                            "raw_error": scrub_secrets_from_text(
                                raw.decode("utf-8", errors="replace")[:300],
                                self._secrets,
                            )
                        }

                if 200 <= status < 300:
                    return status, parsed_json, elapsed_ms, resp_headers

                err = self._classify_http_error(status, parsed_json, resp_headers)
                last_exc = err
                if err.retryable and attempt < attempts - 1:
                    delay = self._compute_backoff(attempt, err.retry_after)
                    time.sleep(delay)
                    continue
                raise err

            except ProviderExecutionError as exc:
                last_exc = exc
                if exc.retryable and attempt < attempts - 1:
                    delay = self._compute_backoff(attempt, exc.retry_after)
                    time.sleep(delay)
                    continue
                raise

        if last_exc is not None:
            raise last_exc
        raise ProviderExecutionError(
            provider=self.provider_name,
            model=self.model_name,
            code=ProviderErrorCode.NETWORK_ERROR,
            message="Provider request failed.",
        )

    def _compute_backoff(self, attempt: int, retry_after: Optional[float]) -> float:
        if retry_after is not None and retry_after > 0:
            return min(retry_after, 2.0)
        return min(0.1 * (2 ** attempt), 1.0)

    def _single_request(
        self,
        *,
        method: str,
        scheme: str,
        host: str,
        port: Optional[int],
        path: str,
        headers: Mapping[str, str],
        body_bytes: Optional[bytes],
    ) -> Tuple[int, Dict[str, str], bytes]:
        if scheme == "https":
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                host,
                port=port,
                timeout=self.timeout_seconds,
                context=self._ssl_context,
            )
        else:
            conn = http.client.HTTPConnection(
                host,
                port=port,
                timeout=self.timeout_seconds,
            )

        try:
            conn.request(method, path, body=body_bytes, headers=dict(headers))
            resp = conn.getresponse()
            raw = resp.read(_MAX_RESPONSE_BYTES + 1)
            if len(raw) > _MAX_RESPONSE_BYTES:
                raise ProviderExecutionError(
                    provider=self.provider_name,
                    model=self.model_name,
                    code=ProviderErrorCode.INVALID_RESPONSE,
                    status_code=resp.status,
                    message="Provider response exceeded 2 MiB safety limit.",
                    retryable=False,
                )
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, resp_headers, raw
        except (TimeoutError, socket.timeout) as exc:
            raise ProviderExecutionError(
                provider=self.provider_name,
                model=self.model_name,
                code=ProviderErrorCode.TIMEOUT,
                message=f"Provider request timed out after {self.timeout_seconds}s.",
                retryable=True,
            ) from exc
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            msg = scrub_secrets_from_text(str(exc), self._secrets)
            raise ProviderExecutionError(
                provider=self.provider_name,
                model=self.model_name,
                code=ProviderErrorCode.NETWORK_ERROR,
                message=f"Network failure communicating with provider: {msg}",
                retryable=True,
            ) from exc
        finally:
            conn.close()

    def _classify_http_error(
        self,
        status: int,
        payload: Dict[str, Any],
        resp_headers: Dict[str, str],
    ) -> ProviderExecutionError:
        err_obj = payload.get("error")
        if isinstance(err_obj, dict):
            detail = str(err_obj.get("message") or err_obj.get("type") or "")
        elif isinstance(err_obj, str):
            detail = err_obj
        else:
            detail = str(payload.get("message") or payload.get("raw_error") or f"HTTP {status}")
        detail = scrub_secrets_from_text(detail, self._secrets)[:300]

        if status in (401, 403):
            return ProviderExecutionError(
                provider=self.provider_name,
                model=self.model_name,
                code=ProviderErrorCode.AUTH_ERROR,
                status_code=status,
                message=detail or "Authentication failed.",
                retryable=False,
            )
        if status == 429:
            retry_after: Optional[float] = None
            raw_ra = resp_headers.get("retry-after")
            if raw_ra:
                try:
                    retry_after = float(raw_ra)
                except ValueError:
                    retry_after = None
            return ProviderExecutionError(
                provider=self.provider_name,
                model=self.model_name,
                code=ProviderErrorCode.RATE_LIMITED,
                status_code=status,
                message=detail or "Rate limit exceeded.",
                retryable=True,
                retry_after=retry_after,
            )
        if status == 408:
            return ProviderExecutionError(
                provider=self.provider_name,
                model=self.model_name,
                code=ProviderErrorCode.TIMEOUT,
                status_code=status,
                message=detail or "Request timeout.",
                retryable=True,
            )
        if 400 <= status < 500:
            return ProviderExecutionError(
                provider=self.provider_name,
                model=self.model_name,
                code=ProviderErrorCode.BAD_REQUEST,
                status_code=status,
                message=detail or f"Client error HTTP {status}.",
                retryable=False,
            )
        return ProviderExecutionError(
            provider=self.provider_name,
            model=self.model_name,
            code=ProviderErrorCode.SERVER_ERROR,
            status_code=status,
            message=detail or f"Server error HTTP {status}.",
            retryable=True,
        )
