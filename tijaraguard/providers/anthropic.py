"""Anthropic Messages API provider adapter."""

from __future__ import annotations

import time
from typing import Dict

from ..config import ProviderEndpointConfig
from .base import (
    AIProvider,
    AIRequest,
    AIResponse,
    HealthCheckResult,
    ProviderErrorCode,
    ProviderExecutionError,
    TokenUsage,
    compute_cost_usd,
)
from .http_client import HardenedJSONHttpClient


class AnthropicProvider(AIProvider):
    """Adapter for the official Anthropic Messages API (/v1/messages)."""

    ANTHROPIC_VERSION = "2023-06-01"

    def __init__(
        self,
        config: ProviderEndpointConfig,
        *,
        allow_loopback: bool = False,
    ) -> None:
        self.config = config
        self.provider_name = config.name
        self.model_name = config.model
        self.base_url = (config.base_url or "https://api.anthropic.com/v1").rstrip("/")
        self._api_key = (config.api_key or "").strip()
        self._client = HardenedJSONHttpClient(
            provider_name=self.provider_name,
            model_name=self.model_name,
            timeout_seconds=config.timeout_seconds,
            max_retries=config.max_retries,
            allow_loopback=allow_loopback,
            secrets_to_mask=(self._api_key,) if self._api_key else (),
        )

    def _headers(self) -> Dict[str, str]:
        if not self._api_key:
            raise ProviderExecutionError(
                provider=self.provider_name,
                model=self.model_name,
                code=ProviderErrorCode.CONFIG_ERROR,
                message=f"Missing API key ({self.config.api_key_env or 'ANTHROPIC_API_KEY'}).",
            )
        hdrs = {
            "x-api-key": self._api_key,
            "anthropic-version": self.ANTHROPIC_VERSION,
        }
        hdrs.update(self.config.extra_headers)
        return hdrs

    def generate(self, request: AIRequest) -> AIResponse:
        url = f"{self.base_url}/messages"
        payload = {
            "model": self.model_name,
            "system": request.system_prompt,
            "messages": [{"role": "user", "content": request.user_prompt}],
            "temperature": float(request.temperature),
            "max_tokens": int(request.max_tokens),
        }
        _status, data, latency_ms, resp_headers = self._client.request_json(
            "POST",
            url,
            headers=self._headers(),
            body=payload,
        )
        blocks = data.get("content")
        if not isinstance(blocks, list) or not blocks:
            raise ProviderExecutionError(
                provider=self.provider_name,
                model=self.model_name,
                code=ProviderErrorCode.INVALID_RESPONSE,
                message="Anthropic response missing 'content' blocks.",
            )
        text_parts = [
            str(b.get("text", ""))
            for b in blocks
            if isinstance(b, dict) and b.get("type") == "text"
        ]
        content = "\n".join(p for p in text_parts if p).strip()
        if not content:
            raise ProviderExecutionError(
                provider=self.provider_name,
                model=self.model_name,
                code=ProviderErrorCode.INVALID_RESPONSE,
                message="Anthropic response contained no text blocks.",
            )

        usage_raw = data.get("usage") or {}
        in_t = int(usage_raw.get("input_tokens") or 0)
        out_t = int(usage_raw.get("output_tokens") or 0)
        cost = compute_cost_usd(
            in_t,
            out_t,
            self.config.input_cost_per_1k,
            self.config.output_cost_per_1k,
        )
        return AIResponse(
            provider=self.provider_name,
            model=str(data.get("model") or self.model_name),
            content=content,
            usage=TokenUsage(
                prompt_tokens=in_t,
                completion_tokens=out_t,
                total_tokens=in_t + out_t,
                estimated_cost_usd=cost,
            ),
            latency_ms=latency_ms,
            finish_reason=data.get("stop_reason"),
            raw_request_id=data.get("id") or resp_headers.get("request-id"),
        )

    def health_check(self) -> HealthCheckResult:
        t0 = time.monotonic()
        try:
            status, _data, latency_ms, _hdrs = self._client.request_json(
                "GET",
                f"{self.base_url}/models",
                headers=self._headers(),
                retry_on_errors=False,
            )
            return HealthCheckResult(
                provider=self.provider_name,
                model=self.model_name,
                healthy=True,
                latency_ms=latency_ms,
                status_code=status,
                detail="models endpoint reachable",
            )
        except ProviderExecutionError as exc:
            return HealthCheckResult(
                provider=self.provider_name,
                model=self.model_name,
                healthy=False,
                latency_ms=(time.monotonic() - t0) * 1000.0,
                status_code=exc.status_code,
                error_code=exc.code.value,
                detail=str(exc),
            )
