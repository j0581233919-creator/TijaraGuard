"""OpenAI-compatible provider adapter (OpenAI, Groq, OpenRouter, Mistral, custom base URLs)."""

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


class OpenAICompatibleProvider(AIProvider):
    """Adapter for OpenAI Chat Completions compatible APIs."""

    def __init__(
        self,
        config: ProviderEndpointConfig,
        *,
        allow_loopback: bool = False,
    ) -> None:
        self.config = config
        self.provider_name = config.name
        self.model_name = config.model
        self.base_url = config.base_url.rstrip("/")
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
                message=f"Missing API key ({self.config.api_key_env or 'api_key'}).",
            )
        hdrs = dict(self.config.extra_headers)
        hdrs["Authorization"] = f"Bearer {self._api_key}"
        return hdrs

    def generate(self, request: AIRequest) -> AIResponse:
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.user_prompt},
            ],
            "temperature": float(request.temperature),
            "max_tokens": int(request.max_tokens),
        }
        _status, data, latency_ms, resp_headers = self._client.request_json(
            "POST",
            url,
            headers=self._headers(),
            body=payload,
        )
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ProviderExecutionError(
                provider=self.provider_name,
                model=self.model_name,
                code=ProviderErrorCode.INVALID_RESPONSE,
                message="Response missing non-empty 'choices' array.",
            )
        first = choices[0] or {}
        message = first.get("message") or {}
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ProviderExecutionError(
                provider=self.provider_name,
                model=self.model_name,
                code=ProviderErrorCode.INVALID_RESPONSE,
                message="Response choice missing non-empty message content.",
            )

        usage_raw = data.get("usage") or {}
        prompt_t = int(usage_raw.get("prompt_tokens") or 0)
        comp_t = int(usage_raw.get("completion_tokens") or 0)
        total_t = int(usage_raw.get("total_tokens") or (prompt_t + comp_t))
        cost = compute_cost_usd(
            prompt_t,
            comp_t,
            self.config.input_cost_per_1k,
            self.config.output_cost_per_1k,
        )
        return AIResponse(
            provider=self.provider_name,
            model=str(data.get("model") or self.model_name),
            content=content.strip(),
            usage=TokenUsage(
                prompt_tokens=prompt_t,
                completion_tokens=comp_t,
                total_tokens=total_t,
                estimated_cost_usd=cost,
            ),
            latency_ms=latency_ms,
            finish_reason=first.get("finish_reason"),
            raw_request_id=data.get("id") or resp_headers.get("x-request-id"),
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
