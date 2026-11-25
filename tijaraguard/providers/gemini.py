"""Google Gemini API provider adapter (API key sent strictly via x-goog-api-key header)."""

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


class GeminiProvider(AIProvider):
    """Adapter for Google Gemini generateContent REST API."""

    def __init__(
        self,
        config: ProviderEndpointConfig,
        *,
        allow_loopback: bool = False,
    ) -> None:
        self.config = config
        self.provider_name = config.name
        self.model_name = config.model
        self.base_url = (
            config.base_url or "https://generativelanguage.googleapis.com/v1beta"
        ).rstrip("/")
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
                message=f"Missing API key ({self.config.api_key_env or 'GEMINI_API_KEY'}).",
            )
        hdrs = {"x-goog-api-key": self._api_key}
        hdrs.update(self.config.extra_headers)
        return hdrs

    def generate(self, request: AIRequest) -> AIResponse:
        model_ref = self.model_name
        if model_ref.startswith("models/"):
            model_ref = model_ref[len("models/"):]
        url = f"{self.base_url}/models/{model_ref}:generateContent"
        payload = {
            "systemInstruction": {"parts": [{"text": request.system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": request.user_prompt}]}],
            "generationConfig": {
                "temperature": float(request.temperature),
                "maxOutputTokens": int(request.max_tokens),
            },
        }
        _status, data, latency_ms, _hdrs = self._client.request_json(
            "POST",
            url,
            headers=self._headers(),
            body=payload,
        )
        candidates = data.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise ProviderExecutionError(
                provider=self.provider_name,
                model=self.model_name,
                code=ProviderErrorCode.INVALID_RESPONSE,
                message="Gemini response missing 'candidates'.",
            )
        first = candidates[0] or {}
        content_obj = first.get("content") or {}
        parts = content_obj.get("parts") or []
        text = "\n".join(str(p.get("text", "")) for p in parts if isinstance(p, dict)).strip()
        if not text:
            raise ProviderExecutionError(
                provider=self.provider_name,
                model=self.model_name,
                code=ProviderErrorCode.INVALID_RESPONSE,
                message="Gemini candidate missing text content.",
            )

        usage_raw = data.get("usageMetadata") or {}
        prompt_t = int(usage_raw.get("promptTokenCount") or 0)
        comp_t = int(usage_raw.get("candidatesTokenCount") or 0)
        total_t = int(usage_raw.get("totalTokenCount") or (prompt_t + comp_t))
        cost = compute_cost_usd(
            prompt_t,
            comp_t,
            self.config.input_cost_per_1k,
            self.config.output_cost_per_1k,
        )
        return AIResponse(
            provider=self.provider_name,
            model=self.model_name,
            content=text,
            usage=TokenUsage(
                prompt_tokens=prompt_t,
                completion_tokens=comp_t,
                total_tokens=total_t,
                estimated_cost_usd=cost,
            ),
            latency_ms=latency_ms,
            finish_reason=first.get("finishReason"),
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
