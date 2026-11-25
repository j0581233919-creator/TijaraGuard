"""Optional local Ollama inference provider adapter."""

from __future__ import annotations

import time

from ..config import ProviderEndpointConfig
from .base import (
    AIProvider,
    AIRequest,
    AIResponse,
    HealthCheckResult,
    ProviderErrorCode,
    ProviderExecutionError,
    TokenUsage,
)
from .http_client import HardenedJSONHttpClient


class OllamaProvider(AIProvider):
    """Optional adapter for local Ollama /api/chat inference."""

    def __init__(
        self,
        config: ProviderEndpointConfig,
        *,
        allow_loopback: bool = True,
    ) -> None:
        self.config = config
        self.provider_name = config.name
        self.model_name = config.model
        self.base_url = (config.base_url or "http://127.0.0.1:11434").rstrip("/")
        self._client = HardenedJSONHttpClient(
            provider_name=self.provider_name,
            model_name=self.model_name,
            timeout_seconds=config.timeout_seconds,
            max_retries=config.max_retries,
            allow_loopback=allow_loopback,
        )

    def generate(self, request: AIRequest) -> AIResponse:
        url = f"{self.base_url}/api/chat"
        payload = {
            "model": self.model_name,
            "stream": False,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.user_prompt},
            ],
            "options": {
                "temperature": float(request.temperature),
                "num_predict": int(request.max_tokens),
            },
        }
        _status, data, latency_ms, _hdrs = self._client.request_json(
            "POST",
            url,
            headers=self.config.extra_headers,
            body=payload,
        )
        msg = data.get("message") or {}
        content = msg.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ProviderExecutionError(
                provider=self.provider_name,
                model=self.model_name,
                code=ProviderErrorCode.INVALID_RESPONSE,
                message="Ollama response missing message.content.",
            )
        prompt_t = int(data.get("prompt_eval_count") or 0)
        comp_t = int(data.get("eval_count") or 0)
        return AIResponse(
            provider=self.provider_name,
            model=str(data.get("model") or self.model_name),
            content=content.strip(),
            usage=TokenUsage(
                prompt_tokens=prompt_t,
                completion_tokens=comp_t,
                total_tokens=prompt_t + comp_t,
                estimated_cost_usd=0.0,
            ),
            latency_ms=latency_ms,
            finish_reason=data.get("done_reason"),
        )

    def health_check(self) -> HealthCheckResult:
        t0 = time.monotonic()
        try:
            status, _data, latency_ms, _hdrs = self._client.request_json(
                "GET",
                f"{self.base_url}/api/tags",
                headers=self.config.extra_headers,
                retry_on_errors=False,
            )
            return HealthCheckResult(
                provider=self.provider_name,
                model=self.model_name,
                healthy=True,
                latency_ms=latency_ms,
                status_code=status,
                detail="ollama tags endpoint reachable",
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
