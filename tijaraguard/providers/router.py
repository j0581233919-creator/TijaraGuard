"""Model router with pre-send Gate 1 PII guard, complexity routing, and explicit fallback."""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Optional

from ..config import ProviderEndpointConfig, RoutingConfig, TijaraGuardConfig
from ..models import MalformedInputError, PrivacyViolationError
from ..privacy import PrivacyGate
from .anthropic import AnthropicProvider
from .base import (
    AIProvider,
    AIRequest,
    AIResponse,
    HealthCheckResult,
    ProviderErrorCode,
    ProviderExecutionError,
    TaskComplexity,
)
from .gemini import GeminiProvider
from .ollama import OllamaProvider
from .openai_compat import OpenAICompatibleProvider

logger = logging.getLogger("tijaraguard.providers")


def build_provider_from_config(
    cfg: ProviderEndpointConfig,
    *,
    allow_loopback: bool = False,
) -> AIProvider:
    kind = cfg.kind.strip().lower()
    if kind == "openai_compat":
        return OpenAICompatibleProvider(cfg, allow_loopback=allow_loopback)
    if kind == "anthropic":
        return AnthropicProvider(cfg, allow_loopback=allow_loopback)
    if kind == "gemini":
        return GeminiProvider(cfg, allow_loopback=allow_loopback)
    if kind == "ollama":
        return OllamaProvider(cfg, allow_loopback=True)
    raise MalformedInputError(f"Unsupported provider kind '{cfg.kind}'.")


class ModelRouter:
    """Routes AI requests across configured providers with pre-send PII blocking and explicit fallback."""

    def __init__(
        self,
        *,
        providers: Dict[str, AIProvider],
        routing: RoutingConfig,
        privacy_gate: Optional[PrivacyGate] = None,
        on_attempt: Optional[Callable[[Dict[str, Any]], None]] = None,
        require_privacy_gate: bool = False,
    ) -> None:
        self.providers = dict(providers)
        self.routing = routing
        self.privacy_gate = privacy_gate
        self.on_attempt = on_attempt
        self.require_privacy_gate = bool(require_privacy_gate)

    @classmethod
    def from_config(
        cls,
        cfg: TijaraGuardConfig,
        *,
        privacy_gate: Optional[PrivacyGate] = None,
        on_attempt: Optional[Callable[[Dict[str, Any]], None]] = None,
        require_privacy_gate: bool = False,
    ) -> "ModelRouter":
        instances: Dict[str, AIProvider] = {}
        for name, p_cfg in cfg.providers.items():
            if not p_cfg.enabled:
                continue
            instances[name] = build_provider_from_config(
                p_cfg,
                allow_loopback=cfg.allow_loopback_providers,
            )
        return cls(
            providers=instances,
            routing=cfg.routing,
            privacy_gate=privacy_gate,
            on_attempt=on_attempt,
            require_privacy_gate=require_privacy_gate,
        )

    def _select_candidate_names(self, complexity: TaskComplexity) -> List[str]:
        tier_key = complexity.value
        primary = self.routing.tier_routes.get(tier_key) or self.routing.default_provider
        if not primary:
            if not self.providers:
                raise ProviderExecutionError(
                    provider="router",
                    model="none",
                    code=ProviderErrorCode.CONFIG_ERROR,
                    message="No AI providers are configured.",
                )
            primary = next(iter(self.providers.keys()))

        candidates = [primary]
        if self.routing.allow_fallback:
            for fb in self.routing.fallback_chain:
                if fb not in candidates:
                    candidates.append(fb)
        return candidates

    def _enforce_pre_send_pii_guard(self, request: AIRequest) -> None:
        if self.privacy_gate is None:
            if self.require_privacy_gate:
                raise PrivacyViolationError(
                    "ModelRouter requires a configured PrivacyGate before sending outbound prompts."
                )
            return
        leaked_sys = self.privacy_gate.verify_text_clean(request.system_prompt)
        leaked_usr = self.privacy_gate.verify_text_clean(request.user_prompt)
        leaked = sorted(set(leaked_sys + leaked_usr))
        if leaked:
            raise PrivacyViolationError(
                f"Blocked outbound AI request containing unredacted PII categories: {leaked}"
            )

    def _emit_attempt(
        self,
        record: Dict[str, Any],
        per_call_cb: Optional[Callable[[Dict[str, Any]], None]],
    ) -> None:
        for cb in (per_call_cb, self.on_attempt):
            if cb is not None:
                try:
                    cb(record)
                except Exception:
                    pass

    def generate(
        self,
        request: AIRequest,
        *,
        on_attempt: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> AIResponse:
        """Executes AI generation with Gate 1 PII check and observable fallback policy."""
        self._enforce_pre_send_pii_guard(request)

        candidates = self._select_candidate_names(request.task_complexity)
        fallback_events: List[Dict[str, Any]] = []
        last_error: Optional[ProviderExecutionError] = None
        primary_name = candidates[0]

        for idx, name in enumerate(candidates):
            provider = self.providers.get(name)
            if provider is None:
                err = ProviderExecutionError(
                    provider=name,
                    model="unknown",
                    code=ProviderErrorCode.CONFIG_ERROR,
                    message=f"Configured route '{name}' is unavailable.",
                    retryable=False,
                )
                last_error = err
                self._emit_attempt(
                    {
                        "provider": name,
                        "model": "unknown",
                        "task_tier": request.task_complexity.value,
                        "status": "ERROR",
                        "error_category": err.code.value,
                        "latency_ms": 0.0,
                        "prompt_tokens": 0,
                        "completion_tokens": 0,
                        "total_tokens": 0,
                        "estimated_cost_usd": 0.0,
                        "fallback_from": primary_name if idx > 0 else None,
                    },
                    on_attempt,
                )
                if idx < len(candidates) - 1 and self.routing.allow_fallback:
                    fallback_events.append(
                        {"from": name, "error_code": err.code.value, "reason": str(err)}
                    )
                    continue
                raise err

            t0 = time.monotonic()
            try:
                response = provider.generate(request)
                self._emit_attempt(
                    {
                        "provider": response.provider,
                        "model": response.model,
                        "task_tier": request.task_complexity.value,
                        "status": "OK",
                        "error_category": None,
                        "latency_ms": response.latency_ms,
                        "prompt_tokens": response.usage.prompt_tokens,
                        "completion_tokens": response.usage.completion_tokens,
                        "total_tokens": response.usage.total_tokens,
                        "estimated_cost_usd": response.usage.estimated_cost_usd,
                        "fallback_from": primary_name if idx > 0 else None,
                    },
                    on_attempt,
                )
                if fallback_events:
                    logger.info(
                        "provider_fallback_succeeded primary=%s active=%s events=%d",
                        primary_name,
                        response.provider,
                        len(fallback_events),
                    )
                return AIResponse(
                    provider=response.provider,
                    model=response.model,
                    content=response.content,
                    usage=response.usage,
                    latency_ms=response.latency_ms,
                    finish_reason=response.finish_reason,
                    fallback_events=tuple(fallback_events),
                    raw_request_id=response.raw_request_id,
                )
            except ProviderExecutionError as exc:
                elapsed_ms = max(0.01, (time.monotonic() - t0) * 1000.0)
                last_error = exc
                self._emit_attempt(
                    {
                        "provider": exc.provider,
                        "model": exc.model,
                        "task_tier": request.task_complexity.value,
                        "status": "ERROR",
                        "error_category": exc.code.value,
                        "latency_ms": round(elapsed_ms, 2),
                        "prompt_tokens": 0,
                        "completion_tokens": 0,
                        "total_tokens": 0,
                        "estimated_cost_usd": 0.0,
                        "fallback_from": primary_name if idx > 0 else None,
                    },
                    on_attempt,
                )
                logger.warning(
                    "provider_error provider=%s model=%s code=%s retryable=%s",
                    exc.provider,
                    exc.model,
                    exc.code.value,
                    exc.retryable,
                )
                if self.routing.allow_fallback and idx < len(candidates) - 1:
                    fallback_events.append(
                        {
                            "from": name,
                            "error_code": exc.code.value,
                            "status_code": exc.status_code,
                        }
                    )
                    continue
                raise

        if last_error is not None:
            raise last_error
        raise ProviderExecutionError(
            provider="router",
            model="none",
            code=ProviderErrorCode.CONFIG_ERROR,
            message="No provider succeeded.",
        )

    def health_check_all(self) -> List[HealthCheckResult]:
        """Runs health checks across all registered providers."""
        return [p.health_check() for p in self.providers.values()]

    def public_summary(self) -> Dict[str, Any]:
        return {
            "providers": [
                {
                    "name": name,
                    "model": p.model_name,
                    "type": type(p).__name__,
                }
                for name, p in self.providers.items()
            ],
            "routing": self.routing.to_public_dict(),
        }
