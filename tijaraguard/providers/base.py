"""Base types and interfaces for TijaraGuard AI model providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from ..models import ProviderError
from ..security import scrub_secrets_from_text


class ProviderErrorCode(str, Enum):
    """Explicit classification of provider failures."""

    CONFIG_ERROR = "CONFIG_ERROR"
    AUTH_ERROR = "AUTH_ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    SERVER_ERROR = "SERVER_ERROR"
    BAD_REQUEST = "BAD_REQUEST"
    NETWORK_ERROR = "NETWORK_ERROR"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    PII_BLOCKED = "PII_BLOCKED"


class ProviderExecutionError(ProviderError):
    """Structured, secret-scrubbed provider failure."""

    def __init__(
        self,
        *,
        provider: str,
        model: str,
        code: ProviderErrorCode,
        message: str,
        status_code: Optional[int] = None,
        retryable: bool = False,
        retry_after: Optional[float] = None,
    ) -> None:
        self.provider = provider
        self.model = model
        self.code = code
        self.status_code = status_code
        self.retryable = bool(retryable)
        self.retry_after = retry_after
        clean_msg = scrub_secrets_from_text(message)
        super().__init__(f"[{provider}/{model}] {code.value}: {clean_msg}")


class TaskComplexity(str, Enum):
    """Task complexity tiers for configurable model routing."""

    SIMPLE = "simple"
    STANDARD = "standard"
    COMPLEX = "complex"


@dataclass(frozen=True)
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "estimated_cost_usd": self.estimated_cost_usd,
        }


@dataclass(frozen=True)
class AIRequest:
    system_prompt: str
    user_prompt: str
    task_complexity: TaskComplexity = TaskComplexity.STANDARD
    temperature: float = 0.2
    max_tokens: int = 512
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AIResponse:
    provider: str
    model: str
    content: str
    usage: TokenUsage
    latency_ms: float
    finish_reason: Optional[str] = None
    fallback_events: Tuple[Dict[str, Any], ...] = ()
    raw_request_id: Optional[str] = None


@dataclass(frozen=True)
class HealthCheckResult:
    provider: str
    model: str
    healthy: bool
    latency_ms: float
    status_code: Optional[int] = None
    error_code: Optional[str] = None
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "healthy": self.healthy,
            "latency_ms": round(self.latency_ms, 2),
            "status_code": self.status_code,
            "error_code": self.error_code,
            "detail": scrub_secrets_from_text(self.detail),
        }


class AIProvider(ABC):
    """Abstract base class for all AI model provider adapters."""

    provider_name: str
    model_name: str

    @abstractmethod
    def generate(self, request: AIRequest) -> AIResponse:
        """Executes a completion/generation request."""

    @abstractmethod
    def health_check(self) -> HealthCheckResult:
        """Performs a lightweight health/connectivity check against the provider."""


def compute_cost_usd(
    prompt_tokens: int,
    completion_tokens: int,
    input_cost_per_1k: Optional[float],
    output_cost_per_1k: Optional[float],
) -> Optional[float]:
    if input_cost_per_1k is None and output_cost_per_1k is None:
        return None
    in_cost = (prompt_tokens / 1000.0) * float(input_cost_per_1k or 0.0)
    out_cost = (completion_tokens / 1000.0) * float(output_cost_per_1k or 0.0)
    return round(in_cost + out_cost, 8)
