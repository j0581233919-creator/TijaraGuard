"""TijaraGuard isolated integration MVP package."""

from __future__ import annotations

import sys

# Must execute prior to importing read-only sibling repositories.
sys.dont_write_bytecode = True

from .commerce import CommercialGate
from .delivery import LocalLoopbackReceiver, MessageShieldDeliveryAdapter
from .deps import DependencyBundle, inspect_dependencies, load_dependencies
from .ledger import ApprovalLedger
from .models import (
    ApprovalAlreadyConsumedError,
    ApprovalExpiredError,
    ApprovalRequiredError,
    ApprovalTamperError,
    ApprovalToken,
    CommercialEvaluation,
    DeliveryError,
    DispatchOutcome,
    DraftState,
    ExecutionMode,
    InboundMessage,
    MalformedInputError,
    PrivacyViolationError,
    RedactedEnvelope,
    TijaraGuardError,
    VerificationBlockedError,
)
from .pipeline import TijaraGuardPipeline
from .privacy import PrivacyGate

__version__ = "0.1.0"

__all__ = [
    "ApprovalAlreadyConsumedError",
    "ApprovalExpiredError",
    "ApprovalLedger",
    "ApprovalRequiredError",
    "ApprovalTamperError",
    "ApprovalToken",
    "CommercialEvaluation",
    "CommercialGate",
    "DeliveryError",
    "DependencyBundle",
    "DispatchOutcome",
    "DraftState",
    "ExecutionMode",
    "InboundMessage",
    "LocalLoopbackReceiver",
    "MalformedInputError",
    "MessageShieldDeliveryAdapter",
    "PrivacyGate",
    "PrivacyViolationError",
    "RedactedEnvelope",
    "TijaraGuardError",
    "TijaraGuardPipeline",
    "VerificationBlockedError",
    "inspect_dependencies",
    "load_dependencies",
]
