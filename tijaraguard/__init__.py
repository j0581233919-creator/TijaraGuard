"""TijaraGuard commercial customer-support & sales-assistance platform."""

from __future__ import annotations

import importlib
import sys
from typing import Any

# Must execute prior to importing external/sibling repositories.
sys.dont_write_bytecode = True

__version__ = "0.2.0b1"

_EXPORTS = {
    "ApprovalAlreadyConsumedError": ("models", "ApprovalAlreadyConsumedError"),
    "ApprovalExpiredError": ("models", "ApprovalExpiredError"),
    "ApprovalLedger": ("ledger", "ApprovalLedger"),
    "ApprovalRequiredError": ("models", "ApprovalRequiredError"),
    "ApprovalTamperError": ("models", "ApprovalTamperError"),
    "ApprovalToken": ("models", "ApprovalToken"),
    "ChannelError": ("models", "ChannelError"),
    "CommercialEvaluation": ("models", "CommercialEvaluation"),
    "CommercialGate": ("commerce", "CommercialGate"),
    "DeliveryError": ("models", "DeliveryError"),
    "DependencyBundle": ("deps", "DependencyBundle"),
    "DispatchOutcome": ("models", "DispatchOutcome"),
    "DraftState": ("models", "DraftState"),
    "EphemeralRouteStore": ("ledger", "EphemeralRouteStore"),
    "ExecutionMode": ("models", "ExecutionMode"),
    "InboundMessage": ("models", "InboundMessage"),
    "LocalLoopbackReceiver": ("delivery", "LocalLoopbackReceiver"),
    "MalformedInputError": ("models", "MalformedInputError"),
    "MessageShieldDeliveryAdapter": ("delivery", "MessageShieldDeliveryAdapter"),
    "PrivacyGate": ("privacy", "PrivacyGate"),
    "PrivacyViolationError": ("models", "PrivacyViolationError"),
    "ProviderError": ("models", "ProviderError"),
    "RedactedEnvelope": ("models", "RedactedEnvelope"),
    "TijaraGuardConfig": ("config", "TijaraGuardConfig"),
    "TijaraGuardError": ("models", "TijaraGuardError"),
    "TijaraGuardHTTPServer": ("api", "TijaraGuardHTTPServer"),
    "TijaraGuardPipeline": ("pipeline", "TijaraGuardPipeline"),
    "VerificationBlockedError": ("models", "VerificationBlockedError"),
    "build_channel_registry": ("runtime", "build_channel_registry"),
    "build_grounded_ai_callable": ("commerce", "build_grounded_ai_callable"),
    "build_pipeline_from_config": ("runtime", "build_pipeline_from_config"),
    "inspect_dependencies": ("deps", "inspect_dependencies"),
    "load_config": ("config", "load_config"),
    "load_dependencies": ("deps", "load_dependencies"),
    "restore_ledger_backup": ("ledger", "restore_ledger_backup"),
    "validate_config": ("config", "validate_config"),
    "verify_vendor_manifest": ("deps", "verify_vendor_manifest"),
}

__all__ = sorted([*list(_EXPORTS.keys()), "__version__"])


def __getattr__(name: str) -> Any:
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    mod_name, attr_name = target
    mod = importlib.import_module(f".{mod_name}", __name__)
    val = getattr(mod, attr_name)
    globals()[name] = val
    return val
