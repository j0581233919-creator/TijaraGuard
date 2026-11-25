"""Application runtime wiring from TijaraGuardConfig to pipeline, channels, and AI router."""

from __future__ import annotations

import logging
from typing import Optional

from .channels import (
    ChannelRegistry,
    ChatwootAdapter,
    GenericWebhookAdapter,
    TelegramBotAdapter,
    WhatsAppCloudAdapter,
)
from .commerce import CommercialGate
from .config import TijaraGuardConfig
from .ledger import EphemeralRouteStore
from .pipeline import TijaraGuardPipeline
from .providers import ModelRouter
from .security import SecretAndPIIRedactingLogFilter


def build_channel_registry(cfg: TijaraGuardConfig) -> ChannelRegistry:
    """Builds enabled official channel adapters from TijaraGuardConfig."""
    registry = ChannelRegistry()
    if cfg.channels.whatsapp.enabled:
        registry.register(
            WhatsAppCloudAdapter(
                cfg.channels.whatsapp,
                allow_loopback=cfg.allow_loopback_channels,
                replay_window_seconds=cfg.webhook_replay_window_seconds,
            )
        )
    if cfg.channels.telegram.enabled:
        registry.register(
            TelegramBotAdapter(
                cfg.channels.telegram,
                allow_loopback=cfg.allow_loopback_channels,
                replay_window_seconds=cfg.webhook_replay_window_seconds,
            )
        )
    if cfg.channels.chatwoot.enabled:
        registry.register(
            ChatwootAdapter(
                cfg.channels.chatwoot,
                allow_loopback=cfg.allow_loopback_channels,
                replay_window_seconds=cfg.webhook_replay_window_seconds,
            )
        )
    if cfg.channels.webhook.enabled:
        registry.register(
            GenericWebhookAdapter(
                cfg.channels.webhook,
                allow_loopback=cfg.allow_loopback_channels,
                replay_window_seconds=cfg.webhook_replay_window_seconds,
            )
        )
    return registry


def attach_privacy_log_filter(
    cfg: TijaraGuardConfig,
    pipeline: TijaraGuardPipeline,
) -> SecretAndPIIRedactingLogFilter:
    """Attaches a secret & BayanGate PII redacting filter to tijaraguard loggers and handlers."""
    flt = SecretAndPIIRedactingLogFilter(
        privacy_gate=pipeline.privacy_gate,
        secrets_provider=cfg.secret_values_for_scrubbing,
    )
    logger_names = (
        "tijaraguard",
        "tijaraguard.pipeline",
        "tijaraguard.api",
        "tijaraguard.providers",
        "tijaraguard.channels",
        "tijaraguard.cli",
    )
    for lname in logger_names:
        lg = logging.getLogger(lname)
        for existing in list(lg.filters):
            if isinstance(existing, SecretAndPIIRedactingLogFilter):
                lg.removeFilter(existing)
        lg.addFilter(flt)
        for h in lg.handlers:
            for existing in list(h.filters):
                if isinstance(existing, SecretAndPIIRedactingLogFilter):
                    h.removeFilter(existing)
            h.addFilter(flt)
    return flt


def build_pipeline_from_config(
    cfg: TijaraGuardConfig,
    *,
    attach_log_filter: bool = True,
) -> TijaraGuardPipeline:
    """Constructs a fully wired TijaraGuardPipeline from TijaraGuardConfig."""
    if str(cfg.catalog_path).lower().endswith(".csv"):
        catalog = CommercialGate.from_csv_file(cfg.catalog_path).catalog
    else:
        catalog = CommercialGate.from_json_file(cfg.catalog_path).catalog

    channel_registry = build_channel_registry(cfg)
    route_store = EphemeralRouteStore(
        cfg.routes_db_path,
        default_ttl_seconds=cfg.retention.route_ttl_seconds,
    )
    ai_router: Optional[ModelRouter] = None
    if any(p.enabled for p in cfg.providers.values()):
        ai_router = ModelRouter.from_config(cfg)

    pipeline = TijaraGuardPipeline(
        catalog=catalog,
        ledger_db_path=cfg.ledger_db_path,
        approval_secret=cfg.approval_secret,
        mode=cfg.mode,
        outbox_db_path=cfg.outbox_db_path,
        receiver_endpoint=cfg.loopback_receiver_endpoint,
        contact_hash_key=cfg.contact_hash_key,
        ai_router=ai_router,
        channel_registry=channel_registry,
        route_store=route_store,
        tenant_id=cfg.tenant_id,
        retention_days=cfg.retention.inquiry_retention_days,
        fallback_to_template_on_ai_error=cfg.routing.fallback_to_template,
        allow_loopback_channels=cfg.allow_loopback_channels,
    )
    if attach_log_filter:
        attach_privacy_log_filter(cfg, pipeline)
    return pipeline
