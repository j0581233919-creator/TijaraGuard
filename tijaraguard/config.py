"""Environment & file configuration loader and startup validator for TijaraGuard."""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .models import ExecutionMode, MalformedInputError, parse_bool_strict, validate_safe_id
from .security import SSRFError, validate_outbound_url


@dataclass(frozen=True)
class ProviderEndpointConfig:
    """Configuration for a single AI provider endpoint (never logs raw api_key)."""

    name: str
    kind: str  # openai_compat | anthropic | gemini | ollama
    model: str
    base_url: str
    api_key_env: Optional[str] = None
    api_key: Optional[str] = field(default=None, repr=False)
    timeout_seconds: float = 20.0
    max_retries: int = 2
    extra_headers: Dict[str, str] = field(default_factory=dict)
    input_cost_per_1k: Optional[float] = None
    output_cost_per_1k: Optional[float] = None
    enabled: bool = True

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "model": self.model,
            "base_url": self.base_url,
            "api_key_env": self.api_key_env,
            "api_key_configured": bool(self.api_key and self.api_key.strip()),
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "enabled": self.enabled,
            "input_cost_per_1k": self.input_cost_per_1k,
            "output_cost_per_1k": self.output_cost_per_1k,
        }


@dataclass(frozen=True)
class RoutingConfig:
    """Model routing and explicit fallback configuration."""

    default_provider: Optional[str] = None
    tier_routes: Dict[str, str] = field(default_factory=dict)
    allow_fallback: bool = False
    fallback_chain: Tuple[str, ...] = ()
    fallback_to_template: bool = True

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "default_provider": self.default_provider,
            "tier_routes": dict(self.tier_routes),
            "allow_fallback": self.allow_fallback,
            "fallback_chain": list(self.fallback_chain),
            "fallback_to_template": self.fallback_to_template,
        }


@dataclass(frozen=True)
class WhatsAppConfig:
    enabled: bool = False
    phone_number_id: str = ""
    access_token: Optional[str] = field(default=None, repr=False)
    verify_token: Optional[str] = field(default=None, repr=False)
    app_secret: Optional[str] = field(default=None, repr=False)
    api_version: str = "v21.0"
    base_url: str = "https://graph.facebook.com"

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "phone_number_id_configured": bool(self.phone_number_id.strip()),
            "access_token_configured": bool(self.access_token and self.access_token.strip()),
            "verify_token_configured": bool(self.verify_token and self.verify_token.strip()),
            "app_secret_configured": bool(self.app_secret and self.app_secret.strip()),
            "api_version": self.api_version,
            "base_url": self.base_url,
        }


@dataclass(frozen=True)
class TelegramConfig:
    enabled: bool = False
    bot_token: Optional[str] = field(default=None, repr=False)
    webhook_secret_token: Optional[str] = field(default=None, repr=False)
    base_url: str = "https://api.telegram.org"

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "bot_token_configured": bool(self.bot_token and self.bot_token.strip()),
            "webhook_secret_configured": bool(
                self.webhook_secret_token and self.webhook_secret_token.strip()
            ),
            "base_url": self.base_url,
        }


@dataclass(frozen=True)
class ChatwootConfig:
    enabled: bool = False
    base_url: str = ""
    account_id: str = ""
    api_access_token: Optional[str] = field(default=None, repr=False)
    webhook_secret: Optional[str] = field(default=None, repr=False)

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "base_url": self.base_url,
            "account_id": self.account_id,
            "api_access_token_configured": bool(
                self.api_access_token and self.api_access_token.strip()
            ),
            "webhook_secret_configured": bool(self.webhook_secret and self.webhook_secret.strip()),
        }


@dataclass(frozen=True)
class GenericWebhookConfig:
    enabled: bool = False
    inbound_secret: Optional[str] = field(default=None, repr=False)
    outbound_url: str = ""
    outbound_secret: Optional[str] = field(default=None, repr=False)
    receipt_lookup_url: str = ""

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "inbound_secret_configured": bool(self.inbound_secret and self.inbound_secret.strip()),
            "outbound_url": self.outbound_url,
            "outbound_secret_configured": bool(
                self.outbound_secret and self.outbound_secret.strip()
            ),
            "receipt_lookup_url": self.receipt_lookup_url,
        }


@dataclass(frozen=True)
class ChannelConfigs:
    whatsapp: WhatsAppConfig = field(default_factory=WhatsAppConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    chatwoot: ChatwootConfig = field(default_factory=ChatwootConfig)
    webhook: GenericWebhookConfig = field(default_factory=GenericWebhookConfig)

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "whatsapp": self.whatsapp.to_public_dict(),
            "telegram": self.telegram.to_public_dict(),
            "chatwoot": self.chatwoot.to_public_dict(),
            "webhook": self.webhook.to_public_dict(),
        }


@dataclass(frozen=True)
class RetentionConfig:
    inquiry_retention_days: int = 30
    route_ttl_seconds: int = 86400
    channel_event_retention_days: int = 7


@dataclass(frozen=True)
class TijaraGuardConfig:
    """Complete runtime configuration for TijaraGuard."""

    mode: ExecutionMode
    tenant_id: str
    state_dir: Path
    ledger_db_path: Path
    outbox_db_path: Path
    routes_db_path: Path
    backup_dir: Path
    catalog_path: Path
    approval_secret: bytes = field(repr=False)
    contact_hash_key: bytes = field(repr=False)
    operator_api_key: Optional[str] = field(default=None, repr=False)
    bind_host: str = "127.0.0.1"
    bind_port: int = 8080
    loopback_receiver_endpoint: Optional[str] = None
    allow_loopback_providers: bool = False
    allow_loopback_channels: bool = False
    providers: Dict[str, ProviderEndpointConfig] = field(default_factory=dict)
    routing: RoutingConfig = field(default_factory=RoutingConfig)
    channels: ChannelConfigs = field(default_factory=ChannelConfigs)
    retention: RetentionConfig = field(default_factory=RetentionConfig)
    rate_limit_per_minute: int = 120
    webhook_replay_window_seconds: int = 300
    ephemeral_secrets_generated: bool = False

    def secret_values_for_scrubbing(self) -> List[str]:
        vals: List[str] = []
        if self.operator_api_key:
            vals.append(self.operator_api_key)
        for p in self.providers.values():
            if p.api_key:
                vals.append(p.api_key)
            for hv in p.extra_headers.values():
                if isinstance(hv, str) and len(hv) >= 4:
                    vals.append(hv)
        for val in (
            self.channels.whatsapp.access_token,
            self.channels.whatsapp.verify_token,
            self.channels.whatsapp.app_secret,
            self.channels.telegram.bot_token,
            self.channels.telegram.webhook_secret_token,
            self.channels.chatwoot.api_access_token,
            self.channels.chatwoot.webhook_secret,
            self.channels.webhook.inbound_secret,
            self.channels.webhook.outbound_secret,
        ):
            if val:
                vals.append(val)
        return [v for v in vals if isinstance(v, str) and len(v) >= 4]

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "tenant_id": self.tenant_id,
            "state_dir": str(self.state_dir),
            "ledger_db_path": str(self.ledger_db_path),
            "outbox_db_path": str(self.outbox_db_path),
            "routes_db_path": str(self.routes_db_path),
            "backup_dir": str(self.backup_dir),
            "catalog_path": str(self.catalog_path),
            "bind_host": self.bind_host,
            "bind_port": self.bind_port,
            "operator_api_key_configured": bool(
                self.operator_api_key and self.operator_api_key.strip()
            ),
            "ephemeral_secrets_generated": self.ephemeral_secrets_generated,
            "allow_loopback_providers": self.allow_loopback_providers,
            "allow_loopback_channels": self.allow_loopback_channels,
            "providers": {k: v.to_public_dict() for k, v in self.providers.items()},
            "routing": self.routing.to_public_dict(),
            "channels": self.channels.to_public_dict(),
            "retention": {
                "inquiry_retention_days": self.retention.inquiry_retention_days,
                "route_ttl_seconds": self.retention.route_ttl_seconds,
                "channel_event_retention_days": self.retention.channel_event_retention_days,
            },
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "webhook_replay_window_seconds": self.webhook_replay_window_seconds,
        }


def _decode_secret_bytes(raw: Optional[str]) -> Optional[bytes]:
    if raw is None or not raw.strip():
        return None
    val = raw.strip()
    if len(val) >= 32 and all(c in "0123456789abcdefABCDEF" for c in val) and len(val) % 2 == 0:
        try:
            return bytes.fromhex(val)
        except ValueError:
            pass
    return val.encode("utf-8")


def _parse_mode(raw: str) -> ExecutionMode:
    norm = raw.strip().upper()
    if norm in ("SHADOW", "SIMULATED_NO_SEND"):
        return ExecutionMode.SHADOW
    if norm == "LOOPBACK_LIVE":
        return ExecutionMode.LOOPBACK_LIVE
    if norm == "LIVE":
        return ExecutionMode.LIVE
    raise MalformedInputError(f"Unsupported ExecutionMode '{raw}'.")


def _parse_int(raw: Any, field_name: str, *, default: Optional[int] = None) -> int:
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        if default is not None:
            return default
        raise MalformedInputError(f"Field '{field_name}' must be an integer.")
    if isinstance(raw, bool):
        raise MalformedInputError(f"Field '{field_name}' must be an integer, not boolean.")
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        s = raw.strip()
        try:
            return int(s)
        except ValueError as exc:
            raise MalformedInputError(f"Field '{field_name}' must be a valid integer.") from exc
    raise MalformedInputError(f"Field '{field_name}' must be an integer.")


def _default_repo_root() -> Path:
    pkg_parent = Path(__file__).resolve().parents[1]
    if (pkg_parent / "pyproject.toml").is_file() or (pkg_parent / "examples").is_dir():
        return pkg_parent
    return Path.cwd()


def _default_catalog_path(repo_root: Path) -> Path:
    repo_cat = repo_root / "examples" / "catalog.json"
    if repo_cat.is_file():
        return repo_cat
    cwd_cat = Path.cwd() / "examples" / "catalog.json"
    if cwd_cat.is_file():
        return cwd_cat
    return Path(__file__).resolve().parent / "data" / "catalog.json"


def load_config(
    config_file: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
) -> TijaraGuardConfig:
    """Loads configuration from optional JSON file overlaid with environment variables."""
    env_map = os.environ if env is None else env
    file_data: Dict[str, Any] = {}
    if config_file is not None:
        cfg_path = Path(config_file).resolve()
        if not cfg_path.is_file():
            raise MalformedInputError(f"Config file not found: {cfg_path}")
        try:
            loaded = json.loads(cfg_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MalformedInputError(f"Invalid config JSON file: {exc}") from exc
        if not isinstance(loaded, dict):
            raise MalformedInputError("Config file root must be a JSON object.")
        file_data = loaded

    repo_root = _default_repo_root()
    state_dir = Path(
        env_map.get("TIJARAGUARD_STATE_DIR")
        or file_data.get("state_dir")
        or str(repo_root / ".state" / "runtime")
    ).resolve()
    ledger_db = Path(
        env_map.get("TIJARAGUARD_LEDGER_DB")
        or file_data.get("ledger_db_path")
        or str(state_dir / "ledger.sqlite3")
    ).resolve()
    outbox_db = Path(
        env_map.get("TIJARAGUARD_OUTBOX_DB")
        or file_data.get("outbox_db_path")
        or str(state_dir / "outbox.sqlite3")
    ).resolve()
    routes_db = Path(
        env_map.get("TIJARAGUARD_ROUTES_DB")
        or file_data.get("routes_db_path")
        or str(state_dir / "routes.sqlite3")
    ).resolve()
    backup_dir = Path(
        env_map.get("TIJARAGUARD_BACKUP_DIR")
        or file_data.get("backup_dir")
        or str(state_dir / "backups")
    ).resolve()
    raw_cat = env_map.get("TIJARAGUARD_CATALOG_PATH") or file_data.get("catalog_path")
    catalog_path = (
        Path(raw_cat).resolve() if raw_cat else _default_catalog_path(repo_root).resolve()
    )

    mode = _parse_mode(
        str(env_map.get("TIJARAGUARD_MODE") or file_data.get("mode") or ExecutionMode.SHADOW.value)
    )
    tenant_id = validate_safe_id(
        str(env_map.get("TIJARAGUARD_TENANT_ID") or file_data.get("tenant_id") or "default"),
        "tenant_id",
    )

    approval_secret_bytes = _decode_secret_bytes(
        env_map.get("TIJARAGUARD_APPROVAL_SECRET") or file_data.get("approval_secret")
    )
    contact_hash_bytes = _decode_secret_bytes(
        env_map.get("TIJARAGUARD_CONTACT_HASH_KEY") or file_data.get("contact_hash_key")
    )
    ephemeral = False
    if approval_secret_bytes is None:
        approval_secret_bytes = secrets.token_bytes(32)
        ephemeral = True
    if contact_hash_bytes is None:
        contact_hash_bytes = secrets.token_bytes(32)
        ephemeral = True

    operator_api_key = (
        env_map.get("TIJARAGUARD_API_KEY")
        or file_data.get("operator_api_key")
        or None
    )
    bind_host = str(env_map.get("TIJARAGUARD_HOST") or file_data.get("bind_host") or "127.0.0.1")
    raw_port = env_map.get("TIJARAGUARD_PORT")
    if raw_port is None or not str(raw_port).strip():
        raw_port = file_data.get("bind_port")
    bind_port = _parse_int(raw_port, "bind_port", default=8080)

    loopback_endpoint = (
        env_map.get("TIJARAGUARD_LOOPBACK_RECEIVER_URL")
        or file_data.get("loopback_receiver_endpoint")
        or None
    )
    allow_loopback_providers = parse_bool_strict(
        env_map.get(
            "TIJARAGUARD_ALLOW_LOOPBACK_PROVIDERS",
            file_data.get("allow_loopback_providers", False),
        ),
        "allow_loopback_providers",
    )
    allow_loopback_channels = parse_bool_strict(
        env_map.get(
            "TIJARAGUARD_ALLOW_LOOPBACK_CHANNELS",
            file_data.get("allow_loopback_channels", False),
        ),
        "allow_loopback_channels",
    )

    providers: Dict[str, ProviderEndpointConfig] = {}
    raw_providers = file_data.get("providers") or {}
    if isinstance(raw_providers, dict):
        for name, pdata in raw_providers.items():
            if not isinstance(pdata, dict):
                continue
            key_env = pdata.get("api_key_env")
            resolved_key = env_map.get(key_env) if key_env else None
            if not resolved_key:
                resolved_key = pdata.get("api_key")
            providers[name] = ProviderEndpointConfig(
                name=name,
                kind=str(pdata.get("kind", "openai_compat")),
                model=str(pdata.get("model", "")),
                base_url=str(pdata.get("base_url", "")),
                api_key_env=key_env,
                api_key=resolved_key,
                timeout_seconds=float(pdata.get("timeout_seconds", 20.0)),
                max_retries=_parse_int(pdata.get("max_retries"), "max_retries", default=2),
                extra_headers=dict(pdata.get("extra_headers") or {}),
                input_cost_per_1k=pdata.get("input_cost_per_1k"),
                output_cost_per_1k=pdata.get("output_cost_per_1k"),
                enabled=bool(pdata.get("enabled", True)),
            )

    builtin_provider_specs = [
        ("openai", "openai_compat", "OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL", "https://api.openai.com/v1", "gpt-4o-mini"),
        ("groq", "openai_compat", "GROQ_API_KEY", "GROQ_BASE_URL", "GROQ_MODEL", "https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"),
        ("openrouter", "openai_compat", "OPENROUTER_API_KEY", "OPENROUTER_BASE_URL", "OPENROUTER_MODEL", "https://openrouter.ai/api/v1", "openai/gpt-4o-mini"),
        ("mistral", "openai_compat", "MISTRAL_API_KEY", "MISTRAL_BASE_URL", "MISTRAL_MODEL", "https://api.mistral.ai/v1", "mistral-small-latest"),
        ("anthropic", "anthropic", "ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL", "https://api.anthropic.com/v1", "claude-3-5-haiku-latest"),
        ("gemini", "gemini", "GEMINI_API_KEY", "GEMINI_BASE_URL", "GEMINI_MODEL", "https://generativelanguage.googleapis.com/v1beta", "gemini-2.0-flash"),
    ]
    for name, kind, key_env, url_env, model_env, default_url, default_model in builtin_provider_specs:
        api_key = (env_map.get(key_env) or "").strip() or None
        base_url = (env_map.get(url_env) or "").strip() or None
        model = (env_map.get(model_env) or "").strip() or None
        if name not in providers and api_key:
            providers[name] = ProviderEndpointConfig(
                name=name,
                kind=kind,
                model=model or default_model,
                base_url=base_url or default_url,
                api_key_env=key_env,
                api_key=api_key,
                enabled=True,
            )
        elif name in providers:
            existing = providers[name]
            providers[name] = ProviderEndpointConfig(
                name=existing.name,
                kind=existing.kind,
                model=model or existing.model,
                base_url=base_url or existing.base_url,
                api_key_env=existing.api_key_env or key_env,
                api_key=api_key or existing.api_key,
                timeout_seconds=existing.timeout_seconds,
                max_retries=existing.max_retries,
                extra_headers=existing.extra_headers,
                input_cost_per_1k=existing.input_cost_per_1k,
                output_cost_per_1k=existing.output_cost_per_1k,
                enabled=existing.enabled,
            )

    # Ollama is strictly optional: only enable when OLLAMA_BASE_URL or OLLAMA_ENABLED=true is set
    ollama_url = (env_map.get("OLLAMA_BASE_URL") or "").strip() or None
    ollama_model = (env_map.get("OLLAMA_MODEL") or "").strip() or None
    ollama_enabled_env = env_map.get("OLLAMA_ENABLED")
    ollama_explicit = (
        parse_bool_strict(ollama_enabled_env, "OLLAMA_ENABLED")
        if ollama_enabled_env is not None and str(ollama_enabled_env).strip()
        else bool(ollama_url)
    )
    if "ollama" not in providers and ollama_explicit:
        providers["ollama"] = ProviderEndpointConfig(
            name="ollama",
            kind="ollama",
            model=ollama_model or "qwen2.5:7b",
            base_url=ollama_url or "http://127.0.0.1:11434",
            enabled=True,
        )
    elif "ollama" in providers:
        existing = providers["ollama"]
        providers["ollama"] = ProviderEndpointConfig(
            name=existing.name,
            kind=existing.kind,
            model=ollama_model or existing.model,
            base_url=ollama_url or existing.base_url,
            api_key_env=existing.api_key_env,
            api_key=existing.api_key,
            timeout_seconds=existing.timeout_seconds,
            max_retries=existing.max_retries,
            extra_headers=existing.extra_headers,
            input_cost_per_1k=existing.input_cost_per_1k,
            output_cost_per_1k=existing.output_cost_per_1k,
            enabled=(
                parse_bool_strict(ollama_enabled_env, "OLLAMA_ENABLED")
                if ollama_enabled_env is not None and str(ollama_enabled_env).strip()
                else existing.enabled
            ),
        )

    routing_raw = file_data.get("routing") or {}
    default_provider = (
        (env_map.get("TIJARAGUARD_DEFAULT_PROVIDER") or "").strip()
        or routing_raw.get("default_provider")
        or next((k for k, p in providers.items() if p.enabled), None)
    )
    fallback_raw = env_map.get("TIJARAGUARD_FALLBACK_CHAIN")
    if fallback_raw is not None:
        fallback_chain = tuple(x.strip() for x in fallback_raw.split(",") if x.strip())
    else:
        fallback_chain = tuple(routing_raw.get("fallback_chain") or ())

    tier_routes: Dict[str, str] = dict(routing_raw.get("tier_routes") or {})
    for tier in ("simple", "standard", "complex"):
        env_tier = (env_map.get(f"TIJARAGUARD_PROVIDER_{tier.upper()}") or "").strip()
        if env_tier:
            tier_routes[tier] = env_tier

    routing = RoutingConfig(
        default_provider=default_provider,
        tier_routes=tier_routes,
        allow_fallback=parse_bool_strict(
            env_map.get("TIJARAGUARD_ALLOW_FALLBACK", routing_raw.get("allow_fallback", False)),
            "allow_fallback",
        ),
        fallback_chain=fallback_chain,
        fallback_to_template=parse_bool_strict(
            env_map.get(
                "TIJARAGUARD_FALLBACK_TO_TEMPLATE",
                routing_raw.get("fallback_to_template", True),
            ),
            "fallback_to_template",
        ),
    )

    ch_raw = file_data.get("channels") or {}
    wa_raw = ch_raw.get("whatsapp") or {}
    wa_token = env_map.get("WHATSAPP_ACCESS_TOKEN") or wa_raw.get("access_token")
    wa_phone_id = env_map.get("WHATSAPP_PHONE_NUMBER_ID") or wa_raw.get("phone_number_id") or ""
    wa_verify = env_map.get("WHATSAPP_VERIFY_TOKEN") or wa_raw.get("verify_token")
    wa_secret = env_map.get("WHATSAPP_APP_SECRET") or wa_raw.get("app_secret")
    wa_enabled = parse_bool_strict(
        env_map.get(
            "WHATSAPP_ENABLED",
            wa_raw.get("enabled", bool(wa_phone_id or wa_token or wa_secret)),
        ),
        "WHATSAPP_ENABLED",
    )
    whatsapp_cfg = WhatsAppConfig(
        enabled=wa_enabled,
        phone_number_id=str(wa_phone_id),
        access_token=wa_token,
        verify_token=wa_verify,
        app_secret=wa_secret,
        api_version=str(env_map.get("WHATSAPP_API_VERSION") or wa_raw.get("api_version") or "v21.0"),
        base_url=str(
            env_map.get("WHATSAPP_BASE_URL")
            or wa_raw.get("base_url")
            or "https://graph.facebook.com"
        ),
    )

    tg_raw = ch_raw.get("telegram") or {}
    tg_token = env_map.get("TELEGRAM_BOT_TOKEN") or tg_raw.get("bot_token")
    tg_secret = env_map.get("TELEGRAM_WEBHOOK_SECRET") or tg_raw.get("webhook_secret_token")
    tg_enabled = parse_bool_strict(
        env_map.get("TELEGRAM_ENABLED", tg_raw.get("enabled", bool(tg_token or tg_secret))),
        "TELEGRAM_ENABLED",
    )
    telegram_cfg = TelegramConfig(
        enabled=tg_enabled,
        bot_token=tg_token,
        webhook_secret_token=tg_secret,
        base_url=str(
            env_map.get("TELEGRAM_BASE_URL") or tg_raw.get("base_url") or "https://api.telegram.org"
        ),
    )

    cw_raw = ch_raw.get("chatwoot") or {}
    cw_url = env_map.get("CHATWOOT_BASE_URL") or cw_raw.get("base_url") or ""
    cw_account = env_map.get("CHATWOOT_ACCOUNT_ID") or cw_raw.get("account_id") or ""
    cw_token = env_map.get("CHATWOOT_API_ACCESS_TOKEN") or cw_raw.get("api_access_token")
    cw_secret = env_map.get("CHATWOOT_WEBHOOK_SECRET") or cw_raw.get("webhook_secret")
    cw_enabled = parse_bool_strict(
        env_map.get(
            "CHATWOOT_ENABLED",
            cw_raw.get("enabled", bool(cw_url or cw_token or cw_secret)),
        ),
        "CHATWOOT_ENABLED",
    )
    chatwoot_cfg = ChatwootConfig(
        enabled=cw_enabled,
        base_url=str(cw_url),
        account_id=str(cw_account),
        api_access_token=cw_token,
        webhook_secret=cw_secret,
    )

    wh_raw = ch_raw.get("webhook") or {}
    wh_in_secret = env_map.get("TIJARAGUARD_WEBHOOK_INBOUND_SECRET") or wh_raw.get("inbound_secret")
    wh_out_url = env_map.get("TIJARAGUARD_WEBHOOK_OUTBOUND_URL") or wh_raw.get("outbound_url") or ""
    wh_out_secret = env_map.get("TIJARAGUARD_WEBHOOK_OUTBOUND_SECRET") or wh_raw.get("outbound_secret")
    wh_lookup_url = env_map.get("TIJARAGUARD_WEBHOOK_LOOKUP_URL") or wh_raw.get("receipt_lookup_url") or ""
    wh_enabled = parse_bool_strict(
        env_map.get(
            "TIJARAGUARD_WEBHOOK_ENABLED",
            wh_raw.get("enabled", bool(wh_in_secret or wh_out_url)),
        ),
        "TIJARAGUARD_WEBHOOK_ENABLED",
    )
    webhook_cfg = GenericWebhookConfig(
        enabled=wh_enabled,
        inbound_secret=wh_in_secret,
        outbound_url=str(wh_out_url),
        outbound_secret=wh_out_secret,
        receipt_lookup_url=str(wh_lookup_url),
    )

    ret_raw = file_data.get("retention") or {}
    ret_days = _parse_int(
        env_map.get("TIJARAGUARD_RETENTION_DAYS")
        if env_map.get("TIJARAGUARD_RETENTION_DAYS") not in (None, "")
        else ret_raw.get("inquiry_retention_days"),
        "inquiry_retention_days",
        default=30,
    )
    route_ttl = _parse_int(
        env_map.get("TIJARAGUARD_ROUTE_TTL_SECONDS")
        if env_map.get("TIJARAGUARD_ROUTE_TTL_SECONDS") not in (None, "")
        else ret_raw.get("route_ttl_seconds"),
        "route_ttl_seconds",
        default=86400,
    )
    ev_ret_days = _parse_int(
        env_map.get("TIJARAGUARD_CHANNEL_EVENT_RETENTION_DAYS")
        if env_map.get("TIJARAGUARD_CHANNEL_EVENT_RETENTION_DAYS") not in (None, "")
        else ret_raw.get("channel_event_retention_days"),
        "channel_event_retention_days",
        default=7,
    )
    retention = RetentionConfig(
        inquiry_retention_days=ret_days,
        route_ttl_seconds=route_ttl,
        channel_event_retention_days=ev_ret_days,
    )

    rate_limit = _parse_int(
        env_map.get("TIJARAGUARD_RATE_LIMIT_PER_MIN")
        if env_map.get("TIJARAGUARD_RATE_LIMIT_PER_MIN") not in (None, "")
        else file_data.get("rate_limit_per_minute"),
        "rate_limit_per_minute",
        default=120,
    )
    replay_window = _parse_int(
        env_map.get("TIJARAGUARD_WEBHOOK_REPLAY_WINDOW_SECONDS")
        if env_map.get("TIJARAGUARD_WEBHOOK_REPLAY_WINDOW_SECONDS") not in (None, "")
        else file_data.get("webhook_replay_window_seconds"),
        "webhook_replay_window_seconds",
        default=300,
    )

    return TijaraGuardConfig(
        mode=mode,
        tenant_id=tenant_id,
        state_dir=state_dir,
        ledger_db_path=ledger_db,
        outbox_db_path=outbox_db,
        routes_db_path=routes_db,
        backup_dir=backup_dir,
        catalog_path=catalog_path,
        approval_secret=approval_secret_bytes,
        contact_hash_key=contact_hash_bytes,
        operator_api_key=operator_api_key,
        bind_host=bind_host,
        bind_port=bind_port,
        loopback_receiver_endpoint=loopback_endpoint,
        allow_loopback_providers=allow_loopback_providers,
        allow_loopback_channels=allow_loopback_channels,
        providers=providers,
        routing=routing,
        channels=ChannelConfigs(
            whatsapp=whatsapp_cfg,
            telegram=telegram_cfg,
            chatwoot=chatwoot_cfg,
            webhook=webhook_cfg,
        ),
        retention=retention,
        rate_limit_per_minute=rate_limit,
        webhook_replay_window_seconds=replay_window,
        ephemeral_secrets_generated=ephemeral,
    )


def validate_config(cfg: TijaraGuardConfig) -> Dict[str, Any]:
    """Validates configuration at startup without exposing secret values."""
    errors: List[str] = []
    warnings: List[str] = []

    if not cfg.catalog_path.is_file():
        errors.append(f"Catalog file does not exist: {cfg.catalog_path}")

    if len(cfg.approval_secret) < 16:
        errors.append("TIJARAGUARD_APPROVAL_SECRET must be at least 16 bytes.")
    elif len(cfg.approval_secret) < 32:
        warnings.append("TIJARAGUARD_APPROVAL_SECRET is shorter than recommended 32 bytes.")

    if len(cfg.contact_hash_key) < 16:
        errors.append("TIJARAGUARD_CONTACT_HASH_KEY must be at least 16 bytes.")
    elif len(cfg.contact_hash_key) < 32:
        warnings.append("TIJARAGUARD_CONTACT_HASH_KEY is shorter than recommended 32 bytes.")

    if cfg.ephemeral_secrets_generated:
        msg = (
            "Ephemeral approval_secret / contact_hash_key generated for this process; "
            "existing approvals/contact_refs will not verify across restarts."
        )
        if cfg.mode == ExecutionMode.LIVE:
            errors.append(f"LIVE mode requires persistent secrets: {msg}")
        else:
            warnings.append(msg)

    if cfg.bind_host not in ("127.0.0.1", "::1") and not (
        cfg.operator_api_key and cfg.operator_api_key.strip()
    ):
        errors.append(
            "Binding to a non-loopback address requires TIJARAGUARD_API_KEY to be configured."
        )
    elif not (cfg.operator_api_key and cfg.operator_api_key.strip()):
        warnings.append(
            "TIJARAGUARD_API_KEY is unset; protected /api/v1/* endpoints will fail closed (401)."
        )

    if not (1 <= cfg.bind_port <= 65535):
        errors.append(f"Invalid bind_port: {cfg.bind_port}")

    if cfg.mode == ExecutionMode.LOOPBACK_LIVE and not cfg.loopback_receiver_endpoint:
        errors.append("LOOPBACK_LIVE mode requires TIJARAGUARD_LOOPBACK_RECEIVER_URL.")

    for name, p in cfg.providers.items():
        if not p.enabled:
            continue
        if not p.model.strip():
            errors.append(f"Provider '{name}' has empty model name.")
        if p.kind in ("openai_compat", "anthropic", "gemini") and not (p.api_key and p.api_key.strip()):
            errors.append(f"Enabled cloud provider '{name}' is missing an API key.")
        try:
            allow_lb = cfg.allow_loopback_providers or p.kind == "ollama"
            validate_outbound_url(
                p.base_url,
                allow_loopback=allow_lb,
                allow_http_loopback=allow_lb,
                require_dns=False,
            )
        except SSRFError as exc:
            errors.append(f"Provider '{name}' URL rejected: {exc}")

    def _check_route_ref(label: str, pname: str) -> None:
        if pname not in cfg.providers:
            errors.append(f"{label} '{pname}' is not configured.")
        elif not cfg.providers[pname].enabled:
            errors.append(f"{label} '{pname}' is disabled.")

    if cfg.routing.default_provider:
        _check_route_ref("routing.default_provider", cfg.routing.default_provider)
    for tier, pname in cfg.routing.tier_routes.items():
        _check_route_ref(f"routing.tier_routes['{tier}']", pname)
    for pname in cfg.routing.fallback_chain:
        _check_route_ref("routing.fallback_chain", pname)

    wa = cfg.channels.whatsapp
    if wa.enabled:
        if not wa.phone_number_id.strip():
            errors.append("WhatsApp enabled but WHATSAPP_PHONE_NUMBER_ID is missing.")
        if not (wa.access_token and wa.access_token.strip()):
            errors.append("WhatsApp enabled but WHATSAPP_ACCESS_TOKEN is missing.")
        if not (wa.app_secret and wa.app_secret.strip()):
            errors.append("WhatsApp enabled but WHATSAPP_APP_SECRET is missing.")
        try:
            validate_outbound_url(
                wa.base_url,
                allow_loopback=cfg.allow_loopback_channels,
                allow_http_loopback=cfg.allow_loopback_channels,
                require_dns=False,
            )
        except SSRFError as exc:
            errors.append(f"WhatsApp base_url rejected: {exc}")

    tg = cfg.channels.telegram
    if tg.enabled:
        if not (tg.bot_token and tg.bot_token.strip()):
            errors.append("Telegram enabled but TELEGRAM_BOT_TOKEN is missing.")
        if not (tg.webhook_secret_token and tg.webhook_secret_token.strip()):
            warnings.append("Telegram enabled without TELEGRAM_WEBHOOK_SECRET; webhook endpoint will reject requests.")
        try:
            validate_outbound_url(
                tg.base_url,
                allow_loopback=cfg.allow_loopback_channels,
                allow_http_loopback=cfg.allow_loopback_channels,
                require_dns=False,
            )
        except SSRFError as exc:
            errors.append(f"Telegram base_url rejected: {exc}")

    cw = cfg.channels.chatwoot
    if cw.enabled:
        if not cw.base_url.strip() or not cw.account_id.strip():
            errors.append("Chatwoot enabled but CHATWOOT_BASE_URL or CHATWOOT_ACCOUNT_ID is missing.")
        if not (cw.api_access_token and cw.api_access_token.strip()):
            errors.append("Chatwoot enabled but CHATWOOT_API_ACCESS_TOKEN is missing.")
        if not (cw.webhook_secret and cw.webhook_secret.strip()):
            errors.append("Chatwoot enabled but CHATWOOT_WEBHOOK_SECRET is missing.")
        if cw.base_url.strip():
            try:
                validate_outbound_url(
                    cw.base_url,
                    allow_loopback=cfg.allow_loopback_channels,
                    allow_http_loopback=cfg.allow_loopback_channels,
                    require_dns=False,
                )
            except SSRFError as exc:
                errors.append(f"Chatwoot base_url rejected: {exc}")

    wh = cfg.channels.webhook
    if wh.enabled:
        if not (wh.inbound_secret and wh.inbound_secret.strip()):
            warnings.append("Generic webhook enabled without TIJARAGUARD_WEBHOOK_INBOUND_SECRET; inbound webhooks will reject requests.")
        if wh.outbound_url.strip():
            try:
                validate_outbound_url(
                    wh.outbound_url,
                    allow_loopback=cfg.allow_loopback_channels,
                    allow_http_loopback=cfg.allow_loopback_channels,
                    require_dns=False,
                )
            except SSRFError as exc:
                errors.append(f"Generic webhook outbound_url rejected: {exc}")
        if wh.receipt_lookup_url.strip():
            try:
                validate_outbound_url(
                    wh.receipt_lookup_url,
                    allow_loopback=cfg.allow_loopback_channels,
                    allow_http_loopback=cfg.allow_loopback_channels,
                    require_dns=False,
                )
            except SSRFError as exc:
                errors.append(f"Generic webhook receipt_lookup_url rejected: {exc}")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "summary": cfg.to_public_dict(),
    }
