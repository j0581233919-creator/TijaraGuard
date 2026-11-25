# TijaraGuard

**TijaraGuard** is a self-hosted and cloud-deployable commercial customer-support and sales-assistance platform for Arabic (Gulf, Egyptian, Levantine, MSA) and English commerce.

It enforces four mandatory safety gates between customer inquiries, cloud AI model providers, human operators, and official messaging channels:

1. **Gate 1 — Privacy (`BayanGate`)**: Detects and redacts regional/MENA PII (National IDs, Iqama, Emirates ID, Egyptian ID, GCC IBANs, phone numbers, emails) *before* SQLite persistence, logging, exception formatting, or outbound AI requests.
2. **Gate 2 — Commercial Truth (`CatalogCopilot`)**: Resolves Arabic dialect and English product inquiries against the deterministic catalog and verifies AI-generated or edited drafts against actual price, stock, discount validity, warranty, consent, and PII rules.
3. **Gate 3 — Human Approval (`ApprovalLedger`)**: Defaults to Shadow Mode (`SIMULATED_NO_SEND`), binds single-use HMAC-SHA256 approval leases to exact canonical `payload_sha256` hashes, and maintains an append-only SHA-256 hash-chained SQLite WAL audit trail.
4. **Gate 4 — Reliable Delivery (`MessageShield`)**: Dispatches approved responses through official channel adapters (WhatsApp Business Cloud API, Telegram Bot API, Chatwoot, Generic Signed Webhook, or Local Loopback) with idempotency keys, conservative `UNKNOWN` state handling, and read-only recovery.

## Supported AI Providers & Messaging Channels

- **AI Providers (all optional/configurable, no local model required)**:
  - OpenAI-compatible APIs (OpenAI, Groq, OpenRouter, Mistral, custom base URLs)
  - Anthropic Messages API (Claude models)
  - Google Gemini API (`x-goog-api-key` header)
  - Optional local Ollama inference
- **Messaging Channels**:
  - WhatsApp Business Cloud API (Meta Graph API webhooks, challenge verification, status callbacks, outbound send)
  - Telegram Bot API (`webhook` + `getUpdates` + `sendMessage`)
  - Chatwoot (inbound webhooks, private draft notes, operator handoff, public replies)
  - Generic Signed Webhook / REST integration

## Quickstart

```bash
# 1. Inspect resolved dependencies (sibling repo or MIT-attributed vendored snapshot)
PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard inspect-deps

# 2. Run the 4-gate synthetic Arabic business demonstration
PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard demo

# 3. Validate configuration and start the REST API + Operator Dashboard
cp .env.example .env
# Edit .env with your secrets/keys (keep TIJARAGUARD_MODE=SIMULATED_NO_SEND until ready)
set -a && source .env && set +a
PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard check-config
PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard serve

# 4. Run the full automated test suite
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
```

## Documentation

- [INSTALL.md](INSTALL.md) — Clean-room installation, CLI commands, and dependency provenance
- [ARCHITECTURE.md](ARCHITECTURE.md) — System architecture, 4-gate pipeline, and provider/channel design
- [DEPLOYMENT.md](DEPLOYMENT.md) — Self-hosted / VPS / TLS / Docker deployment and backup/restore
- [SECURITY.md](SECURITY.md) — Threat model, security controls, and honest residual boundaries
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — MIT upstream attributions (`BayanGate`, `CatalogCopilot`, `MessageShield`)
- [LEDGER.md](LEDGER.md) — Authoritative engineering execution ledger
