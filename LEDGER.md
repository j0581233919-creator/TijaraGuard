# TijaraGuard Authoritative Execution Ledger

## Immutable Starting Baseline
- **Repository:** `/media/islam/shared pop/GitHub/tijaraguard-prototype` (branch `main`)
- **Starting Commit:** `066a8447efc37e99b4f0fd289062e435f009447d` (32/32 baseline tests passing, `ACCEPTED_WITH_MINOR_NOTES`)
- **Upstream Dependencies (Immutable, Unmodified):**
  - `bayan-gate/repo`: `1d6b83a46cb75484a434efe17be2e7d97885050c` (MIT)
  - `catalog-copilot/repo`: `12522d3b17767ae9a4766499b6495fd4231ebcfc` (MIT)
  - `message-shield/repo`: `4ccbc2641c18b47a9feadbe41010a06fb2791275` (MIT)
  - `quote-judge/repo`: `0563ddd2af8646962a5d627402119b007a9cfc37` (MIT — out of scope)

## Productization Milestones

| Milestone | Scope | Status |
| --- | --- | --- |
| M1: Packaging & Attribution | MIT-attributed `tijaraguard/_vendor/` snapshots + `MANIFEST.json` + `THIRD_PARTY_NOTICES.md` + updated `deps.py` | IMPLEMENTED |
| M2: Security & Config | `security.py` (SSRF, HMAC, API auth, rate limiter, CSV injection, secret/PII log filter, POSIX perms) + `config.py` | IMPLEMENTED |
| M3: Persistence v2 & Migrations | Schema v2, safe v1->v2 migration preserving `audit_events` & triggers, backup/restore, retention purge, `EphemeralRouteStore` | IMPLEMENTED |
| M4: Real AI Providers | `providers/` (OpenAI-compat, Anthropic, Gemini, optional Ollama, `ModelRouter` with pre-send PII guard & explicit fallback) | IMPLEMENTED |
| M5: Official Messaging Channels | `channels/` (WhatsApp Cloud, Telegram Bot, Chatwoot, Generic Webhook, `ChannelShieldTransport`, `ChannelRegistry`) | IMPLEMENTED |
| M6: Pipeline, REST API, Dashboard, CLI | `pipeline.py` LIVE mode + channel ingestion/escalation, `runtime.py`, `api.py`, `web/index.html`, `cli.py`, deployment configs | IMPLEMENTED |
| M7: Expanded Test & Protocol Suite | Protocol HTTP server tests, security, migrations, API/CLI, E2E Arabic scenarios, clean-room packaging | AUTOMATED_TESTED (48/48 passing) |
| M8: Independent EGM Audit & Publication | Fresh-context read-only EGM audit, remediation, GitHub release, `HANDOFF.txt` | PENDING |
