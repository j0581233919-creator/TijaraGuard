# TijaraGuard Security Policy & Threat Model

## 1. Security Controls Implemented

| Control Area | Implementation | Module |
| --- | --- | --- |
| **Pre-Persistence PII Redaction** | `BayanGate` redacts Saudi ID, Iqama, UAE ID, Egyptian ID, GCC IBAN, regional phones, emails before SQLite, logs, exceptions, and AI prompts; raw contact targets become keyed HMAC `contact_ref` handles. | `privacy.py`, `providers/router.py` |
| **Zero-PII Immutable Audit Ledger** | `ledger.sqlite3` never stores outbound raw phone/email targets (those live strictly in `EphemeralRouteStore` `routes.sqlite3` with TTL); `audit_events` enforces SQLite `BEFORE UPDATE`/`BEFORE DELETE` abort triggers and a SHA-256 hash chain. | `ledger.py` |
| **Single-Use Cryptographic Approval** | `ApprovalToken` HMAC-SHA256 leases bound to canonical `payload_sha256`; atomic `UPDATE ... WHERE consumed=0 AND revoked=0`; edit/tamper revokes lease automatically. | `ledger.py` |
| **Commercial Truth Guardrail** | `CatalogCopilot` deterministic `CommercialClaimVerifier` rejects hallucinated prices, discounts, warranties, stock claims, missing consent, and draft PII leaks. | `commerce.py` |
| **SSRF Protection** | `validate_outbound_url` enforces HTTPS (HTTP only for explicit loopback testing), rejects embedded credentials, fragments, redirects, localhost/private/link-local (`169.254.169.254`) IPs via DNS resolution. | `security.py`, `providers/http_client.py` |
| **Webhook Auth & Replay Protection** | Fail-closed signature/token validation (WhatsApp `X-Hub-Signature-256`, Telegram `X-Telegram-Bot-Api-Secret-Token`, Chatwoot `X-Chatwoot-Signature` + timestamp, Generic HMAC + timestamp) + persistent `channel_events` deduplication. | `channels/*.py`, `ledger.py` |
| **API Auth & Rate Limiting** | `/api/v1/*` requires constant-time Bearer or `X-API-Key` match against `TIJARAGUARD_API_KEY` (fail closed if unset); per-IP `SlidingWindowRateLimiter` returns HTTP `429` + `Retry-After`. | `api.py`, `security.py` |
| **CSV Formula Injection Defense** | `sanitize_csv_cell` neutralizes `=`, `+`, `-`, `@`, `\t`, `\r` in `/api/v1/audit/export.csv`. | `security.py`, `api.py` |
| **Secret & PII Log Redaction** | `SecretAndPIIRedactingLogFilter` and `scrub_secrets_from_text` mask API keys, Bearer tokens, Telegram bot tokens, and BayanGate PII from logs and exceptions. | `security.py` |

## 2. Honest Residual Boundaries & Non-Claims

1. **Single-Node SQLite Persistence**: SQLite WAL is single-node only; no horizontal multi-instance clustering claim is made.
2. **Tenant Boundaries**: Ledger and route tables partition records by `tenant_id`, and cross-customer/cross-channel target mismatches are blocked. Full production multi-tenant SaaS isolation (per-tenant KMS keys, independent rate quotas, independent process/DB isolation) has **not** been claimed or load-tested.
3. **BayanGate NER Scope**: `DATE_OF_BIRTH` and unstructured Arabic `PERSON_NAME` remain unsupported (`UNSUPPORTED_ENTITY_TYPES`) in `BayanGate`; operators should continue using pseudonymous `customer_handle` values.
4. **Delivery Semantics**: `MessageShield` + `EphemeralRouteStore` provides effectively-once logical processing for idempotent endpoints and conservative `UNKNOWN` reconciliation; universal exactly-once delivery across third-party gateways without idempotency/readback cannot be guaranteed.
5. **Host Filesystem Permissions**: `fuseblk`/NTFS mounts ignore POSIX `chmod 0600`/`0700`; production state must reside on a POSIX filesystem (`ext4`, `xfs`, etc.).
