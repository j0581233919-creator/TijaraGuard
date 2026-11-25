# TijaraGuard (Isolated Integration MVP)

**TijaraGuard** is an isolated, Python stdlib + SQLite integration prototype that enforces a 4-gate safety pipeline for Arabic and English customer support responses:

1. **Gate 1 — Privacy (`BayanGate`)**: Detects and redacts regional/MENA PII (Saudi National ID, Iqama, UAE Emirates ID, Egyptian ID, GCC IBAN, regional phone numbers, emails) *before* SQLite persistence, logging, exception formatting, or commercial drafting. Converts raw contact targets into irreversible HMAC-based `contact_ref` handles.
2. **Gate 2 — Commercial Verification (`CatalogCopilot`)**: Parses Arabic dialect inquiries (Gulf, Egyptian, Levantine, MSA), resolves catalog SKUs, validates documented consent-to-contact, and deterministically verifies prices, stock availability, currencies, active/expired discounts, and ungrounded commercial claims (plus outbound PII leak checks).
3. **Gate 3 — Human Approval (`ApprovalLedger`)**: Defaults strictly to **Shadow Mode (`SIMULATED_NO_SEND`)**, persisting state in SQLite WAL with an append-only hash-chained `audit_events` log and single-use HMAC-SHA256 approval leases bound cryptographically to `(draft_id, payload_sha256, lease_id)`.
4. **Gate 4 — Reliable Loopback Delivery (`MessageShield`)**: Integrates `MessageShield` for local loopback (`127.0.0.1` / `::1`) outbox dispatch with stable SHA-256 idempotency keys, read-only `GET /inbox/receipts/<key>` recovery from `UNKNOWN` after lost acknowledgments, and receiver-side SQLite `PRIMARY KEY(key)` deduplication.

## Quickstart

Run everything with bytecode writing disabled so the read-only sibling repositories remain completely untouched:

```bash
cd "/media/islam/shared pop/GitHub/tijaraguard-prototype"

# 1. Inspect read-only sibling dependencies
PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard inspect-deps

# 2. Run the complete 4-gate synthetic business demo
PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard demo

# 3. Run the deterministic unit & adversarial test suite
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
```

## Honest Scope & Known Limitations

- **No external runtime dependencies**: Standard library + SQLite only (`dependencies = []` in [pyproject.toml](pyproject.toml)). No external PyPI packages, Docker, PostgreSQL, or Redis.
- **No external channel connections**: No WhatsApp, Chatwoot, external LLMs, or internet hosts. Gate 4 is strictly restricted to literal loopback endpoints (`127.0.0.1` / `::1`).
- **No universal exactly-once delivery claim**: `MessageShield` plus `LocalLoopbackReceiver` provides receiver-side logical deduplication and conservative `UNKNOWN` reconciliation against a conforming loopback inbox; arbitrary third-party gateways without idempotent keys and truthful readback cannot be guaranteed exactly-once.
- **BayanGate NER scope**: `DATE_OF_BIRTH` and `PERSON_NAME` remain unsupported (`UNSUPPORTED_ENTITY_TYPES`) in `BayanGate`'s deterministic engine; callers must supply pseudonymous `customer_handle` labels rather than relying on free-text Arabic person-name redaction.
- **Host filesystem permissions**: On non-POSIX mounts such as `fuseblk` (`/media/islam/shared pop`), OS `chmod 0600` restrictions are ignored by the mount driver; runtime SQLite state in production must reside on a permissioned POSIX filesystem.

See [ARCHITECTURE.md](ARCHITECTURE.md), [INSTALL.md](INSTALL.md), and [verification/COMMANDS.md](verification/COMMANDS.md).
