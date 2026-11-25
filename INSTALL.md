# Installation & Operator Guide

## 1. Prerequisites

- Python `3.11` or newer (tested on Python `3.12.3` on Linux).
- Standard library + built-in SQLite only (`dependencies = []`, zero `pip` installs required).
- Read-only local sibling checkouts expected next to this directory:
  - `../bayan-gate/repo` (`BayanGate`)
  - `../catalog-copilot/repo` (`CatalogCopilot`)
  - `../message-shield/repo` (`MessageShield`)

If the sibling repositories live elsewhere, override their paths using environment variables:

```bash
export TIJARAGUARD_BAYAN_GATE_PATH="/path/to/bayan-gate/repo"
export TIJARAGUARD_CATALOG_COPILOT_PATH="/path/to/catalog-copilot/repo"
export TIJARAGUARD_MESSAGE_SHIELD_PATH="/path/to/message-shield/repo"
```

## 2. Running Without Modifying Dependency Repositories

Always invoke Python with `-B` and `PYTHONDONTWRITEBYTECODE=1` so Python does not write `__pycache__` directories into the read-only dependency repositories (TijaraGuard also sets `sys.dont_write_bytecode = True` on import as defense-in-depth).

```bash
cd "/media/islam/shared pop/GitHub/tijaraguard-prototype"
PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard inspect-deps
```

## 3. CLI Operations

### Run the Complete Synthetic Demonstration

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard demo --state-dir .state/my-demo
```

This creates isolated SQLite databases in `.state/my-demo/` and outputs JSON summarizing:
- Gate 1 PII redaction + Shadow Mode (`SIMULATED_NO_SEND`)
- Gate 2 adversarial LLM hallucination blocking
- Gate 3 post-approval payload tampering detection
- Gate 4 lost-ACK (`drop_ack=True`) -> `UNKNOWN` -> read-only recovery (`DELIVERED`, 1 logical inbox row, 1 POST attempt)
- Hash-chain audit verification and zero-PII leak counts

### Verify an Existing Ledger Audit Chain

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard verify-audit .state/my-demo/ledger.sqlite3
```

## 4. Operator Security Notes

- Keep `approval_secret` and `contact_hash_key` out of source control and supply >= 32 cryptographically random bytes at runtime.
- Never place SQLite ledger/outbox state on world-writable shared filesystems in production; use a private POSIX directory (`0700`) and restricted file permissions (`0600`). Note that `fuseblk`/NTFS mounts ignore POSIX `chmod`.
- Never manually clear `UNKNOWN_DELIVERY` records or invent new message IDs to force a retry; always reconcile via `recover_delivery()`.
