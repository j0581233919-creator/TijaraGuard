# Installation & Operator Guide

## 1. Prerequisites

- Python `3.11` or newer (verified on Python `3.12.3` on Linux).
- Standard library + built-in SQLite only (`dependencies = []`, zero `pip` installs required).
- Works standalone from a fresh checkout using MIT-attributed vendored snapshots under `tijaraguard/_vendor/` (verified via `MANIFEST.json` SHA-256 checksums), or automatically uses read-only sibling repositories / `TIJARAGUARD_*_PATH` overrides when present.

## 2. Clean-Room Installation

```bash
git clone https://github.com/j0581233919-creator/TijaraGuard.git
cd TijaraGuard

# Optional editable or standard install into a virtualenv
python3 -m venv .venv
.venv/bin/python -B -m pip install --no-deps --no-build-isolation -e .

# Verify dependencies & bundled manifest integrity
PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard inspect-deps
```

### 2a. Installing from GitHub Release Wheel & Verifying Checksums

Download `tijaraguard-0.2.0b1-py3-none-any.whl` (or `tijaraguard-0.2.0b1.tar.gz`) and `SHA256SUMS.txt` from the GitHub prerelease (`v0.2.0-beta.1`), then verify integrity before installing offline (`dependencies = []`):

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
python3 -m venv .venv
.venv/bin/python -B -m pip install --no-deps tijaraguard-0.2.0b1-py3-none-any.whl
PYTHONDONTWRITEBYTECODE=1 .venv/bin/tijaraguard inspect-deps
```

## 3. CLI Reference

- `tijaraguard inspect-deps` — Inspect resolved dependencies (`sibling_repo` / `vendored`) and manifest checksums.
- `tijaraguard demo [--state-dir DIR]` — Run the 4-gate synthetic Arabic business demonstration.
- `tijaraguard verify-audit LEDGER_DB` — Verify triggers, sequence continuity, and SHA-256 hash chain read-only.
- `tijaraguard check-config` — Validate catalog, secret lengths, SSRF rules, providers, and channels.
- `tijaraguard serve [--host HOST] [--port PORT]` — Start REST API, webhooks, and operator web console (`/`).
- `tijaraguard catalog-search QUERY [--lang ar|en]` — Fuzzy catalog SKU resolution.
- `tijaraguard ingest --message-id ... --text ...` — Run Gate 1 -> Gate 2 -> Gate 3 on an inquiry.
- `tijaraguard drafts [--state STATE]` — List drafts from the ledger.
- `tijaraguard approve DRAFT_ID --reviewer ID --payload-sha256 HEX` — Issue single-use approval lease.
- `tijaraguard edit DRAFT_ID --actor ID --body TEXT` — Edit and re-verify draft (revokes old lease).
- `tijaraguard reject DRAFT_ID --reviewer ID --reason TEXT` — Reject draft.
- `tijaraguard escalate DRAFT_ID --actor ID --reason TEXT` — Escalate draft to human operator.
- `tijaraguard dispatch DRAFT_ID [--target TARGET]` — Consume active approval lease and dispatch.
- `tijaraguard recover DRAFT_ID` — Reconcile `UNKNOWN_DELIVERY` / `DISPATCHING` without replaying POST.
- `tijaraguard providers-health` — Check connectivity/auth on configured AI providers.
- `tijaraguard backup DEST_PATH` — Create a verified SQLite hot backup.
- `tijaraguard restore BACKUP_FILE TARGET_DB` — Verify backup audit chain and restore atomically.
- `tijaraguard purge-retention` — Apply data retention purge to expired terminal drafts and replay keys.
