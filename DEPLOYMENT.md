# TijaraGuard Deployment & Operations Guide

## 1. Deployment Topologies

TijaraGuard uses Python `3.11+` standard library + SQLite WAL (`dependencies = []`) and runs cleanly on:
1. **Local Self-Hosted Workstation / Server** (`127.0.0.1:8080`)
2. **Linux VPS / Cloud VM** behind a TLS reverse proxy (`deploy/tijaraguard.service` + `deploy/nginx-tijaraguard.conf`)
3. **Optional Container Deployment** (`deploy/Dockerfile`)

> **Important Concurrency & Scaling Boundary:** SQLite WAL provides durable single-node ACID persistence with `BEGIN IMMEDIATE` write serialization. It is designed for single-node deployments and **does not** provide horizontally scalable multi-instance shared storage. Do not mount the same SQLite directory across multiple container replicas over NFS/network filesystems.

---

## 2. Linux VPS / Cloud Server Setup

1. Create a dedicated system user and private POSIX state directory (`0700`):
   ```bash
   sudo useradd --system --no-create-home tijaraguard
   sudo mkdir -p /opt/tijaraguard /etc/tijaraguard /var/lib/tijaraguard/backups
   sudo chown -R tijaraguard:tijaraguard /var/lib/tijaraguard
   sudo chmod 0700 /var/lib/tijaraguard
   ```
2. Install TijaraGuard from a clean checkout or wheel:
   ```bash
   cd /opt/tijaraguard
   python3 -B -m pip install --no-deps --no-build-isolation .
   ```
3. Copy `.env.example` to `/etc/tijaraguard/tijaraguard.env` (`chmod 0600`), generate 32-byte random secrets (`openssl rand -hex 32`), and configure your cloud AI provider(s) and messaging channel(s).
4. Validate startup configuration before starting the service:
   ```bash
   set -a && source /etc/tijaraguard/tijaraguard.env && set +a
   PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard check-config
   ```
5. Install `deploy/tijaraguard.service` and put `deploy/nginx-tijaraguard.conf` (with valid TLS certificates) in front of `127.0.0.1:8080`. Never expose plain HTTP over the public internet.

---

## 3. Backup, Restore & Data Retention

### Hot WAL Backup
```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard backup /var/lib/tijaraguard/backups/ledger-$(date -u +%Y%m%dT%H%M%SZ).sqlite3
```
`backup` uses SQLite's online `Connection.backup()` API, runs `verify_audit_database_readonly()` on the resulting snapshot, and prints its SHA-256 digest.

### Verified Restore
Stop the TijaraGuard service first, then restore:
```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard restore /path/to/backup.sqlite3 /var/lib/tijaraguard/ledger.sqlite3
```
`restore` verifies the backup's audit hash chain and immutability triggers before atomically replacing the target database and removing stale `-wal`/`-shm` sidecars.

### Retention Purge
```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m tijaraguard purge-retention
```
Redacts expired `redacted_inquiry` and `consent_evidence` fields on terminal drafts (`DELIVERED`, `REJECTED`, `SHADOW_RECORDED`, `FAILED_DELIVERY`) and prunes old channel replay keys while leaving pending/approved drafts and `audit_events` untouched.
