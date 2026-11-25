"""Gate 3 — SQLite WAL approval ledger, Shadow Mode gate, migrations, and append-only audit trail."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .models import (
    ApprovalAlreadyConsumedError,
    ApprovalExpiredError,
    ApprovalRequiredError,
    ApprovalTamperError,
    ApprovalToken,
    CommercialEvaluation,
    DraftState,
    ExecutionMode,
    MalformedInputError,
    RedactedEnvelope,
    VerificationBlockedError,
    canonical_json,
    canonical_sha256,
    is_valid_sha256_hex,
    sha256_hex,
    validate_safe_id,
)
from .security import harden_state_permissions

_GENESIS_HASH = "0" * 64
_VALID_STATES_SQL = ",".join(f"'{s.value}'" for s in DraftState)
_LATEST_SCHEMA_VERSION = 2

_SCHEMA_V2 = f"""
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS drafts (
    draft_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    message_id TEXT NOT NULL UNIQUE,
    conversation_id TEXT NOT NULL,
    customer_handle TEXT NOT NULL,
    contact_ref TEXT NOT NULL,
    contact_channel TEXT NOT NULL,
    sku TEXT,
    language TEXT NOT NULL,
    redacted_inquiry TEXT NOT NULL,
    pii_summary_json TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    consent_to_contact INTEGER NOT NULL CHECK(consent_to_contact IN (0, 1)),
    consent_evidence TEXT NOT NULL,
    verification_status TEXT NOT NULL,
    verification_report_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ({_VALID_STATES_SQL})),
    delivery_key TEXT UNIQUE,
    receipt_id TEXT,
    ai_provider TEXT,
    ai_model TEXT,
    ai_metadata_json TEXT NOT NULL DEFAULT '{{}}',
    channel_metadata_json TEXT NOT NULL DEFAULT '{{}}',
    escalation_reason TEXT,
    retention_expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_drafts_tenant_state
    ON drafts(tenant_id, state, created_at);

CREATE INDEX IF NOT EXISTS idx_drafts_tenant_conv
    ON drafts(tenant_id, conversation_id);

CREATE INDEX IF NOT EXISTS idx_drafts_receipt_id
    ON drafts(tenant_id, receipt_id);

CREATE TABLE IF NOT EXISTS approvals (
    lease_id TEXT PRIMARY KEY,
    draft_id TEXT NOT NULL REFERENCES drafts(draft_id),
    payload_sha256 TEXT NOT NULL,
    reviewer_id TEXT NOT NULL,
    notes TEXT NOT NULL,
    approved_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    approval_mac TEXT NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0, 1)),
    consumed_at REAL,
    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
    revoked_reason TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_approval
    ON approvals(draft_id) WHERE consumed = 0 AND revoked = 0;

CREATE TABLE IF NOT EXISTS audit_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    draft_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload_sha256 TEXT,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE
);

CREATE TRIGGER IF NOT EXISTS audit_events_no_update
    BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
    BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TABLE IF NOT EXISTS channel_events (
    event_key TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    channel TEXT NOT NULL,
    external_event_id TEXT NOT NULL,
    conversation_id TEXT,
    received_at REAL NOT NULL,
    status TEXT NOT NULL,
    draft_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_channel_events_received
    ON channel_events(received_at);

CREATE TABLE IF NOT EXISTS provider_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    draft_id TEXT,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    task_tier TEXT NOT NULL,
    status TEXT NOT NULL,
    error_category TEXT,
    latency_ms REAL NOT NULL,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    total_tokens INTEGER,
    estimated_cost_usd REAL,
    fallback_from TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_provider_usage_tenant
    ON provider_usage(tenant_id, created_at);
"""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _retention_expiry_iso(days: int) -> str:
    days_clamped = max(1, int(days))
    return (datetime.now(timezone.utc) + timedelta(days=days_clamped)).isoformat()


def compute_draft_payload_sha256(row_or_fields: Dict[str, Any]) -> str:
    """Computes the canonical SHA-256 bound to an approved draft payload."""
    canonical_payload = {
        "draft_id": row_or_fields["draft_id"],
        "sku": row_or_fields.get("sku"),
        "language": row_or_fields["language"],
        "subject": row_or_fields["subject"],
        "body": row_or_fields["body"],
        "contact_ref": row_or_fields["contact_ref"],
        "contact_channel": row_or_fields["contact_channel"],
        "consent_to_contact": bool(int(row_or_fields["consent_to_contact"])),
        "consent_evidence": str(row_or_fields.get("consent_evidence") or ""),
        "verification_status": row_or_fields["verification_status"],
    }
    return canonical_sha256(canonical_payload)


_ALLOWED_DELIVERY_TRANSITIONS: Dict[str, set[str]] = {
    DraftState.DISPATCHING.value: {
        DraftState.ACCEPTED_DELIVERY.value,
        DraftState.UNKNOWN_DELIVERY.value,
        DraftState.FAILED_DELIVERY.value,
    },
    DraftState.UNKNOWN_DELIVERY.value: {
        DraftState.ACCEPTED_DELIVERY.value,
        DraftState.FAILED_DELIVERY.value,
    },
    DraftState.ACCEPTED_DELIVERY.value: {
        DraftState.DELIVERED.value,
        DraftState.FAILED_DELIVERY.value,
    },
}


def verify_audit_database_readonly(db_path: str | Path) -> Tuple[bool, int, List[str]]:
    """Verifies table/trigger presence, tail consistency, and hash chain read-only."""
    resolved = Path(db_path).resolve()
    if not resolved.is_file():
        return False, 0, [f"Ledger database not found: {resolved}"]

    errors: List[str] = []
    event_count = 0
    wal_path = Path(f"{resolved}-wal")
    has_live_wal = wal_path.is_file() and wal_path.stat().st_size > 0
    uri = f"{resolved.as_uri()}?mode=ro" if has_live_wal else f"{resolved.as_uri()}?mode=ro&immutable=1"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
    except sqlite3.DatabaseError as exc:
        return False, 0, [f"Failed to open SQLite database read-only: {exc}"]

    try:
        tables = {
            r["name"]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if not {"drafts", "approvals", "audit_events"}.issubset(tables):
            errors.append("Missing required ledger tables (drafts, approvals, audit_events).")
            return False, 0, errors

        triggers = {
            r["name"]: re.sub(r"\s+", " ", (r["sql"] or "").strip()).upper()
            for r in conn.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='trigger' AND tbl_name='audit_events'"
            ).fetchall()
        }
        expected_triggers = {
            "audit_events_no_update": "BEFORE UPDATE ON AUDIT_EVENTS",
            "audit_events_no_delete": "BEFORE DELETE ON AUDIT_EVENTS",
        }
        for req_trig, required_clause in expected_triggers.items():
            trig_sql = triggers.get(req_trig)
            if (
                not trig_sql
                or required_clause not in trig_sql
                or " WHEN " in trig_sql
                or " WHERE " in trig_sql
                or "RAISE(ABORT" not in trig_sql
                or not re.search(
                    rf"{re.escape(required_clause)}\s+(?:FOR EACH ROW\s+)?BEGIN\s+SELECT\s+RAISE\s*\(\s*ABORT\s*,[^)]+\)\s*;\s*END$",
                    trig_sql,
                )
            ):
                errors.append(f"Missing or weakened immutability trigger: {req_trig}")

        draft_count = int(conn.execute("SELECT COUNT(*) FROM drafts").fetchone()[0])
        rows = conn.execute("SELECT * FROM audit_events ORDER BY seq ASC").fetchall()
        event_count = len(rows)

        if draft_count > 0 and event_count == 0:
            errors.append("Draft records exist with zero audit_events (missing history).")

        if "sqlite_sequence" in tables:
            seq_row = conn.execute(
                "SELECT seq FROM sqlite_sequence WHERE name='audit_events'"
            ).fetchone()
            if seq_row is not None:
                recorded_seq = int(seq_row["seq"])
                max_row_seq = int(rows[-1]["seq"]) if rows else 0
                if recorded_seq != max_row_seq:
                    errors.append(
                        f"Audit tail deletion suspected: sqlite_sequence={recorded_seq}, max_seq={max_row_seq}"
                    )

        expected_prev = _GENESIS_HASH
        for idx, row in enumerate(rows, start=1):
            if row["seq"] != idx:
                errors.append(f"Sequence gap at row {idx}: got seq={row['seq']}")
            if (
                not is_valid_sha256_hex(row["prev_hash"])
                or not is_valid_sha256_hex(expected_prev)
                or not hmac.compare_digest(row["prev_hash"].lower(), expected_prev.lower())
            ):
                errors.append(f"Chain break at seq={row['seq']}: prev_hash mismatch")
            if not is_valid_sha256_hex(row["event_hash"]):
                errors.append(f"Invalid non-hex event_hash at seq={row['seq']}")
                expected_prev = str(row["event_hash"])
                continue
            recomputed = _compute_audit_event_hash(
                draft_id=row["draft_id"],
                event_type=row["event_type"],
                from_state=row["from_state"],
                to_state=row["to_state"],
                actor=row["actor"],
                payload_sha256=row["payload_sha256"],
                details_json=row["details_json"],
                created_at=row["created_at"],
                prev_hash=row["prev_hash"],
            )
            if not hmac.compare_digest(recomputed.lower(), row["event_hash"].lower()):
                errors.append(f"Tampered audit event digest at seq={row['seq']}")
            expected_prev = row["event_hash"]
    except sqlite3.DatabaseError as exc:
        errors.append(f"SQLite verification error: {exc}")
    finally:
        conn.close()

    return len(errors) == 0, event_count, errors


def compute_approval_mac(
    secret: bytes,
    *,
    lease_id: str,
    draft_id: str,
    payload_sha256: str,
    reviewer_id: str,
    approved_at: float,
    expires_at: float,
) -> str:
    """Computes HMAC-SHA256 binding lease identity, reviewer, expiry, and draft payload."""
    signing_doc = canonical_json(
        {
            "lease_id": lease_id,
            "draft_id": draft_id,
            "payload_sha256": payload_sha256,
            "reviewer_id": reviewer_id,
            "approved_at_us": round(approved_at * 1_000_000),
            "expires_at_us": round(expires_at * 1_000_000),
        }
    )
    return hmac.new(secret, signing_doc.encode("utf-8"), hashlib.sha256).hexdigest()


def _compute_audit_event_hash(
    *,
    draft_id: str,
    event_type: str,
    from_state: Optional[str],
    to_state: str,
    actor: str,
    payload_sha256: Optional[str],
    details_json: str,
    created_at: str,
    prev_hash: str,
) -> str:
    doc = canonical_json(
        {
            "draft_id": draft_id,
            "event_type": event_type,
            "from_state": from_state,
            "to_state": to_state,
            "actor": actor,
            "payload_sha256": payload_sha256,
            "details_json": details_json,
            "created_at": created_at,
            "prev_hash": prev_hash,
        }
    )
    return sha256_hex(doc)


def restore_ledger_backup(backup_path: str | Path, target_db_path: str | Path) -> Dict[str, Any]:
    """Verifies a ledger backup read-only and atomically restores it to target_db_path."""
    src = Path(backup_path).resolve()
    dst = Path(target_db_path).resolve()
    valid, event_count, errors = verify_audit_database_readonly(src)
    if not valid:
        raise MalformedInputError(f"Backup failed audit verification: {'; '.join(errors)}")

    dst.parent.mkdir(parents=True, exist_ok=True)
    harden_state_permissions(dst.parent, is_dir=True)
    tmp_dst = dst.with_name(f".{dst.name}.restore.{os.getpid()}.{secrets.token_hex(6)}.tmp")
    shutil.copy2(src, tmp_dst)
    os.replace(tmp_dst, dst)
    for sidecar in (Path(f"{dst}-wal"), Path(f"{dst}-shm")):
        if sidecar.exists():
            sidecar.unlink()
    perm_info = harden_state_permissions(dst, is_dir=False)
    return {
        "restored": True,
        "backup_path": str(src),
        "target_db_path": str(dst),
        "event_count": event_count,
        "sha256": hashlib.sha256(dst.read_bytes()).hexdigest(),
        "permissions": perm_info,
    }


class ApprovalLedger:
    """Durable SQLite WAL approval ledger with single-use cryptographic approval leases."""

    def __init__(self, db_path: str | Path, approval_secret: bytes) -> None:
        if not isinstance(approval_secret, (bytes, bytearray)) or len(approval_secret) < 16:
            raise MalformedInputError("approval_secret must be bytes of at least 16 bytes.")
        self.db_path = Path(db_path).resolve()
        self._secret = bytes(approval_secret)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        harden_state_permissions(self.db_path.parent, is_dir=True)
        self._initialize_schema()
        harden_state_permissions(self.db_path, is_dir=False)

    def _initialize_schema(self) -> None:
        with self._connect(write=False) as conn:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            if str(mode).lower() != "wal":
                conn.execute("PRAGMA journal_mode=WAL")
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            tables = {
                r["name"]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if version == 0 and "drafts" not in tables:
                conn.executescript(_SCHEMA_V2)
                conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations(version, applied_at, description) VALUES (?, ?, ?)",
                    (_LATEST_SCHEMA_VERSION, _utc_now_iso(), "Initial v2 schema"),
                )
                conn.execute(f"PRAGMA user_version = {_LATEST_SCHEMA_VERSION}")
                return
            if version >= 2:
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_drafts_receipt_id ON drafts(tenant_id, receipt_id)"
                )

        if version < 2:
            self._migrate_v1_to_v2()

    def _migrate_v1_to_v2(self) -> None:
        """Migrates a v1 ledger database cleanly to v2 without touching audit_events."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute("BEGIN IMMEDIATE")

            current_ver = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if current_ver >= 2:
                conn.commit()
                return

            conn.execute(
                f"""
                CREATE TABLE drafts_v2 (
                    draft_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    message_id TEXT NOT NULL UNIQUE,
                    conversation_id TEXT NOT NULL,
                    customer_handle TEXT NOT NULL,
                    contact_ref TEXT NOT NULL,
                    contact_channel TEXT NOT NULL,
                    sku TEXT,
                    language TEXT NOT NULL,
                    redacted_inquiry TEXT NOT NULL,
                    pii_summary_json TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    body TEXT NOT NULL,
                    consent_to_contact INTEGER NOT NULL CHECK(consent_to_contact IN (0, 1)),
                    consent_evidence TEXT NOT NULL,
                    verification_status TEXT NOT NULL,
                    verification_report_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ({_VALID_STATES_SQL})),
                    delivery_key TEXT UNIQUE,
                    receipt_id TEXT,
                    ai_provider TEXT,
                    ai_model TEXT,
                    ai_metadata_json TEXT NOT NULL DEFAULT '{{}}',
                    channel_metadata_json TEXT NOT NULL DEFAULT '{{}}',
                    escalation_reason TEXT,
                    retention_expires_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                INSERT INTO drafts_v2(
                    draft_id, tenant_id, message_id, conversation_id, customer_handle,
                    contact_ref, contact_channel, sku, language, redacted_inquiry,
                    pii_summary_json, subject, body, consent_to_contact, consent_evidence,
                    verification_status, verification_report_json, payload_sha256, state,
                    delivery_key, receipt_id, ai_provider, ai_model, ai_metadata_json,
                    channel_metadata_json, escalation_reason, retention_expires_at,
                    created_at, updated_at
                )
                SELECT
                    draft_id, 'default', message_id, conversation_id, customer_handle,
                    contact_ref, contact_channel, sku, language, redacted_inquiry,
                    pii_summary_json, subject, body, consent_to_contact, consent_evidence,
                    verification_status, verification_report_json, payload_sha256, state,
                    delivery_key, receipt_id, NULL, NULL, '{}', '{}', NULL, NULL,
                    created_at, updated_at
                FROM drafts
                """
            )
            conn.execute("DROP TABLE drafts")
            conn.execute("ALTER TABLE drafts_v2 RENAME TO drafts")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_drafts_tenant_state ON drafts(tenant_id, state, created_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_drafts_tenant_conv ON drafts(tenant_id, conversation_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_drafts_receipt_id ON drafts(tenant_id, receipt_id)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL,
                    description TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS channel_events (
                    event_key TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    channel TEXT NOT NULL,
                    external_event_id TEXT NOT NULL,
                    conversation_id TEXT,
                    received_at REAL NOT NULL,
                    status TEXT NOT NULL,
                    draft_id TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_channel_events_received ON channel_events(received_at)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS provider_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    draft_id TEXT,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    task_tier TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error_category TEXT,
                    latency_ms REAL NOT NULL,
                    prompt_tokens INTEGER,
                    completion_tokens INTEGER,
                    total_tokens INTEGER,
                    estimated_cost_usd REAL,
                    fallback_from TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_provider_usage_tenant ON provider_usage(tenant_id, created_at)"
            )
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at, description) VALUES (?, ?, ?)",
                (2, _utc_now_iso(), "Migrate v1 drafts/ledger to v2 product schema"),
            )
            conn.execute("PRAGMA user_version = 2")
            fk_issues = conn.execute("PRAGMA foreign_key_check").fetchall()
            if fk_issues:
                raise MalformedInputError("Foreign key check failed during v1->v2 migration.")
            conn.commit()
            conn.execute("PRAGMA foreign_keys=ON")
        except BaseException:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    @contextmanager
    def _connect(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA busy_timeout=5000")
            if write:
                conn.execute("BEGIN IMMEDIATE")
            yield conn
            if write:
                conn.commit()
        except BaseException:
            if write:
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass
            raise
        finally:
            conn.close()

    def _append_audit_event(
        self,
        conn: sqlite3.Connection,
        *,
        draft_id: str,
        event_type: str,
        from_state: Optional[str],
        to_state: str,
        actor: str,
        payload_sha256: Optional[str],
        details: Dict[str, Any],
    ) -> None:
        last_row = conn.execute(
            "SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_hash = last_row["event_hash"] if last_row else _GENESIS_HASH
        created_at = _utc_now_iso()
        details_json = canonical_json(details)
        event_hash = _compute_audit_event_hash(
            draft_id=draft_id,
            event_type=event_type,
            from_state=from_state,
            to_state=to_state,
            actor=actor,
            payload_sha256=payload_sha256,
            details_json=details_json,
            created_at=created_at,
            prev_hash=prev_hash,
        )
        conn.execute(
            """
            INSERT INTO audit_events(
                draft_id, event_type, from_state, to_state, actor,
                payload_sha256, details_json, created_at, prev_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                draft_id,
                event_type,
                from_state,
                to_state,
                actor,
                payload_sha256,
                details_json,
                created_at,
                prev_hash,
                event_hash,
            ),
        )

    def record_ingested_draft(
        self,
        envelope: RedactedEnvelope,
        evaluation: CommercialEvaluation,
        *,
        retention_days: int = 30,
    ) -> Dict[str, Any]:
        """Persists redacted inquiry + commercial evaluation into the ledger."""
        now_iso = _utc_now_iso()
        ret_exp = _retention_expiry_iso(retention_days)
        consent_ok = bool(envelope.consent_to_contact and envelope.consent_evidence.strip())
        target_state = (
            DraftState.PENDING_APPROVAL.value
            if evaluation.verification_status == "PASS" and consent_ok
            else DraftState.VERIFIED_BLOCKED.value
        )

        payload_sha256 = compute_draft_payload_sha256(
            {
                "draft_id": evaluation.draft_id,
                "sku": evaluation.sku,
                "language": evaluation.language,
                "subject": evaluation.subject,
                "body": evaluation.body,
                "contact_ref": envelope.contact_ref,
                "contact_channel": envelope.contact_channel,
                "consent_to_contact": 1 if envelope.consent_to_contact else 0,
                "consent_evidence": envelope.consent_evidence,
                "verification_status": evaluation.verification_status,
            }
        )

        try:
            with self._connect(write=True) as conn:
                conn.execute(
                    """
                    INSERT INTO drafts(
                        draft_id, tenant_id, message_id, conversation_id, customer_handle, contact_ref,
                        contact_channel, sku, language, redacted_inquiry, pii_summary_json,
                        subject, body, consent_to_contact, consent_evidence,
                        verification_status, verification_report_json, payload_sha256,
                        state, ai_provider, ai_model, ai_metadata_json, channel_metadata_json,
                        retention_expires_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evaluation.draft_id,
                        envelope.tenant_id,
                        envelope.message_id,
                        envelope.conversation_id,
                        envelope.customer_handle,
                        envelope.contact_ref,
                        envelope.contact_channel,
                        evaluation.sku,
                        evaluation.language,
                        envelope.redacted_text,
                        canonical_json(envelope.pii_summary),
                        evaluation.subject,
                        evaluation.body,
                        1 if envelope.consent_to_contact else 0,
                        envelope.consent_evidence,
                        evaluation.verification_status,
                        canonical_json(evaluation.verification_report_dict),
                        payload_sha256,
                        target_state,
                        evaluation.ai_provider,
                        evaluation.ai_model,
                        canonical_json(evaluation.ai_metadata or {}),
                        canonical_json(envelope.channel_metadata or {}),
                        ret_exp,
                        now_iso,
                        now_iso,
                    ),
                )

                self._append_audit_event(
                    conn,
                    draft_id=evaluation.draft_id,
                    event_type="DRAFT_INGESTED",
                    from_state=None,
                    to_state=DraftState.INGESTED.value,
                    actor="gate1_privacy",
                    payload_sha256=payload_sha256,
                    details={
                        "tenant_id": envelope.tenant_id,
                        "message_id": envelope.message_id,
                        "contact_ref": envelope.contact_ref,
                        "pii_entity_count": envelope.pii_summary.get("entity_count", 0),
                    },
                )
                self._append_audit_event(
                    conn,
                    draft_id=evaluation.draft_id,
                    event_type="VERIFICATION_RECORDED",
                    from_state=DraftState.INGESTED.value,
                    to_state=target_state,
                    actor="gate2_commerce",
                    payload_sha256=payload_sha256,
                    details={
                        "verification_status": evaluation.verification_status,
                        "reason_count": len(evaluation.reasons),
                        "reasons": evaluation.reasons,
                        "detected_dialect": evaluation.detected_dialect,
                        "sku": evaluation.sku,
                        "ai_provider": evaluation.ai_provider,
                        "ai_model": evaluation.ai_model,
                    },
                )
                row = conn.execute(
                    "SELECT * FROM drafts WHERE draft_id=?", (evaluation.draft_id,)
                ).fetchone()
                return dict(row)
        except sqlite3.IntegrityError as exc:
            raise VerificationBlockedError(
                f"Duplicate message_id '{envelope.message_id}' or draft conflict."
            ) from exc

    def get_draft(self, draft_id: str, *, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Fetches a draft record by draft_id (optionally scoped to tenant_id)."""
        with self._connect(write=False) as conn:
            if tenant_id is not None:
                row = conn.execute(
                    "SELECT * FROM drafts WHERE draft_id=? AND tenant_id=?",
                    (draft_id, tenant_id),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM drafts WHERE draft_id=?", (draft_id,)
                ).fetchone()
            if row is None:
                raise MalformedInputError(f"Unknown draft_id '{draft_id}'.")
            return dict(row)

    def get_draft_by_receipt_id(
        self,
        receipt_id: str,
        *,
        tenant_id: Optional[str] = None,
        channel: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Looks up a draft by its normalized MessageShield receipt_id."""
        clauses = ["receipt_id=?"]
        params: List[Any] = [receipt_id]
        if tenant_id is not None:
            clauses.append("tenant_id=?")
            params.append(tenant_id)
        if channel is not None:
            clauses.append("contact_channel=?")
            params.append(channel.strip().lower())
        with self._connect(write=False) as conn:
            row = conn.execute(
                f"SELECT * FROM drafts WHERE {' AND '.join(clauses)} LIMIT 1",
                tuple(params),
            ).fetchone()
            return dict(row) if row is not None else None

    def list_drafts(
        self,
        *,
        tenant_id: Optional[str] = None,
        state: Optional[str] = None,
        conversation_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Lists draft records with optional tenant, state, and conversation filters."""
        clauses: List[str] = []
        params: List[Any] = []
        if tenant_id is not None:
            clauses.append("tenant_id=?")
            params.append(tenant_id)
        if state is not None:
            clauses.append("state=?")
            params.append(state)
        if conversation_id is not None:
            clauses.append("conversation_id=?")
            params.append(conversation_id)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        lim = max(1, min(500, int(limit)))
        off = max(0, int(offset))
        with self._connect(write=False) as conn:
            rows = conn.execute(
                f"SELECT * FROM drafts {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (*params, lim, off),
            ).fetchall()
            return [dict(r) for r in rows]

    def list_conversations(
        self,
        *,
        tenant_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Lists conversation summaries grouped by (tenant_id, conversation_id)."""
        lim = max(1, min(500, int(limit)))
        with self._connect(write=False) as conn:
            if tenant_id is not None:
                rows = conn.execute(
                    """
                    SELECT tenant_id, conversation_id, contact_channel, contact_ref,
                           COUNT(*) AS draft_count,
                           MAX(updated_at) AS last_updated_at
                    FROM drafts
                    WHERE tenant_id=?
                    GROUP BY tenant_id, conversation_id
                    ORDER BY last_updated_at DESC
                    LIMIT ?
                    """,
                    (tenant_id, lim),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT tenant_id, conversation_id, contact_channel, contact_ref,
                           COUNT(*) AS draft_count,
                           MAX(updated_at) AS last_updated_at
                    FROM drafts
                    GROUP BY tenant_id, conversation_id
                    ORDER BY last_updated_at DESC
                    LIMIT ?
                    """,
                    (lim,),
                ).fetchall()
            return [dict(r) for r in rows]

    def get_state_counts(self, *, tenant_id: Optional[str] = None) -> Dict[str, int]:
        """Returns draft counts per DraftState."""
        counts = {s.value: 0 for s in DraftState}
        with self._connect(write=False) as conn:
            if tenant_id is not None:
                rows = conn.execute(
                    "SELECT state, COUNT(*) AS c FROM drafts WHERE tenant_id=? GROUP BY state",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT state, COUNT(*) AS c FROM drafts GROUP BY state"
                ).fetchall()
            for r in rows:
                counts[r["state"]] = int(r["c"])
        return counts

    def get_active_approval(self, draft_id: str) -> Optional[Dict[str, Any]]:
        """Returns active unconsumed/unrevoked approval row if present."""
        with self._connect(write=False) as conn:
            row = conn.execute(
                "SELECT * FROM approvals WHERE draft_id=? AND consumed=0 AND revoked=0",
                (draft_id,),
            ).fetchone()
            return dict(row) if row is not None else None

    def approve_draft(
        self,
        draft_id: str,
        reviewer_id: str,
        expected_payload_sha256: str,
        *,
        notes: str = "",
        ttl_seconds: int = 900,
    ) -> ApprovalToken:
        """Issues a cryptographic single-use human approval lease bound to payload_sha256."""
        if not isinstance(reviewer_id, str) or not reviewer_id.strip():
            raise MalformedInputError("reviewer_id must be a non-empty string.")
        if not isinstance(notes, str):
            raise MalformedInputError("notes must be a string.")
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 86400:
            raise MalformedInputError("ttl_seconds must be an integer between 1 and 86400.")
        if not is_valid_sha256_hex(expected_payload_sha256):
            raise MalformedInputError("expected_payload_sha256 must be a 64-char SHA-256 hex digest.")

        with self._connect(write=True) as conn:
            row = conn.execute(
                "SELECT * FROM drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if row is None:
                raise MalformedInputError(f"Unknown draft_id '{draft_id}'.")
            draft = dict(row)

            if draft["state"] != DraftState.PENDING_APPROVAL.value:
                raise VerificationBlockedError(
                    f"Draft '{draft_id}' is in state '{draft['state']}', cannot approve."
                )
            if draft["verification_status"] != "PASS":
                raise VerificationBlockedError(
                    f"Draft '{draft_id}' failed commercial verification."
                )
            if draft["consent_to_contact"] != 1 or not str(draft["consent_evidence"]).strip():
                raise VerificationBlockedError(
                    f"Draft '{draft_id}' lacks documented consent to contact."
                )

            live_hash = compute_draft_payload_sha256(draft)
            if not is_valid_sha256_hex(draft["payload_sha256"]) or not hmac.compare_digest(
                live_hash, draft["payload_sha256"].lower()
            ):
                raise ApprovalTamperError("Stored draft payload digest mismatch prior to approval.")
            if not hmac.compare_digest(live_hash, expected_payload_sha256.lower()):
                raise ApprovalTamperError(
                    "Reviewer expected_payload_sha256 does not match current draft payload."
                )

            approved_at = time.time()
            expires_at = approved_at + float(ttl_seconds)
            lease_id = f"LEASE-{secrets.token_hex(12).upper()}"
            mac = compute_approval_mac(
                self._secret,
                lease_id=lease_id,
                draft_id=draft_id,
                payload_sha256=live_hash,
                reviewer_id=reviewer_id.strip(),
                approved_at=approved_at,
                expires_at=expires_at,
            )

            conn.execute(
                """
                INSERT INTO approvals(
                    lease_id, draft_id, payload_sha256, reviewer_id, notes,
                    approved_at, expires_at, approval_mac, consumed, revoked
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
                """,
                (
                    lease_id,
                    draft_id,
                    live_hash,
                    reviewer_id.strip(),
                    str(notes or ""),
                    approved_at,
                    expires_at,
                    mac,
                ),
            )
            conn.execute(
                "UPDATE drafts SET state=?, updated_at=? WHERE draft_id=?",
                (DraftState.APPROVED.value, _utc_now_iso(), draft_id),
            )
            self._append_audit_event(
                conn,
                draft_id=draft_id,
                event_type="HUMAN_APPROVED",
                from_state=DraftState.PENDING_APPROVAL.value,
                to_state=DraftState.APPROVED.value,
                actor=reviewer_id.strip(),
                payload_sha256=live_hash,
                details={"lease_id": lease_id, "ttl_seconds": ttl_seconds},
            )

            return ApprovalToken(
                lease_id=lease_id,
                draft_id=draft_id,
                payload_sha256=live_hash,
                reviewer_id=reviewer_id.strip(),
                approved_at=approved_at,
                expires_at=expires_at,
                approval_mac=mac,
            )

    def reject_draft(self, draft_id: str, reviewer_id: str, reason: str) -> Dict[str, Any]:
        """Rejects a draft and revokes any unconsumed approval lease."""
        if not isinstance(reviewer_id, str) or not reviewer_id.strip():
            raise MalformedInputError("reviewer_id must be a non-empty string.")
        if not isinstance(reason, str):
            raise MalformedInputError("reason must be a string.")
        with self._connect(write=True) as conn:
            row = conn.execute(
                "SELECT * FROM drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if row is None:
                raise MalformedInputError(f"Unknown draft_id '{draft_id}'.")
            from_state = row["state"]
            if from_state not in (
                DraftState.PENDING_APPROVAL.value,
                DraftState.VERIFIED_BLOCKED.value,
                DraftState.APPROVED.value,
                DraftState.ESCALATED.value,
            ):
                raise VerificationBlockedError(
                    f"Draft '{draft_id}' in state '{from_state}' cannot be rejected."
                )

            conn.execute(
                """
                UPDATE approvals SET revoked=1, revoked_reason='HUMAN_REJECTED'
                WHERE draft_id=? AND consumed=0 AND revoked=0
                """,
                (draft_id,),
            )
            conn.execute(
                "UPDATE drafts SET state=?, updated_at=? WHERE draft_id=?",
                (DraftState.REJECTED.value, _utc_now_iso(), draft_id),
            )
            self._append_audit_event(
                conn,
                draft_id=draft_id,
                event_type="HUMAN_REJECTED",
                from_state=from_state,
                to_state=DraftState.REJECTED.value,
                actor=reviewer_id.strip(),
                payload_sha256=row["payload_sha256"],
                details={"reason": str(reason or "rejected")},
            )
            return dict(
                conn.execute("SELECT * FROM drafts WHERE draft_id=?", (draft_id,)).fetchone()
            )

    def escalate_draft(self, draft_id: str, actor: str, reason: str) -> Dict[str, Any]:
        """Escalates a draft to human operator handoff and revokes active approvals."""
        if not isinstance(actor, str) or not actor.strip():
            raise MalformedInputError("actor must be a non-empty string.")
        if not isinstance(reason, str):
            raise MalformedInputError("reason must be a string.")
        actor_clean = actor.strip()
        reason_clean = str(reason or "escalated_to_human").strip()
        with self._connect(write=True) as conn:
            row = conn.execute(
                "SELECT * FROM drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if row is None:
                raise MalformedInputError(f"Unknown draft_id '{draft_id}'.")
            from_state = row["state"]
            if from_state not in (
                DraftState.PENDING_APPROVAL.value,
                DraftState.VERIFIED_BLOCKED.value,
                DraftState.APPROVED.value,
            ):
                raise VerificationBlockedError(
                    f"Draft '{draft_id}' in state '{from_state}' cannot be escalated."
                )
            conn.execute(
                """
                UPDATE approvals SET revoked=1, revoked_reason='HUMAN_ESCALATED'
                WHERE draft_id=? AND consumed=0 AND revoked=0
                """,
                (draft_id,),
            )
            conn.execute(
                "UPDATE drafts SET state=?, escalation_reason=?, updated_at=? WHERE draft_id=?",
                (DraftState.ESCALATED.value, reason_clean, _utc_now_iso(), draft_id),
            )
            self._append_audit_event(
                conn,
                draft_id=draft_id,
                event_type="DRAFT_ESCALATED",
                from_state=from_state,
                to_state=DraftState.ESCALATED.value,
                actor=actor_clean,
                payload_sha256=row["payload_sha256"],
                details={"reason": reason_clean},
            )
            return dict(
                conn.execute("SELECT * FROM drafts WHERE draft_id=?", (draft_id,)).fetchone()
            )

    def edit_draft_body(
        self,
        draft_id: str,
        evaluation: CommercialEvaluation,
        actor: str,
    ) -> Dict[str, Any]:
        """Updates draft body with re-verified evaluation and revokes any active approval."""
        if not isinstance(actor, str) or not actor.strip():
            raise MalformedInputError("actor must be a non-empty string.")
        actor_clean = actor.strip()
        with self._connect(write=True) as conn:
            row = conn.execute(
                "SELECT * FROM drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if row is None:
                raise MalformedInputError(f"Unknown draft_id '{draft_id}'.")
            draft = dict(row)
            from_state = draft["state"]
            if from_state not in (
                DraftState.PENDING_APPROVAL.value,
                DraftState.VERIFIED_BLOCKED.value,
                DraftState.APPROVED.value,
                DraftState.ESCALATED.value,
            ):
                raise VerificationBlockedError(
                    f"Cannot edit draft '{draft_id}' in terminal or post-dispatch state '{from_state}'."
                )

            cur = conn.execute(
                """
                UPDATE approvals SET revoked=1, revoked_reason='PAYLOAD_EDITED'
                WHERE draft_id=? AND consumed=0 AND revoked=0
                """,
                (draft_id,),
            )
            revoked_count = cur.rowcount

            consent_ok = bool(draft["consent_to_contact"] == 1 and str(draft["consent_evidence"]).strip())
            to_state = (
                DraftState.PENDING_APPROVAL.value
                if evaluation.verification_status == "PASS" and consent_ok
                else DraftState.VERIFIED_BLOCKED.value
            )
            new_hash = compute_draft_payload_sha256(
                {
                    "draft_id": draft_id,
                    "sku": draft["sku"],
                    "language": draft["language"],
                    "subject": draft["subject"],
                    "body": evaluation.body,
                    "contact_ref": draft["contact_ref"],
                    "contact_channel": draft["contact_channel"],
                    "consent_to_contact": draft["consent_to_contact"],
                    "consent_evidence": draft["consent_evidence"],
                    "verification_status": evaluation.verification_status,
                }
            )
            conn.execute(
                """
                UPDATE drafts
                SET body=?, verification_status=?, verification_report_json=?,
                    payload_sha256=?, state=?, updated_at=?
                WHERE draft_id=?
                """,
                (
                    evaluation.body,
                    evaluation.verification_status,
                    canonical_json(evaluation.verification_report_dict),
                    new_hash,
                    to_state,
                    _utc_now_iso(),
                    draft_id,
                ),
            )
            self._append_audit_event(
                conn,
                draft_id=draft_id,
                event_type="DRAFT_EDITED_APPROVAL_REVOKED",
                from_state=from_state,
                to_state=to_state,
                actor=actor_clean,
                payload_sha256=new_hash,
                details={
                    "revoked_approvals": revoked_count,
                    "verification_status": evaluation.verification_status,
                },
            )
            return dict(
                conn.execute("SELECT * FROM drafts WHERE draft_id=?", (draft_id,)).fetchone()
            )

    def consume_approval_for_dispatch(
        self,
        *,
        draft_id: str,
        lease_id: str,
        approval_mac: str,
        mode: ExecutionMode,
        expected_payload_sha256: Optional[str] = None,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Atomically verifies payload integrity + HMAC lease and consumes single-use token."""
        if not is_valid_sha256_hex(approval_mac):
            raise ApprovalTamperError("Malformed approval_mac format.")
        if expected_payload_sha256 is not None and not is_valid_sha256_hex(expected_payload_sha256):
            raise ApprovalTamperError("Malformed expected_payload_sha256 format.")

        current_time = float(time.time() if now is None else now)

        tamper_reason: Optional[str] = None
        expired = False

        with self._connect(write=True) as conn:
            draft_row = conn.execute(
                "SELECT * FROM drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if draft_row is None:
                raise ApprovalRequiredError(f"Unknown draft_id '{draft_id}'.")
            draft = dict(draft_row)

            app_row = conn.execute(
                "SELECT * FROM approvals WHERE lease_id=? AND draft_id=?",
                (lease_id, draft_id),
            ).fetchone()
            if app_row is None:
                raise ApprovalRequiredError("Approval lease not found for draft.")
            approval = dict(app_row)

            if approval["consumed"] == 1:
                raise ApprovalAlreadyConsumedError("Approval lease has already been consumed.")
            if approval["revoked"] == 1:
                raise ApprovalTamperError(
                    f"Approval lease has been revoked ({approval['revoked_reason']})."
                )

            live_hash = compute_draft_payload_sha256(draft)
            expected_mac = compute_approval_mac(
                self._secret,
                lease_id=approval["lease_id"],
                draft_id=draft_id,
                payload_sha256=approval["payload_sha256"],
                reviewer_id=approval["reviewer_id"],
                approved_at=approval["approved_at"],
                expires_at=approval["expires_at"],
            )

            consent_ok = (
                draft["consent_to_contact"] == 1
                and bool(str(draft["consent_evidence"]).strip())
                and draft["verification_status"] == "PASS"
            )
            caller_hash_ok = (
                True
                if expected_payload_sha256 is None
                else hmac.compare_digest(live_hash, expected_payload_sha256.lower())
            )
            hash_ok = (
                consent_ok
                and caller_hash_ok
                and is_valid_sha256_hex(draft["payload_sha256"])
                and is_valid_sha256_hex(approval["payload_sha256"])
                and hmac.compare_digest(live_hash, draft["payload_sha256"].lower())
                and hmac.compare_digest(live_hash, approval["payload_sha256"].lower())
            )
            mac_ok = (
                is_valid_sha256_hex(approval["approval_mac"])
                and hmac.compare_digest(expected_mac, approval["approval_mac"].lower())
                and hmac.compare_digest(expected_mac, approval_mac.lower())
            )

            if not hash_ok or not mac_ok:
                tamper_reason = "PAYLOAD_TAMPER" if not hash_ok else "APPROVAL_MAC_MISMATCH"
                conn.execute(
                    "UPDATE approvals SET revoked=1, revoked_reason=? WHERE lease_id=?",
                    (tamper_reason, lease_id),
                )
                conn.execute(
                    "UPDATE drafts SET state=?, updated_at=? WHERE draft_id=?",
                    (DraftState.VERIFIED_BLOCKED.value, _utc_now_iso(), draft_id),
                )
                self._append_audit_event(
                    conn,
                    draft_id=draft_id,
                    event_type="APPROVAL_INVALIDATED_TAMPER",
                    from_state=draft["state"],
                    to_state=DraftState.VERIFIED_BLOCKED.value,
                    actor="gate3_ledger",
                    payload_sha256=live_hash,
                    details={"lease_id": lease_id, "reason": tamper_reason},
                )
            elif current_time >= approval["expires_at"]:
                expired = True
                conn.execute(
                    "UPDATE approvals SET revoked=1, revoked_reason='LEASE_EXPIRED' WHERE lease_id=?",
                    (lease_id,),
                )
                conn.execute(
                    "UPDATE drafts SET state=?, updated_at=? WHERE draft_id=?",
                    (DraftState.PENDING_APPROVAL.value, _utc_now_iso(), draft_id),
                )
                self._append_audit_event(
                    conn,
                    draft_id=draft_id,
                    event_type="APPROVAL_EXPIRED",
                    from_state=draft["state"],
                    to_state=DraftState.PENDING_APPROVAL.value,
                    actor="gate3_ledger",
                    payload_sha256=live_hash,
                    details={"lease_id": lease_id},
                )
            else:
                if draft["state"] != DraftState.APPROVED.value:
                    raise ApprovalRequiredError(
                        f"Draft '{draft_id}' is in state '{draft['state']}', not APPROVED."
                    )

                cur = conn.execute(
                    """
                    UPDATE approvals
                    SET consumed=1, consumed_at=?
                    WHERE lease_id=? AND draft_id=? AND consumed=0 AND revoked=0
                    """,
                    (current_time, lease_id, draft_id),
                )
                if cur.rowcount != 1:
                    raise ApprovalAlreadyConsumedError(
                        "Concurrent consumption detected; single-use lease denied."
                    )

                to_state = (
                    DraftState.SHADOW_RECORDED.value
                    if mode == ExecutionMode.SHADOW
                    else DraftState.DISPATCHING.value
                )
                event_type = (
                    "SHADOW_DISPATCH_RECORDED"
                    if mode == ExecutionMode.SHADOW
                    else "DISPATCH_STARTED"
                )
                conn.execute(
                    "UPDATE drafts SET state=?, updated_at=? WHERE draft_id=?",
                    (to_state, _utc_now_iso(), draft_id),
                )
                self._append_audit_event(
                    conn,
                    draft_id=draft_id,
                    event_type=event_type,
                    from_state=DraftState.APPROVED.value,
                    to_state=to_state,
                    actor="gate3_ledger",
                    payload_sha256=live_hash,
                    details={"lease_id": lease_id, "mode": mode.value},
                )
                return dict(
                    conn.execute("SELECT * FROM drafts WHERE draft_id=?", (draft_id,)).fetchone()
                )

        if tamper_reason is not None:
            raise ApprovalTamperError(f"Approval invalidated due to {tamper_reason}.")
        if expired:
            raise ApprovalExpiredError("Approval lease expired before dispatch.")
        raise AssertionError("Unreachable dispatch consumption state")

    def record_delivery_state(
        self,
        draft_id: str,
        to_state: DraftState,
        *,
        delivery_key: Optional[str] = None,
        receipt_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        actor: str = "gate4_delivery",
    ) -> Dict[str, Any]:
        """Transitions a dispatching/unknown/accepted draft through allowed delivery states."""
        with self._connect(write=True) as conn:
            row = conn.execute(
                "SELECT * FROM drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if row is None:
                raise MalformedInputError(f"Unknown draft_id '{draft_id}'.")
            from_state = row["state"]
            allowed_targets = _ALLOWED_DELIVERY_TRANSITIONS.get(from_state, set())
            if to_state.value not in allowed_targets:
                raise VerificationBlockedError(
                    f"Illegal delivery state transition '{from_state}' -> '{to_state.value}'."
                )
            new_key = delivery_key or row["delivery_key"]
            new_receipt = receipt_id or row["receipt_id"]

            conn.execute(
                """
                UPDATE drafts
                SET state=?, delivery_key=?, receipt_id=?, updated_at=?
                WHERE draft_id=?
                """,
                (to_state.value, new_key, new_receipt, _utc_now_iso(), draft_id),
            )
            self._append_audit_event(
                conn,
                draft_id=draft_id,
                event_type=f"DELIVERY_{to_state.value}",
                from_state=from_state,
                to_state=to_state.value,
                actor=actor,
                payload_sha256=row["payload_sha256"],
                details={
                    "delivery_key": new_key,
                    "receipt_id": new_receipt,
                    **(details or {}),
                },
            )
            return dict(
                conn.execute("SELECT * FROM drafts WHERE draft_id=?", (draft_id,)).fetchone()
            )

    def register_channel_event(
        self,
        channel: str,
        external_event_id: str,
        *,
        tenant_id: str = "default",
        conversation_id: Optional[str] = None,
        status: str = "RECEIVED",
        draft_id: Optional[str] = None,
    ) -> bool:
        """Atomically records a hashed channel event key; returns False if already seen."""
        event_key = sha256_hex(f"{tenant_id}:{channel}:{external_event_id}")
        safe_ext_hash = sha256_hex(external_event_id)[:32]
        with self._connect(write=True) as conn:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO channel_events(
                    event_key, tenant_id, channel, external_event_id,
                    conversation_id, received_at, status, draft_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_key,
                    tenant_id,
                    channel,
                    safe_ext_hash,
                    conversation_id,
                    time.time(),
                    status,
                    draft_id,
                ),
            )
            return cur.rowcount == 1

    def update_channel_event(
        self,
        channel: str,
        external_event_id: str,
        *,
        status: str,
        draft_id: Optional[str] = None,
        tenant_id: str = "default",
    ) -> None:
        """Updates status/draft_id on a registered channel event."""
        event_key = sha256_hex(f"{tenant_id}:{channel}:{external_event_id}")
        with self._connect(write=True) as conn:
            conn.execute(
                "UPDATE channel_events SET status=?, draft_id=COALESCE(?, draft_id) WHERE event_key=?",
                (status, draft_id, event_key),
            )

    def release_channel_event(
        self,
        channel: str,
        external_event_id: str,
        *,
        tenant_id: str = "default",
    ) -> None:
        """Releases a PROCESSING channel event key on transient ingestion failure so retries succeed."""
        event_key = sha256_hex(f"{tenant_id}:{channel}:{external_event_id}")
        with self._connect(write=True) as conn:
            conn.execute(
                "DELETE FROM channel_events WHERE event_key=? AND status='PROCESSING' AND draft_id IS NULL",
                (event_key,),
            )

    def record_provider_usage(
        self,
        *,
        draft_id: Optional[str],
        tenant_id: str = "default",
        provider: str,
        model: str,
        task_tier: str,
        status: str,
        error_category: Optional[str] = None,
        latency_ms: float = 0.0,
        prompt_tokens: Optional[int] = None,
        completion_tokens: Optional[int] = None,
        total_tokens: Optional[int] = None,
        estimated_cost_usd: Optional[float] = None,
        fallback_from: Optional[str] = None,
    ) -> None:
        """Persists privacy-safe AI provider usage and failure classification metrics."""
        with self._connect(write=True) as conn:
            conn.execute(
                """
                INSERT INTO provider_usage(
                    draft_id, tenant_id, provider, model, task_tier, status,
                    error_category, latency_ms, prompt_tokens, completion_tokens,
                    total_tokens, estimated_cost_usd, fallback_from, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    draft_id,
                    tenant_id,
                    provider,
                    model,
                    task_tier,
                    status,
                    error_category,
                    float(latency_ms),
                    prompt_tokens,
                    completion_tokens,
                    total_tokens,
                    estimated_cost_usd,
                    fallback_from,
                    _utc_now_iso(),
                ),
            )

    def get_provider_usage_summary(self, *, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Aggregates token usage, latency, errors, and estimated cost by provider/model."""
        with self._connect(write=False) as conn:
            if tenant_id is not None:
                rows = conn.execute(
                    """
                    SELECT provider, model, status,
                           COUNT(*) AS calls,
                           COALESCE(SUM(prompt_tokens), 0) AS prompt_tokens,
                           COALESCE(SUM(completion_tokens), 0) AS completion_tokens,
                           COALESCE(SUM(total_tokens), 0) AS total_tokens,
                           COALESCE(SUM(estimated_cost_usd), 0.0) AS estimated_cost_usd,
                           COALESCE(AVG(latency_ms), 0.0) AS avg_latency_ms
                    FROM provider_usage
                    WHERE tenant_id=?
                    GROUP BY provider, model, status
                    ORDER BY provider, model
                    """,
                    (tenant_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT provider, model, status,
                           COUNT(*) AS calls,
                           COALESCE(SUM(prompt_tokens), 0) AS prompt_tokens,
                           COALESCE(SUM(completion_tokens), 0) AS completion_tokens,
                           COALESCE(SUM(total_tokens), 0) AS total_tokens,
                           COALESCE(SUM(estimated_cost_usd), 0.0) AS estimated_cost_usd,
                           COALESCE(AVG(latency_ms), 0.0) AS avg_latency_ms
                    FROM provider_usage
                    GROUP BY provider, model, status
                    ORDER BY provider, model
                    """
                ).fetchall()

            breakdown = [dict(r) for r in rows]
            return {
                "total_calls": sum(int(r["calls"]) for r in breakdown),
                "total_tokens": sum(int(r["total_tokens"]) for r in breakdown),
                "estimated_cost_usd": round(
                    sum(float(r["estimated_cost_usd"]) for r in breakdown), 6
                ),
                "breakdown": breakdown,
            }

    def purge_expired_retention(
        self,
        *,
        now_iso: Optional[str] = None,
        channel_event_max_age_seconds: int = 7 * 86400,
    ) -> Dict[str, int]:
        """Scrubs expired non-active draft text/body & prunes old channel replay keys."""
        cutoff_iso = now_iso or _utc_now_iso()
        cutoff_epoch = time.time() - max(60, int(channel_event_max_age_seconds))
        purgeable_states = (
            DraftState.DELIVERED.value,
            DraftState.REJECTED.value,
            DraftState.SHADOW_RECORDED.value,
            DraftState.FAILED_DELIVERY.value,
            DraftState.VERIFIED_BLOCKED.value,
            DraftState.ESCALATED.value,
        )
        placeholders = ",".join("?" for _ in purgeable_states)
        with self._connect(write=True) as conn:
            cur_drafts = conn.execute(
                f"""
                UPDATE drafts
                SET redacted_inquiry='[PURGED_BY_RETENTION]',
                    body='[PURGED_BY_RETENTION]',
                    consent_evidence='[PURGED_BY_RETENTION]',
                    channel_metadata_json='{{}}',
                    updated_at=?
                WHERE retention_expires_at IS NOT NULL
                  AND retention_expires_at <= ?
                  AND state IN ({placeholders})
                  AND redacted_inquiry != '[PURGED_BY_RETENTION]'
                """,
                (cutoff_iso, cutoff_iso, *purgeable_states),
            )
            cur_events = conn.execute(
                "DELETE FROM channel_events WHERE received_at <= ?",
                (cutoff_epoch,),
            )
            purged_drafts = int(cur_drafts.rowcount)
            purged_events = int(cur_events.rowcount)
            self._append_audit_event(
                conn,
                draft_id="__RETENTION__",
                event_type="RETENTION_PURGE_EXECUTED",
                from_state=None,
                to_state="PURGED",
                actor="retention_policy",
                payload_sha256=None,
                details={
                    "purged_drafts": purged_drafts,
                    "purged_channel_events": purged_events,
                    "cutoff_iso": cutoff_iso,
                },
            )
            return {
                "purged_drafts": purged_drafts,
                "purged_channel_events": purged_events,
            }

    def backup_to(self, dest_path: str | Path) -> Dict[str, Any]:
        """Creates a consistent SQLite hot backup and verifies its audit hash chain."""
        target = Path(dest_path).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        harden_state_permissions(target.parent, is_dir=True)
        tmp_target = target.with_name(
            f".{target.name}.bak.{os.getpid()}.{secrets.token_hex(6)}.tmp"
        )

        with self._connect(write=False) as src_conn:
            dst_conn = sqlite3.connect(str(tmp_target))
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()

        os.replace(tmp_target, target)
        perm_info = harden_state_permissions(target, is_dir=False)
        valid, event_count, errors = verify_audit_database_readonly(target)
        if not valid:
            raise MalformedInputError(f"Created backup failed verification: {'; '.join(errors)}")
        return {
            "backup_path": str(target),
            "valid": valid,
            "event_count": event_count,
            "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            "permissions": perm_info,
        }

    def list_audit_events(
        self,
        draft_id: Optional[str] = None,
        *,
        tenant_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Returns ordered audit events, optionally filtered by draft_id and/or tenant_id."""
        with self._connect(write=False) as conn:
            if tenant_id is not None:
                if draft_id is not None:
                    rows = conn.execute(
                        """
                        SELECT ae.* FROM audit_events ae
                        INNER JOIN drafts d ON d.draft_id = ae.draft_id
                        WHERE ae.draft_id=? AND d.tenant_id=?
                        ORDER BY ae.seq ASC
                        """,
                        (draft_id, tenant_id),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT ae.* FROM audit_events ae
                        LEFT JOIN drafts d ON d.draft_id = ae.draft_id
                        WHERE d.tenant_id=? OR ae.draft_id='__RETENTION__'
                        ORDER BY ae.seq ASC
                        """,
                        (tenant_id,),
                    ).fetchall()
            elif draft_id is not None:
                rows = conn.execute(
                    "SELECT * FROM audit_events WHERE draft_id=? ORDER BY seq ASC",
                    (draft_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_events ORDER BY seq ASC"
                ).fetchall()
            return [dict(r) for r in rows]

    def verify_audit_chain(self) -> Tuple[bool, List[str]]:
        """Verifies triggers, sequence integrity, and hash chain across audit_events."""
        valid, _event_count, errors = verify_audit_database_readonly(self.db_path)
        return valid, errors

    def scan_for_raw_secrets(self, raw_secrets: List[str]) -> List[Dict[str, Any]]:
        """Scans all persisted ledger tables for raw PII substrings (returns locations only)."""
        leaks: List[Dict[str, Any]] = []
        non_empty = [s for s in raw_secrets if isinstance(s, str) and len(s) >= 4]
        if not non_empty:
            return leaks
        with self._connect(write=False) as conn:
            tables = [
                r["name"]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
            for table in tables:
                if table == "sqlite_sequence":
                    continue
                rows = conn.execute(f'SELECT * FROM "{table}"').fetchall()
                for row in rows:
                    row_dict = dict(row)
                    for col, val in row_dict.items():
                        if isinstance(val, str):
                            for secret_idx, secret_val in enumerate(non_empty):
                                if secret_val in val:
                                    leaks.append(
                                        {
                                            "table": table,
                                            "column": col,
                                            "secret_index": secret_idx,
                                        }
                                    )
        return leaks


class EphemeralRouteStore:
    """Isolated SQLite store mapping (tenant_id, channel, contact_ref, conv) -> outbound target.

    Kept strictly separate from ledger.sqlite3 so the immutable approval/audit ledger
    never persists raw phone numbers or external chat identifiers.
    """

    def __init__(self, db_path: str | Path, *, default_ttl_seconds: int = 86400) -> None:
        self.db_path = Path(db_path).resolve()
        self.default_ttl_seconds = max(60, int(default_ttl_seconds))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        harden_state_permissions(self.db_path.parent, is_dir=True)
        self._init_db()
        harden_state_permissions(self.db_path, is_dir=False)

    @contextmanager
    def _connect(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA busy_timeout=5000")
            if write:
                conn.execute("BEGIN IMMEDIATE")
            yield conn
            if write:
                conn.commit()
        except BaseException:
            if write:
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect(write=False) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS routes (
                    tenant_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    contact_ref TEXT NOT NULL,
                    external_conversation_id TEXT NOT NULL DEFAULT '',
                    external_target TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (tenant_id, channel, contact_ref, external_conversation_id)
                );
                CREATE INDEX IF NOT EXISTS idx_routes_expiry ON routes(expires_at);
                """
            )

    def put(
        self,
        *,
        tenant_id: str,
        channel: str,
        contact_ref: str,
        external_target: str,
        external_conversation_id: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        validate_safe_id(tenant_id, "tenant_id")
        now = time.time()
        ttl = self.default_ttl_seconds if ttl_seconds is None else max(60, int(ttl_seconds))
        conv_key = str(external_conversation_id or "")
        with self._connect(write=True) as conn:
            conn.execute(
                """
                INSERT INTO routes(
                    tenant_id, channel, contact_ref, external_conversation_id,
                    external_target, updated_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, channel, contact_ref, external_conversation_id) DO UPDATE SET
                    external_target=excluded.external_target,
                    updated_at=excluded.updated_at,
                    expires_at=excluded.expires_at
                """,
                (
                    tenant_id,
                    channel.strip().lower(),
                    contact_ref,
                    conv_key,
                    external_target,
                    now,
                    now + ttl,
                ),
            )

    def get(
        self,
        *,
        tenant_id: str,
        channel: str,
        contact_ref: str,
        external_conversation_id: Optional[str] = None,
        now: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        current = float(time.time() if now is None else now)
        ch = channel.strip().lower()
        with self._connect(write=False) as conn:
            if external_conversation_id is not None:
                row = conn.execute(
                    """
                    SELECT * FROM routes
                    WHERE tenant_id=? AND channel=? AND contact_ref=? AND external_conversation_id=? AND expires_at > ?
                    """,
                    (tenant_id, ch, contact_ref, str(external_conversation_id), current),
                ).fetchone()
                return dict(row) if row is not None else None
            row = conn.execute(
                """
                SELECT * FROM routes
                WHERE tenant_id=? AND channel=? AND contact_ref=? AND expires_at > ?
                ORDER BY updated_at DESC LIMIT 1
                """,
                (tenant_id, ch, contact_ref, current),
            ).fetchone()
            return dict(row) if row is not None else None

    def delete(
        self,
        *,
        tenant_id: str,
        channel: str,
        contact_ref: str,
        external_conversation_id: Optional[str] = None,
    ) -> int:
        ch = channel.strip().lower()
        with self._connect(write=True) as conn:
            if external_conversation_id is not None:
                cur = conn.execute(
                    "DELETE FROM routes WHERE tenant_id=? AND channel=? AND contact_ref=? AND external_conversation_id=?",
                    (tenant_id, ch, contact_ref, str(external_conversation_id)),
                )
            else:
                cur = conn.execute(
                    "DELETE FROM routes WHERE tenant_id=? AND channel=? AND contact_ref=?",
                    (tenant_id, ch, contact_ref),
                )
            return int(cur.rowcount)

    def purge_expired(self, *, now: Optional[float] = None) -> int:
        current = float(time.time() if now is None else now)
        with self._connect(write=True) as conn:
            cur = conn.execute("DELETE FROM routes WHERE expires_at <= ?", (current,))
            return int(cur.rowcount)
