"""Gate 3 — SQLite WAL approval ledger, Shadow Mode gate, and append-only audit trail."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
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
)

_GENESIS_HASH = "0" * 64
_VALID_STATES_SQL = ",".join(f"'{s.value}'" for s in DraftState)

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS drafts (
    draft_id TEXT PRIMARY KEY,
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
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

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

PRAGMA user_version = 1;
"""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
                or "RAISE(ABORT" not in trig_sql
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


class ApprovalLedger:
    """Durable SQLite WAL approval ledger with single-use cryptographic approval leases."""

    def __init__(self, db_path: str | Path, approval_secret: bytes) -> None:
        if not isinstance(approval_secret, (bytes, bytearray)) or len(approval_secret) < 16:
            raise MalformedInputError("approval_secret must be bytes of at least 16 bytes.")
        self.db_path = Path(db_path).resolve()
        self._secret = bytes(approval_secret)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        with self._connect(write=False) as conn:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            if str(mode).lower() != "wal":
                conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)

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
    ) -> Dict[str, Any]:
        """Persists redacted inquiry + commercial evaluation into the ledger."""
        now_iso = _utc_now_iso()
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

        with self._connect(write=True) as conn:
            conn.execute(
                """
                INSERT INTO drafts(
                    draft_id, message_id, conversation_id, customer_handle, contact_ref,
                    contact_channel, sku, language, redacted_inquiry, pii_summary_json,
                    subject, body, consent_to_contact, consent_evidence,
                    verification_status, verification_report_json, payload_sha256,
                    state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evaluation.draft_id,
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
                },
            )
            row = conn.execute(
                "SELECT * FROM drafts WHERE draft_id=?", (evaluation.draft_id,)
            ).fetchone()
            return dict(row)

    def get_draft(self, draft_id: str) -> Dict[str, Any]:
        """Fetches a draft record by draft_id."""
        with self._connect(write=False) as conn:
            row = conn.execute(
                "SELECT * FROM drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if row is None:
                raise MalformedInputError(f"Unknown draft_id '{draft_id}'.")
            return dict(row)

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
            if from_state not in (DraftState.PENDING_APPROVAL.value, DraftState.APPROVED.value):
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
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Atomically verifies payload integrity + HMAC lease and consumes single-use token."""
        if not is_valid_sha256_hex(approval_mac):
            raise ApprovalTamperError("Malformed approval_mac format.")

        current_time = float(time.time() if now is None else now)

        # Two-phase safe handling so tamper revocation/audit commits even though exception raises.
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
            hash_ok = (
                consent_ok
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

    def list_audit_events(self, draft_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns ordered audit events."""
        with self._connect(write=False) as conn:
            if draft_id is not None:
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
            for table in ("drafts", "approvals", "audit_events"):
                rows = conn.execute(f"SELECT * FROM {table}").fetchall()
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
