"""Shared test fixtures, synthetic PII vectors, and persistence leak scanners."""

from __future__ import annotations

import logging
import secrets
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Dict, Iterator, List

sys.dont_write_bytecode = True

from tijaraguard.commerce import CommercialGate
from tijaraguard.models import InboundMessage

REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "examples" / "catalog.json"

# Checksum-valid synthetic test PII (never real individuals).
SYNTH_SAUDI_ID = "1082345677"       # Valid Saudi National ID (starts with 1, valid Luhn)
SYNTH_IQAMA = "2082345675"          # Valid Saudi Iqama (starts with 2, valid Luhn)
SYNTH_INVALID_ID = "1082345678"     # Invalid Luhn checksum
SYNTH_GCC_IBAN = "SA0380000000608010167519"
SYNTH_PHONE_INTL = "+966501234567"
SYNTH_PHONE_AR_INDIC = "٠٥٠١٢٣٤٥٦٧"
SYNTH_EMAIL = "synth.buyer.01@example.invalid"

ALL_SYNTH_PII_SECRETS: List[str] = [
    SYNTH_SAUDI_ID,
    SYNTH_IQAMA,
    SYNTH_GCC_IBAN,
    SYNTH_PHONE_INTL,
    SYNTH_PHONE_AR_INDIC,
    SYNTH_EMAIL,
]

FIXED_REFERENCE_TIME = datetime(2026, 6, 15, 12, 0, tzinfo=timezone.utc)


def load_test_catalog():
    return CommercialGate.from_json_file(CATALOG_PATH).catalog


def make_secret_bytes() -> bytes:
    return secrets.token_bytes(32)


def make_inbound_message(
    *,
    message_id: str = "msg-001",
    conversation_id: str = "conv-001",
    customer_handle: str = "عميل_تجريبي",
    raw_contact_target: str = SYNTH_PHONE_INTL,
    contact_channel: str = "whatsapp",
    consent_to_contact: Any = True,
    consent_evidence: str = "whatsapp_opt_in_2026",
    preferred_language: str = "ar",
    raw_text: str = f"هلا والله، كم سعر سماعة سوني WH-1000XM5؟ هويتي {SYNTH_SAUDI_ID}",
    requested_sku: str | None = None,
) -> InboundMessage:
    return InboundMessage(
        message_id=message_id,
        conversation_id=conversation_id,
        customer_handle=customer_handle,
        raw_contact_target=raw_contact_target,
        contact_channel=contact_channel,
        consent_to_contact=consent_to_contact,
        consent_evidence=consent_evidence,
        preferred_language=preferred_language,
        raw_text=raw_text,
        requested_sku=requested_sku,
    )


def scan_sqlite_for_secrets(db_path: Path, secret_values: List[str]) -> List[Dict[str, Any]]:
    leaks: List[Dict[str, Any]] = []
    if not db_path.exists():
        return leaks
    conn = sqlite3.connect(str(db_path))
    try:
        tables = [
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        ]
        for table in tables:
            cursor = conn.execute(f'SELECT * FROM "{table}"')
            col_names = [desc[0] for desc in cursor.description]
            for row in cursor.fetchall():
                for col, val in zip(col_names, row):
                    if isinstance(val, str):
                        for idx, sec in enumerate(secret_values):
                            if sec and sec in val:
                                leaks.append({"table": table, "column": col, "secret_idx": idx})
    finally:
        conn.close()
    return leaks


@contextmanager
def capture_tijaraguard_logs() -> Iterator[StringIO]:
    buf = StringIO()
    handler = logging.StreamHandler(buf)
    logger = logging.getLogger("tijaraguard")
    old_level = logger.level
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    try:
        yield buf
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)
