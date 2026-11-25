"""One local SQLite outbox. Opening existing state never repairs or resets it."""

from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import time


SCHEMA = """
CREATE TABLE messages (
 tenant TEXT NOT NULL, source TEXT NOT NULL, message_id TEXT NOT NULL,
 wire_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL, request_sha256 TEXT NOT NULL,
 endpoint TEXT NOT NULL, expires_at INTEGER NOT NULL, max_attempts INTEGER NOT NULL,
 backoff_seconds REAL NOT NULL, state TEXT NOT NULL CHECK(state IN
 ('PENDING','SENDING','UNKNOWN','ACCEPTED','DELIVERED','READ','FAILED')),
 attempts INTEGER NOT NULL DEFAULT 0, next_at REAL NOT NULL DEFAULT 0,
 run_id TEXT, lease_until REAL, receipt_id TEXT, error TEXT, updated_at REAL NOT NULL,
 PRIMARY KEY(tenant,source,message_id)
);
CREATE TABLE transitions (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, source TEXT NOT NULL,
 message_id TEXT NOT NULL, state TEXT NOT NULL, reason TEXT, at REAL NOT NULL,
 FOREIGN KEY(tenant,source,message_id) REFERENCES messages(tenant,source,message_id)
);
PRAGMA user_version=1;
"""


class Store:
    def __init__(self, path, *, create=False):
        self.path = Path(path).absolute()
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            with self.connect() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.executescript(SCHEMA)
        else:
            with self.connect() as conn:
                if conn.execute("PRAGMA user_version").fetchone()[0] != 1:
                    raise ValueError("Incomplete or unsupported outbox; restore its original history")
                conn.execute("SELECT tenant,source,message_id,wire_json,payload_sha256,request_sha256,"
                             "endpoint,expires_at,max_attempts,backoff_seconds,state,attempts,next_at,"
                             "run_id,lease_until,receipt_id,error,updated_at FROM messages LIMIT 0")
                conn.execute("SELECT seq,tenant,source,message_id,state,reason,at FROM transitions LIMIT 0")

    @contextmanager
    def connect(self, *, write=False):
        conn = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=2, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=FULL")
            if write:
                conn.execute("BEGIN IMMEDIATE")
            yield conn
            if write:
                conn.commit()
        except BaseException:
            if write:
                conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def key(message):
        return tuple(message[k] for k in ("tenant", "source", "message_id"))

    @staticmethod
    def fetch(conn, tenant, source, message_id):
        return conn.execute("SELECT * FROM messages WHERE tenant=? AND source=? AND message_id=?",
                            (tenant, source, message_id)).fetchone()

    @classmethod
    def transition(cls, conn, message, state, reason=None, **changes):
        allowed = {"attempts", "next_at", "run_id", "lease_until", "receipt_id"}
        if changes.keys() - allowed:
            raise ValueError("Invalid internal transition fields")
        values = {"state": state, "error": reason, "updated_at": time.time(), **changes}
        assignments = ",".join(name + "=?" for name in values)
        conn.execute(f"UPDATE messages SET {assignments} WHERE tenant=? AND source=? AND message_id=?",
                     (*values.values(), *cls.key(message)))
        conn.execute("INSERT INTO transitions(tenant,source,message_id,state,reason,at) VALUES(?,?,?,?,?,?)",
                     (*cls.key(message), state, reason, values["updated_at"]))
