"""Real durable loopback inbox implementing Message Shield's gateway receipt contract."""

import argparse
import json
import os
from pathlib import Path
import socket
import sqlite3
import uuid
from http.server import ThreadingHTTPServer

from message_shield.http import JsonHandler, body
from message_shield.model import canonical, fingerprint, identifier


def receiver(database, port=0, *, drop_ack=False):
    """drop_ack injects a real post-commit connection loss for negative tests."""
    path = Path(database).absolute()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        created = False
    else:
        os.close(fd)
        created = True

    def connect():
        conn = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=2, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    conn = connect()
    try:
        if created:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""CREATE TABLE inbox(key TEXT PRIMARY KEY, payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL, receipt_id TEXT NOT NULL UNIQUE)""")
        conn.execute("SELECT key,payload_json,payload_sha256,receipt_id FROM inbox LIMIT 0")
    finally:
        conn.close()

    def accepted(row):
        # Readback validates stored bytes independently of the sender's claims.
        if fingerprint(json.loads(row["payload_json"])) != row["payload_sha256"]:
            raise ValueError("Stored inbox corruption")
        return dict(key=row["key"], payload_sha256=row["payload_sha256"],
                    receipt_id=row["receipt_id"], state="ACCEPTED")

    class Handler(JsonHandler):
        def do_POST(self):
            if self.path != "/inbox":
                self.respond(404, {"error": "Not found"})
                return
            conn = None
            try:
                data = body(self)
                if not isinstance(data, dict) or set(data) != {"key", "payload", "payload_sha256"}:
                    raise ValueError("Invalid gateway envelope")
                payload = data["payload"]
                if not isinstance(payload, dict) or set(payload) != {"tenant", "source", "message_id", "text"}:
                    raise ValueError("Invalid gateway payload")
                for field in ("tenant", "source", "message_id"):
                    identifier(payload[field])
                if (not isinstance(payload["text"], str) or not payload["text"].strip()
                        or len(payload["text"].encode()) > 8192
                        or data["payload_sha256"] != fingerprint(payload)
                        or data["key"] != fingerprint([payload[k] for k in ("tenant", "source", "message_id")])):
                    raise ValueError("Gateway identity mismatch")
                conn = connect()
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("SELECT * FROM inbox WHERE key=?", (data["key"],)).fetchone()
                if row and row["payload_json"] != canonical(payload):
                    conn.rollback()
                    self.respond(409, {"error": "Conflicting gateway content"})
                    return
                if row is None:
                    conn.execute("INSERT INTO inbox VALUES(?,?,?,?)",
                                 (data["key"], canonical(payload), fingerprint(payload), uuid.uuid4().hex))
                    row = conn.execute("SELECT * FROM inbox WHERE key=?", (data["key"],)).fetchone()
                result = accepted(row)
                conn.commit()
                if drop_ack:
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.close_connection = True
                    return
                self.respond(200, result)
            except (ValueError, TypeError):
                self.respond(400, {"error": "Invalid gateway request"})
            finally:
                if conn:
                    conn.close()

        def do_GET(self):
            prefix = "/inbox/receipts/"
            if not self.path.startswith(prefix):
                self.respond(404, {"error": "Not found"})
                return
            conn = connect()
            try:
                row = conn.execute("SELECT * FROM inbox WHERE key=?", (self.path[len(prefix):],)).fetchone()
                self.respond(200, accepted(row)) if row else self.respond(404, {"error": "Receipt not found"})
            finally:
                conn.close()

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--port", type=int, default=8877)
    args = parser.parse_args()
    httpd = receiver(args.database, args.port)
    print(f"Durable inbox: http://127.0.0.1:{httpd.server_port}/inbox", flush=True)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
