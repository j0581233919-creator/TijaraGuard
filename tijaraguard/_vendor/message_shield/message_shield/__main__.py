"""Checkout CLI. Local operators own the state directory; HTTP clients use scoped credentials."""

import argparse
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import threading
import time
import uuid

from .engine import Shield
from .http import serve
from .model import canonical, endpoint, identifier


def load(state):
    config = json.loads((state / "config.json").read_text())
    if set(config) != {"tenant", "endpoint"}:
        raise ValueError("Invalid operator configuration")
    identifier(config["tenant"])
    shield = Shield(state / "outbox.sqlite3", config["endpoint"])
    tokens = [(state / name).read_text().strip() for name in ("access.token", "receipts.token")]
    if any(len(token) < 32 for token in tokens) or tokens[0] == tokens[1]:
        raise ValueError("Invalid or non-distinct local credentials")
    return shield, config["tenant"], tokens


def initialize(state, tenant, target):
    identifier(tenant)
    target = endpoint(target)
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (state / "config.json").exists():
        shield, current_tenant, tokens = load(state)
        if current_tenant != tenant or shield.target != target:
            raise ValueError("Existing state cannot be rebound to another tenant or endpoint")
        return shield, tenant, tokens
    if any(state.iterdir()):
        raise ValueError("Partial existing state; restore it rather than resetting delivery history")
    config = dict(tenant=tenant, endpoint=target)
    Shield(state / "outbox.sqlite3", target, create=True)
    for name, text in (("config.json", canonical(config)), ("access.token", secrets.token_urlsafe(32)),
                       ("receipts.token", secrets.token_urlsafe(32))):
        with (state / name).open("x", encoding="utf-8") as stream:
            stream.write(text + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    return load(state)


def demo(state):
    from examples.local_receiver import receiver

    case = state / ("demo-" + uuid.uuid4().hex)
    case.mkdir(parents=True, mode=0o700)
    inbox = case / "inbox.sqlite3"
    # Receiver and sender state are intentionally separate, durable stores.
    httpd = receiver(inbox)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    sender = case / "sender"
    try:
        shield, tenant, _ = initialize(sender, "demo", f"http://127.0.0.1:{httpd.server_port}/inbox")
        request = dict(source="shop", message_id="order-001", text="Order 001 is ready for collection.",
                       expires_at=int(time.time()) + 3600)
        shield.admit(tenant, request)
        shield.admit(tenant, request)
        result = shield.drain(tenant, "shop", "order-001")
        restarted, _, _ = load(sender)
        if restarted.send(tenant, "shop", "order-001") != result or result["state"] != "ACCEPTED":
            raise ValueError("Demo did not produce stable gateway acceptance")
        conn = sqlite3.connect(inbox.as_uri() + "?mode=ro", uri=True)
        try:
            rows = conn.execute("SELECT key,payload_json,payload_sha256,receipt_id FROM inbox").fetchall()
            expected = dict(tenant=tenant, source="shop", message_id="order-001", text=request["text"])
            if (len(rows) != 1 or json.loads(rows[0][1]) != expected or rows[0][0] != result["key"]
                    or rows[0][2] != result["payload_sha256"] or rows[0][3] != result["receipt_id"]
                    or conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok"):
                raise ValueError("Independent inbox verification failed")
        finally:
            conn.close()
        return dict(message=result, independently_verified_inbox_rows=1, persisted_after_restart=True,
                    state_directory=str(sender), inbox_database=str(inbox), accepted_is_not_delivered=True)
    finally:
        httpd.shutdown()
        thread.join()
        httpd.server_close()


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Message Shield: durable deduplication and delivery state")
    parser.add_argument("--state", type=Path, default=Path(".shield"))
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--tenant", required=True)
    init.add_argument("--endpoint", required=True)
    sub.add_parser("demo")
    admit = sub.add_parser("admit")
    admit.add_argument("request", type=Path)
    for name in ("status", "send", "drain", "recover", "receipt"):
        action = sub.add_parser(name)
        action.add_argument("source")
        action.add_argument("message_id")
        if name == "receipt":
            action.add_argument("--receipt-id", required=True)
            action.add_argument("--status", choices=["DELIVERED", "READ"], required=True)
    http = sub.add_parser("serve")
    http.add_argument("--port", type=int, default=8844)
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            result = demo(args.state.absolute())
        elif args.command == "init":
            initialize(args.state, args.tenant, args.endpoint)
            result = {"initialized": str(args.state), "credentials": "access.token and receipts.token"}
        else:
            shield, tenant, tokens = load(args.state)
            if args.command == "serve":
                httpd = serve(shield, tenant, *tokens, args.port)
                print(f"Listening on http://127.0.0.1:{httpd.server_port}", flush=True)
                try:
                    httpd.serve_forever()
                finally:
                    httpd.server_close()
                return 0
            if args.command == "admit":
                result = shield.admit(tenant, json.loads(args.request.read_text()))
            elif args.command == "receipt":
                result = shield.receipt(tenant, args.source, args.message_id, args.receipt_id, args.status)
            else:
                action = shield.get if args.command == "status" else getattr(shield, args.command)
                result = action(tenant, args.source, args.message_id)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 2 if result.get("state") in ("UNKNOWN", "FAILED") else 0
    except (ValueError, LookupError, OSError, sqlite3.Error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
