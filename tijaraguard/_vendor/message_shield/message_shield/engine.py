"""Durable deduplication and a conservative, finite delivery state machine."""

import json
import time
import uuid

from .model import Conflict, Missing, Outcome, Transport, canonical, endpoint, event, fingerprint, identifier
from .store import Store
from .transport import HttpTransport, delivery_key


class Shield:
    def __init__(self, database, target, *, create=False, timeout=2.0):
        self.target = endpoint(target)
        self.transport = HttpTransport(timeout)
        self.store = Store(database, create=create)

    def _get(self, conn, tenant, source, message_id):
        for value in (tenant, source, message_id):
            identifier(value)
        row = self.store.fetch(conn, tenant, source, message_id)
        if row is None:
            raise Missing("Message not found")
        return dict(row)

    @staticmethod
    def public(message):
        names = ("tenant", "source", "message_id", "payload_sha256", "state", "attempts", "next_at",
                 "receipt_id", "error")
        return {**{name: message[name] for name in names}, "key": delivery_key(message)}

    def admit(self, tenant: str, request: dict) -> dict:
        identifier(tenant)
        request = event(request)
        wire = {name: request[name] for name in ("source", "message_id", "text")}
        wire["tenant"] = tenant
        request_hash = fingerprint(dict(request=request, tenant=tenant, endpoint=self.target))
        with self.store.connect(write=True) as conn:
            prior = self.store.fetch(conn, tenant, request["source"], request["message_id"])
            if prior:
                if prior["request_sha256"] != request_hash:
                    raise Conflict("Message identity already bound to different content, endpoint or policy")
                return self.public(dict(prior))
            now = time.time()
            if not now < request["expires_at"] <= now + 86400:
                raise ValueError("New message must expire within 24 hours")
            conn.execute("""INSERT INTO messages
                (tenant,source,message_id,wire_json,payload_sha256,request_sha256,endpoint,expires_at,
                 max_attempts,backoff_seconds,state,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,'PENDING',?)""",
                         (tenant, request["source"], request["message_id"], canonical(wire), fingerprint(wire),
                          request_hash, self.target, request["expires_at"], request["max_attempts"],
                          request["backoff_seconds"], now))
            message = self._get(conn, tenant, request["source"], request["message_id"])
            conn.execute("INSERT INTO transitions(tenant,source,message_id,state,at) VALUES(?,?,?,'PENDING',?)",
                         (*self.store.key(message), now))
            return self.public(message)

    def get(self, tenant, source, message_id):
        with self.store.connect() as conn:
            return self.public(self._get(conn, tenant, source, message_id))

    def send(self, tenant, source, message_id, *, transport: Transport | None = None):
        transport = transport or self.transport
        with self.store.connect(write=True) as conn:
            message = self._get(conn, tenant, source, message_id)
            now = time.time()
            if message["state"] != "PENDING" or now < message["next_at"]:
                return self.public(message)
            if now >= message["expires_at"]:
                self.store.transition(conn, message, "FAILED", "Expired before dispatch")
                return self.public(self._get(conn, tenant, source, message_id))
            run_id = uuid.uuid4().hex
            self.store.transition(conn, message, "SENDING", attempts=message["attempts"] + 1,
                                  run_id=run_id, lease_until=now + 2 * self.transport.timeout + 1)
            message = self._get(conn, tenant, source, message_id)
        try:
            result = transport.submit(message)
        except Exception:
            result = Outcome("UNKNOWN", reason="Transport outcome unavailable")
        with self.store.connect(write=True) as conn:
            current = self._get(conn, tenant, source, message_id)
            if current["state"] != "SENDING" or current["run_id"] != run_id:
                return self.public(current)
            if result.kind == "ACCEPTED":
                identifier(result.receipt_id)
                self.store.transition(conn, current, "ACCEPTED", receipt_id=result.receipt_id, run_id=None)
            elif result.kind == "RETRYABLE":
                if current["attempts"] >= current["max_attempts"] or time.time() >= current["expires_at"]:
                    self.store.transition(conn, current, "FAILED", "No request sent; retry bound or expiry reached",
                                          run_id=None)
                else:
                    delay = current["backoff_seconds"] * 2 ** (current["attempts"] - 1)
                    self.store.transition(conn, current, "PENDING", result.reason, run_id=None,
                                          next_at=time.time() + delay)
            else:
                self.store.transition(conn, current, "UNKNOWN", result.reason or "Acceptance unresolved", run_id=None)
            return self.public(self._get(conn, tenant, source, message_id))

    def recover(self, tenant, source, message_id, *, transport: Transport | None = None):
        with self.store.connect(write=True) as conn:
            message = self._get(conn, tenant, source, message_id)
            if message["state"] == "SENDING":
                if time.time() < message["lease_until"]:
                    return self.public(message)
                self.store.transition(conn, message, "UNKNOWN", "Interrupted send; lookup required", run_id=None)
                message = self._get(conn, tenant, source, message_id)
            if message["state"] != "UNKNOWN":
                return self.public(message)
        try:
            result = (transport or self.transport).lookup(message)
        except Exception:
            result = Outcome("UNKNOWN", reason="Gateway readback unavailable")
        with self.store.connect(write=True) as conn:
            current = self._get(conn, tenant, source, message_id)
            if current["state"] == "UNKNOWN" and result.kind == "ACCEPTED":
                identifier(result.receipt_id)
                self.store.transition(conn, current, "ACCEPTED", receipt_id=result.receipt_id)
            return self.public(self._get(conn, tenant, source, message_id))

    def receipt(self, tenant, source, message_id, receipt_id, status):
        identifier(receipt_id)
        if status not in ("DELIVERED", "READ"):
            raise ValueError("Delivery status must be DELIVERED or READ")
        with self.store.connect(write=True) as conn:
            message = self._get(conn, tenant, source, message_id)
            if message["receipt_id"] != receipt_id:
                raise Conflict("Delivery receipt does not match accepted gateway identity")
            allowed = {"ACCEPTED": {"DELIVERED", "READ"}, "DELIVERED": {"READ"}, "READ": set()}
            if message["state"] != status:
                if status not in allowed.get(message["state"], set()):
                    raise Conflict("Delivery state cannot regress")
                self.store.transition(conn, message, status)
            return self.public(self._get(conn, tenant, source, message_id))

    def drain(self, tenant, source, message_id):
        message = self.get(tenant, source, message_id)
        for _ in range(3):
            if message["state"] != "PENDING":
                break
            wait = max(0, message["next_at"] - time.time())
            if wait:
                time.sleep(wait)
            message = self.send(tenant, source, message_id)
        return message
