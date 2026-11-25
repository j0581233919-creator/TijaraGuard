"""Fixed-endpoint HTTP transport; no redirects and no replay after an uncertain POST."""

import http.client
import json
import socket
import threading
import time
from urllib.parse import urlsplit

from .model import Outcome, canonical, endpoint, fingerprint, identifier


def delivery_key(message: dict) -> str:
    return fingerprint([message[name] for name in ("tenant", "source", "message_id")])


class HttpTransport:
    def __init__(self, timeout=2.0):
        if type(timeout) not in (int, float) or not 0.1 <= timeout <= 5:
            raise ValueError("Transport timeout must be 0.1–5 seconds")
        self.timeout = float(timeout)

    def submit(self, message: dict) -> Outcome:
        return self._request(message, post=True)

    def lookup(self, message: dict) -> Outcome:
        return self._request(message, post=False)

    def _request(self, message, *, post):
        parsed = urlsplit(endpoint(message["endpoint"]))
        connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        conn = connection_type(parsed.hostname, parsed.port, timeout=self.timeout)
        timer = None
        try:
            try:
                conn.connect()
            except (OSError, http.client.HTTPException):
                return Outcome("RETRYABLE" if post else "UNKNOWN", reason="Connection failed before HTTP request")
            if post and time.time() >= message["expires_at"]:
                return Outcome("RETRYABLE", reason="Message expired before HTTP request")
            # Close the actual socket to interrupt a peer that slowly drips headers/body.
            active_socket = conn.sock

            def interrupt():
                try:
                    active_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            timer = threading.Timer(self.timeout, interrupt)
            timer.daemon = True
            timer.start()
            key = delivery_key(message)
            path = parsed.path.rstrip("/") or "/"
            headers = {"Accept": "application/json", "Connection": "close"}
            if post:
                headers.update({"Content-Type": "application/json", "Idempotency-Key": key})
                body = canonical(dict(key=key, payload=json.loads(message["wire_json"]),
                                      payload_sha256=message["payload_sha256"])).encode()
                conn.request("POST", path, body, headers)
            else:
                conn.request("GET", path.rstrip("/") + "/receipts/" + key, headers=headers)
            response = conn.getresponse()
            raw = response.read(4097)
            if response.status not in (200, 201) or len(raw) > 4096:
                return Outcome("UNKNOWN", reason="Gateway acceptance unconfirmed")
            value = json.loads(raw)
            if (not isinstance(value, dict) or set(value) != {"key", "payload_sha256", "receipt_id", "state"}
                    or value["key"] != key or value["payload_sha256"] != message["payload_sha256"]
                    or value["state"] != "ACCEPTED"):
                return Outcome("UNKNOWN", reason="Receipt identity or state mismatch")
            identifier(value["receipt_id"])
            return Outcome("ACCEPTED", receipt_id=value["receipt_id"])
        except Exception:
            return Outcome("UNKNOWN", reason="HTTP outcome unresolved; reconcile without resending")
        finally:
            if timer:
                timer.cancel()
            conn.close()
