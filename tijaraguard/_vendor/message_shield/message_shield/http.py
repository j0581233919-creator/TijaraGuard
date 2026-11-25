"""Authenticated loopback ingress. HTTP input cannot select a tenant or target URL."""

import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json

from .model import Conflict, Missing, canonical


def body(handler):
    sizes = handler.headers.get_all("Content-Length", [])
    if (len(sizes) != 1 or handler.headers.get("Transfer-Encoding")
            or handler.headers.get_content_type() != "application/json"):
        raise ValueError("A fixed-length JSON body is required")
    size = int(sizes[0])
    if not 0 < size <= 16384:
        raise ValueError("Body size must be 1–16384 bytes")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON fields are forbidden")
            result[key] = value
        return result

    return json.loads(handler.rfile.read(size), object_pairs_hook=pairs)


class JsonHandler(BaseHTTPRequestHandler):
    server_version = "MessageShield/0.1"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def log_message(self, *_):
        pass

    def respond(self, code, value):
        data = canonical(value).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True


def serve(shield, tenant: str, access_token: str, receipt_token: str, port=8844):
    class Handler(JsonHandler):
        def do_GET(self):
            self.dispatch()

        def do_POST(self):
            self.dispatch()

        def dispatch(self):
            try:
                expected = receipt_token if self.path == "/delivery-receipts" else access_token
                actual = self.headers.get("Authorization", "").encode()
                if not hmac.compare_digest(actual, ("Bearer " + expected).encode()):
                    self.respond(401, {"error": "Unauthorized"})
                    return
                parts = self.path.strip("/").split("/")
                if self.command == "POST" and parts == ["messages"]:
                    result = shield.admit(tenant, body(self))
                elif self.command == "POST" and parts == ["delivery-receipts"]:
                    data = body(self)
                    if not isinstance(data, dict) or set(data) != {"source", "message_id", "receipt_id", "status"}:
                        raise ValueError("Invalid delivery receipt fields")
                    result = shield.receipt(tenant, **data)
                elif len(parts) == 3 and parts[0] == "messages" and self.command == "GET":
                    result = shield.get(tenant, parts[1], parts[2])
                elif len(parts) == 4 and parts[0] == "messages" and self.command == "POST":
                    action = {"send": shield.send, "recover": shield.recover}.get(parts[3])
                    if action is None:
                        raise Missing("Route not found")
                    result = action(tenant, parts[1], parts[2])
                else:
                    raise Missing("Route not found")
                self.respond(202 if result["state"] in ("PENDING", "SENDING", "UNKNOWN") else 200, result)
            except Missing as exc:
                self.respond(404, {"error": str(exc)})
            except Conflict as exc:
                self.respond(409, {"error": str(exc)})
            except (ValueError, TypeError, TimeoutError):
                self.respond(400, {"error": "Invalid request"})
            except Exception:
                self.respond(503, {"error": "State unavailable; preserve the original message identity"})

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)
