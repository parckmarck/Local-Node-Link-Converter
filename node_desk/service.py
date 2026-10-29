from __future__ import annotations

import secrets
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from .store import Store


class _LoopbackServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 16

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(4)
        return connection, address

    def handle_error(self, request, client_address):
        # Deliberately avoid emitting request paths containing subscription tokens.
        pass


class SubscriptionService:
    def __init__(self, store: Store):
        self.store = store
        self._server: _LoopbackServer | None = None
        self._thread: threading.Thread | None = None
        self._port: int | None = None

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def port(self) -> int:
        return self._port if self._port is not None else self.store.settings()["port"]

    def start(self, port: int | None = None) -> int:
        if self.running:
            return self.port
        service = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "NodeDesk"
            sys_version = ""

            def log_message(self, format, *args):
                pass

            def respond(self, status: int, body: str, kind: str = "text/plain; charset=utf-8"):
                payload = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'none'")
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    try:
                        self.wfile.write(payload)
                    except (ConnectionError, OSError):
                        pass

            def do_HEAD(self):
                self.do_GET()

            def do_GET(self):
                expected_hosts = {
                    f"127.0.0.1:{self.server.server_port}",
                    f"localhost:{self.server.server_port}",
                }
                if self.headers.get("Host", "") not in expected_hosts:
                    return self.respond(403, "Loopback host required.")
                if self.headers.get("Origin"):
                    return self.respond(403, "Browser cross-origin requests are not allowed.")
                if len(self.path) > 4096:
                    return self.respond(414, "Request too long.")
                try:
                    request = urlsplit(self.path)
                    if request.scheme or request.netloc:
                        return self.respond(400, "Relative path required.")
                    if request.path == "/health":
                        return self.respond(200, '{"service":"NodeDesk","status":"running"}', "application/json")
                    parts = request.path.strip("/").split("/")
                    settings = service.store.settings()
                    if (
                        len(parts) != 3
                        or parts[0] != "sub"
                        or not parts[1].isascii()
                        or not secrets.compare_digest(parts[1], settings["token"])
                        or parts[2] not in ("clash.yaml", "v2ray.txt")
                    ):
                        return self.respond(404, "Not found.")
                    query = parse_qs(request.query, max_num_fields=4, keep_blank_values=True)
                    if set(query) - {"group"} or any(len(value) != 1 for value in query.values()):
                        return self.respond(400, "Invalid filter.")
                    group = query.get("group", [None])[0]
                    if group is not None and len(group) > 80:
                        return self.respond(400, "Invalid group.")
                    nodes = [
                        node for node in service.store.list_nodes()
                        if node["enabled"] and (group is None or node["group"] == group)
                    ]
                    if not nodes:
                        return self.respond(409, "No enabled nodes in this subscription.")
                    from .formats import export_clash, export_v2ray

                    if parts[2] == "clash.yaml":
                        return self.respond(
                            200, export_clash(nodes, test_url=settings["test_url"],
                                              rules=service.store.list_rules()),
                            "text/yaml; charset=utf-8",
                        )
                    return self.respond(200, export_v2ray(nodes))
                except (ValueError, UnicodeError):
                    return self.respond(422, "Subscription cannot be exported. Check the node formats.")
                except Exception:
                    return self.respond(500, "Local subscription error.")

            def do_POST(self):
                self.respond(405, "Read-only subscription service.")

        chosen = self.store.settings()["port"] if port is None else port
        server = _LoopbackServer(("127.0.0.1", chosen), Handler)
        self._server = server
        self._port = server.server_port
        self._thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.15},
            name="node-desk-subscriptions", daemon=True,
        )
        self._thread.start()
        return self.port

    def url(self, format: str, group: str | None = None) -> str:
        if format not in ("clash", "v2ray"):
            raise ValueError("Unknown subscription format.")
        filename = "clash.yaml" if format == "clash" else "v2ray.txt"
        token = self.store.settings()["token"]
        url = f"http://127.0.0.1:{self.port}/sub/{token}/{filename}"
        return url if group is None else url + "?" + urlencode({"group": group})

    def stop(self) -> None:
        server, thread = self._server, self._thread
        if server is None:
            return
        self._server = None
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=5)
        self._thread = None
        self._port = None
