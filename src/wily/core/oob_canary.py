"""Out-of-band (OOB) canary server.

A lightweight local HTTP server that logs every request it receives, so a
scanner can prove a target actually sent an outbound request (jku fetch,
SSRF, ...) rather than relying only on the target's own HTTP response.

Currently local-only (127.0.0.1); a remote target needs a publicly
reachable canary instead (public IP/domain, or a service like interactsh)
behind the same ``url_for``/``wait_for_hit`` interface.

Use as a context manager (``with OOBCanaryServer() as canary:``) so
``stop()`` always runs; runs on its own background thread, independent of
any asyncio event loop.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class CanaryHit:
    token: str
    method: str
    path: str
    headers: dict
    remote_addr: str
    received_at: float


class OOBCanaryServer:
    """A single canary server instance can serve several different tokens
    at the same time - each test (each candidate finding) gets a unique
    token, so results from different tests running concurrently never mix."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._hits: dict[str, list[CanaryHit]] = {}
        self._lock = threading.Lock()
        handler = self._make_handler()
        self._httpd = ThreadingHTTPServer((host, port), handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        self._stopped = False

    def __enter__(self) -> "OOBCanaryServer":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address[:2]
        display_host = "127.0.0.1" if host in ("0.0.0.0", "") else host
        return f"http://{display_host}:{port}"

    def new_token(self) -> str:
        return uuid.uuid4().hex

    def url_for(self, token: str, path_suffix: str = "key.json") -> str:
        return f"{self.base_url}/oob/{token}/{path_suffix}"

    def record_hit(self, hit: CanaryHit) -> None:
        with self._lock:
            self._hits.setdefault(hit.token, []).append(hit)

    def wait_for_hit(self, token: str, timeout: float = 5.0) -> CanaryHit | None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                hits = self._hits.get(token)
            if hits:
                return hits[0]
            time.sleep(0.1)
        return None

    def all_hits(self, token: str) -> list[CanaryHit]:
        with self._lock:
            return list(self._hits.get(token, []))

    def _make_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                parts = self.path.strip("/").split("/")
                token = parts[1] if len(parts) >= 2 and parts[0] == "oob" else self.path

                server.record_hit(
                    CanaryHit(
                        token=token,
                        method=self.command,
                        path=self.path,
                        headers=dict(self.headers.items()),
                        remote_addr=self.client_address[0],
                        received_at=time.time(),
                    )
                )

                body = b'{"keys":[]}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._handle()

            def do_POST(self):
                self._handle()

            def log_message(self, format, *args):
                pass

        return Handler

    def stop(self) -> None:
        """Safe to call more than once (idempotent)."""
        if self._stopped:
            return
        self._stopped = True
        self._httpd.shutdown()
        self._httpd.server_close()
