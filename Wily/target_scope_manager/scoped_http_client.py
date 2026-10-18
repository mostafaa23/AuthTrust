from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)
from urllib.parse import urlsplit

from .scope_guard import ScopeGuard
from .scope_manager import ScopeError


REDIRECT_CODES = {301, 302, 303, 307, 308}

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
}


class HTTPClientError(RuntimeError):
    """Raised when a scoped HTTP request fails."""


class NoAutomaticRedirectHandler(HTTPRedirectHandler):
    """Require every redirect to pass the scope checks manually."""

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        return None


class ScopedHTTPClient:
    """HTTP client that validates scope before every request."""

    def __init__(
        self,
        guard: ScopeGuard,
        *,
        timeout: float = 10.0,
        max_redirects: int = 5,
        max_body_bytes: int = 1_000_000,
    ):
        if timeout <= 0:
            raise ValueError("Timeout must be positive.")

        if max_redirects < 0:
            raise ValueError("max_redirects cannot be negative.")

        if max_body_bytes < 1:
            raise ValueError("max_body_bytes must be positive.")

        self.guard = guard
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_body_bytes = max_body_bytes

        self.opener = build_opener(
            NoAutomaticRedirectHandler()
        )

    @staticmethod
    def _origin(url: str) -> tuple:
        parsed = urlsplit(url)

        default_port = 443 if parsed.scheme.lower() == "https" else 80

        return (
            parsed.scheme.lower(),
            parsed.hostname.lower() if parsed.hostname else None,
            parsed.port or default_port,
        )

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict | None = None,
    ) -> dict:
        method = method.upper()

        # Keep the first version limited to passive HTTP methods.
        if method not in {"GET", "HEAD"}:
            raise ValueError(
                "This client currently supports GET and HEAD only."
            )

        current_url = self.guard.validate_url(url)

        request_headers = {
            "User-Agent": "Wily-Scanner/0.1",
            "Accept": "*/*",
        }

        for name, value in (headers or {}).items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise ValueError("HTTP headers must be strings.")

            if name.lower() == "host":
                raise ValueError(
                    "Overriding the Host header is not supported."
                )

            request_headers[name] = value

        redirects_followed = 0

        while True:
            # Every outbound request must pass the guard.
            self.guard.validate_url(current_url)

            req = Request(
                current_url,
                headers=request_headers,
                method=method,
            )

            try:
                response = self.opener.open(
                    req,
                    timeout=self.timeout,
                )
            except HTTPError as exc:
                # Redirects and HTTP error responses arrive here
                # because automatic redirects are disabled.
                response = exc
            except (URLError, TimeoutError, OSError) as exc:
                raise HTTPClientError(
                    f"HTTP request failed for {current_url}: {exc}"
                ) from exc

            status = response.getcode()

            if status in REDIRECT_CODES:
                location = response.headers.get("Location")
                response.close()

                if not location:
                    raise HTTPClientError(
                        f"HTTP {status} response has no Location header."
                    )

                # Resolve the redirect and check its destination
                # before another network request is sent.
                destination = self.guard.validate_redirect(
                    current_url,
                    location,
                )

                if redirects_followed >= self.max_redirects:
                    raise HTTPClientError(
                        "Maximum redirect count exceeded."
                    )

                # Do not forward credentials across origins.
                if self._origin(current_url) != self._origin(destination):
                    request_headers = {
                        name: value
                        for name, value in request_headers.items()
                        if name.lower() not in SENSITIVE_HEADERS
                    }

                if status == 303 and method != "HEAD":
                    method = "GET"

                redirects_followed += 1
                current_url = destination
                continue

            try:
                body = (
                    b""
                    if method == "HEAD"
                    else response.read(self.max_body_bytes + 1)
                )

                truncated = len(body) > self.max_body_bytes
                body = body[:self.max_body_bytes]

                result = {
                    "url": current_url,
                    "status": status,
                    "headers": dict(response.headers.items()),
                    "body": body,
                    "body_truncated": truncated,
                    "redirects_followed": redirects_followed,
                }

                return result
            finally:
                response.close()

    def get(self, url: str, *, headers: dict | None = None) -> dict:
        return self.request(url, method="GET", headers=headers)

    def head(self, url: str, *, headers: dict | None = None) -> dict:
        return self.request(url, method="HEAD", headers=headers)