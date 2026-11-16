"""Mandatory, centralized HTTP layer for every scanner.

Every request must go through here, no exceptions: ScopeManager and
AdaptiveRateLimiter are required at construction time (never optional),
so no scanner can route around scope policy by rolling its own HTTP
client.

Supports:
  - GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS
  - configurable timeouts
  - bounded retries + exponential backoff + jitter for 429 (idempotent
    methods only)
  - the Retry-After header
  - safe redirect handling: each hop is checked against scope before it
    is followed, and the chain stops and refuses if any hop lands outside
    scope
  - an IP-safety guard: the hostname of every request *and* every
    redirect hop is resolved and checked against private/loopback/
    link-local/metadata address ranges before connecting - so even a
    hostname that is legitimately in scope can never be used to reach an
    internal address via DNS (e.g. a target domain that resolves, or is
    made to resolve, to 169.254.169.254)
  - clear exceptions (ScopeError from core.scope_manager, HttpEngineError,
    HttpTimeoutError defined here)
"""

from __future__ import annotations

import difflib
import ipaddress
import logging
import socket
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import requests

from wily.core.http_policy import REDIRECT_STATUSES, resolve_redirect
from wily.core.rate_limiter import AdaptiveRateLimiter
from wily.core.scope_manager import ScopeError, ScopeManager

logger = logging.getLogger("wily.http_engine")

_IDEMPOTENT_METHODS = {"GET", "HEAD", "OPTIONS"}

_LOCAL_HOSTNAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})

# Default request headers shaped to look like an ordinary modern browser,
# not an automated scanner. The stock requests User-Agent
# ("python-requests/x.y.z") is one of the first things a WAF blocks on, so
# every scanner's traffic carries a realistic Chrome fingerprint by
# default. These are applied at the session level and any per-request
# header (e.g. Authorization, Origin, a forged Host) overrides them.
DEFAULT_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "application/json;q=0.9,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Upgrade-Insecure-Requests": "1",
}


class HttpEngineError(Exception):
    """A generic HTTP-layer error (not scope-related - that is ScopeError)."""


class HttpTimeoutError(HttpEngineError):
    pass


class TooManyRedirectsError(HttpEngineError):
    pass


class UnsafeAddressError(HttpEngineError):
    """Raised when a hostname resolves to a private/loopback/link-local/
    metadata address that must never be connected to, even if the
    hostname itself is within the authorized scope."""


def _ip_is_blocked(ip: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> bool:
    """Covers private/RFC1918, loopback, link-local (this is what blocks
    the 169.254.169.254 cloud instance-metadata service on AWS/GCP/Azure/
    DigitalOcean), multicast, reserved and unspecified ranges. Using the
    stdlib's own classification rather than a hand-rolled CIDR list means
    IPv6 equivalents (::1, fe80::/10, the IPv4-mapped
    ::ffff:169.254.169.254 form, ...) are covered for free."""
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


@dataclass
class HttpResponse:
    status_code: int
    headers: dict
    text: str
    elapsed_ms: float
    url: str  # the actual URL the response came from (after any redirects)


class HttpEngine:
    def __init__(
        self,
        scope_manager: "ScopeManager | None",
        rate_limiter: AdaptiveRateLimiter | None = None,
        timeout: float = 10.0,
        max_redirects: int = 5,
    ) -> None:
        if scope_manager is None:
            raise ValueError(
                "HttpEngine requires a ScopeManager - no HTTP requests without "
                "a scope check."
            )
        self.scope_manager = scope_manager
        self.rate_limiter = rate_limiter or AdaptiveRateLimiter()
        self.timeout = timeout
        self.max_redirects = max_redirects
        self._session = requests.Session()
        # Browser-like default headers for every request made through this
        # session; per-request headers passed to request() take precedence.
        self._session.headers.update(DEFAULT_HEADERS)
        # Per-run cache of host -> "is it safe to connect to" verdicts, so
        # repeated requests to the same host do not each pay a fresh DNS
        # round trip. Not persisted across HttpEngine instances.
        self._host_safety_cache: dict[str, bool] = {}

    def _host_is_safe(self, hostname: str) -> bool:
        """Resolve ``hostname`` and confirm every address it maps to is
        public (or an explicitly allowed loopback target).

        This check runs in addition to, not instead of, the ScopeManager
        check: ScopeManager verifies the *hostname* is inside the
        authorized domain scope, while this verifies the *address* that
        hostname currently resolves to is not an internal/metadata
        address. A hostname can pass scope (it is a subdomain of the
        authorized target) and still be unsafe to connect to, if an
        attacker-influenced DNS record points it at 169.254.169.254 or an
        internal IP.
        """
        host = (hostname or "").strip().rstrip(".").lower()
        if not host:
            return False

        allow_local = self.scope_manager.allow_local_targets
        if host in _LOCAL_HOSTNAMES:
            return allow_local

        if host in self._host_safety_cache:
            return self._host_safety_cache[host]

        safe = True
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
            safe = not _ip_is_blocked(ip) or (allow_local and ip.is_loopback)
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, None)
            except (socket.gaierror, UnicodeError, OSError):
                safe = False  # an unresolvable host is not a safe host
            else:
                for info in infos:
                    try:
                        candidate = ipaddress.ip_address(info[4][0].split("%")[0])
                    except ValueError:
                        safe = False
                        break
                    if _ip_is_blocked(candidate) and not (allow_local and candidate.is_loopback):
                        safe = False
                        break

        self._host_safety_cache[host] = safe
        return safe

    def request(
        self,
        method: str,
        url: str,
        headers: dict | None = None,
        body: str | None = None,
    ) -> HttpResponse:
        return self._request(method, url, headers, body, redirect_count=0)

    def _request(
        self,
        method: str,
        url: str,
        headers: dict | None,
        body: str | None,
        redirect_count: int,
    ) -> HttpResponse:
        self.scope_manager.require_in_scope(url)

        host = urlsplit(url).hostname or ""
        if not self._host_is_safe(host):
            raise UnsafeAddressError(
                f"Refusing to connect to {host!r}: it resolves to a private, "
                "loopback, link-local or otherwise internal/metadata address."
            )

        method_upper = method.upper()
        attempt = 0

        while True:
            self.rate_limiter.wait_for_host(host)
            try:
                resp = self._session.request(
                    method=method_upper,
                    url=url,
                    headers=headers or {},
                    data=body,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            except requests.exceptions.Timeout as exc:
                raise HttpTimeoutError(f"Timeout: {method_upper} {url}") from exc
            except requests.exceptions.RequestException as exc:
                raise HttpEngineError(f"{method_upper} {url}: {exc}") from exc

            self.rate_limiter.on_response(host, resp.status_code)

            if (
                resp.status_code == 429
                and method_upper in _IDEMPOTENT_METHODS
                and attempt < self.rate_limiter.max_retries
            ):
                delay = self.rate_limiter.backoff_delay(
                    attempt, resp.headers.get("Retry-After")
                )
                logger.info(
                    "429 from %s - waiting %.2fs (attempt %d/%d)",
                    host, delay, attempt + 1, self.rate_limiter.max_retries,
                )
                time.sleep(delay)
                attempt += 1
                continue

            if resp.status_code in REDIRECT_STATUSES and "Location" in resp.headers:
                if redirect_count >= self.max_redirects:
                    raise TooManyRedirectsError(
                        f"More than {self.max_redirects} redirects: {url}"
                    )

                next_url = resolve_redirect(self.scope_manager, url, resp.headers["Location"])

                next_method = method_upper
                next_body = body
                if resp.status_code in (301, 302, 303) and method_upper == "POST":
                    next_method = "GET"
                    next_body = None

                return self._request(
                    next_method, next_url, headers, next_body, redirect_count + 1
                )

            return HttpResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text,
                elapsed_ms=resp.elapsed.total_seconds() * 1000,
                url=url,
            )

    def similarity(self, text_a: str, text_b: str) -> float:
        """Similarity ratio (0..1) between two texts - used to detect
        soft-404s / fake blanket responses."""
        return difflib.SequenceMatcher(None, text_a, text_b).ratio()
