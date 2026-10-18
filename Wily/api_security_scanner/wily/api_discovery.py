#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wily :: wily/api_discovery.py
=============================
Black-box API endpoint discovery pipeline (Module 1 of the Wily scanner).

Fallback order (STRICT)
-----------------------
  0. User-provided spec .... An OpenAPI/Swagger spec (local file or URL) or a
                             direct API endpoint is used as-is; discovery is
                             skipped unless ``augment=True`` (see ``--augment``).
  1. Documentation probes .. Common hidden docs paths on the target
                             (/swagger.json, /openapi.yaml, /api-docs, ...).
  2. JavaScript scraping .... Fetch the homepage, extract <script src>,
                             modulepreload and webpack chunk references,
                             download the JS and regex-mine API endpoints,
                             including full absolute URLs and template paths.
  3. Smart fuzzing .......... If the harvest is thin (< fuzz_threshold), probe
                             a built-in, lightweight wordlist of common API
                             routes. Non-destructive: GET/HEAD only, no
                             payloads. A soft-404 / WAF baseline is sampled
                             first so blanket responses do not pollute results.

Design principles
-----------------
* Fully asynchronous (aiohttp), bounded concurrency (semaphore) with an
  optional token-bucket rate limiter, per-request timeouts and defensive
  error handling - a single failure never aborts the pipeline.
* Non-destructive by construction: only GET/HEAD requests are issued,
  no fuzzy payloads, no state-changing verbs.
* Output is a clean, deterministic JSON map (see ``DiscoveryReport.to_json``).

Library integration
-------------------
    from wily.api_discovery import ApiDiscoveryPipeline, DiscoveryConfig

    cfg = DiscoveryConfig(target="https://example.com")
    report = await ApiDiscoveryPipeline(cfg).run()
    payload = report.to_json()          # plain dict, JSON-serializable

CLI
---
    python -m wily.api_discovery https://example.com --output report.json
    python -m wily.api_discovery https://example.com --spec ./openapi.json
    python -m wily.api_discovery https://example.com --aggressive -v

Notes
-----
* YAML specs require PyYAML (``pip install PyYAML``); JSON specs always work.
* "Same site" matching is a pragmatic eTLD+1 heuristic (no Public Suffix
  List); tune via ``DiscoveryConfig`` / the CLI flags if your scope differs.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import logging
import re
import secrets
import socket
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urldefrag, urljoin, urlparse

try:
    import aiohttp
except ImportError:  # pragma: no cover
    sys.stderr.write("Wily requires aiohttp. Install it with:  pip install aiohttp\n")
    raise SystemExit(2)

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    yaml = None  # YAML specs will be skipped with an informative log message.


logger = logging.getLogger("wily.api_discovery")

__all__ = [
    "ApiDiscoveryPipeline",
    "DiscoveryConfig",
    "DiscoveryReport",
    "EndpointRecord",
    "canonical_url",
    "same_site",
    "id_like_names",
    "PARAM_NAME_ID_MARKER",
]

# ---------------------------------------------------------------------------
# Constants and signatures
# ---------------------------------------------------------------------------

USER_AGENT = "Wily/0.1 (cloud-security-scanner; authorized-security-testing)"
DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
}

# Stage 1: common hidden documentation locations (ordered by popularity).
DOCUMENTATION_PATHS: Tuple[str, ...] = (
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/api-docs",
    "/api-docs.json",
    "/api/docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger-resources",
    "/docs",
    "/redoc",
    "/swagger",
    "/swagger-ui.html",
    "/.well-known/openapi.json",
)

# Stage 3: built-in lightweight wordlist of common API routes. The list is
# intentionally small and "quiet" so the fuzzing stage stays fast and
# non-destructive; extend it in your own deployment if needed.
FUZZ_ROUTES: Tuple[str, ...] = (
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/health",
    "/api/status",
    "/api/version",
    "/api/ping",
    "/api/info",
    "/api/users",
    "/api/user",
    "/api/me",
    "/api/account",
    "/api/accounts",
    "/api/auth",
    "/api/login",
    "/api/logout",
    "/api/session",
    "/api/config",
    "/api/settings",
    "/api/metrics",
    "/api/admin",
    "/api/keys",
    "/api/tokens",
    "/api/search",
    "/api/upload",
    "/api/files",
    "/api/v1/users",
    "/api/v1/auth",
    "/api/v1/login",
    "/api/v1/me",
    "/api/v1/health",
    "/api/v1/status",
    "/api/v1/version",
    "/api/v1/config",
    "/api/v2/users",
    "/api/v2/auth",
    "/api/v2/health",
    "/api/graphql",
    "/graphql",
    "/gql",
    "/graphql/schema",
    "/rest",
    "/rest/api",
    "/services",
    "/internal/api",
    "/admin/api",
    "/v1",
    "/v2",
    "/health",
    "/healthz",
    "/readyz",
    "/livez",
    "/version",
    "/api/swagger.json",
    "/api/openapi.json",
)

def _load_extended_wordlist() -> Tuple[str, ...]:
    """Load the SecLists-derived wordlist (thousands of routes) if it ships with this install.

    Deliberately NOT merged into ``FUZZ_ROUTES``: that constant backs the
    default "thin harvest -> fuzz a little" fallback, which is meant to be
    quick and quiet. This extended list is opt-in only (``DiscoveryConfig.
    deep_fuzz=True`` / CLI ``--deep-fuzz``) for when the tester deliberately
    wants a much wider sweep. Missing file -> empty tuple, logged once, never
    a hard failure.
    """
    path = Path(__file__).resolve().parent / "wordlists" / "api_fuzz_extended.txt"
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        logger.debug("Extended wordlist not found at %s; --deep-fuzz will have nothing to add", path)
        return ()
    routes: List[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = "/" + line.strip("/")
        routes.append(line)
    return tuple(routes)


# Loaded lazily at import time; harmless if the data file isn't shipped.
EXTENDED_FUZZ_ROUTES: Tuple[str, ...] = _load_extended_wordlist()

# HTTP methods recognised in OpenAPI path items.
HTTP_METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)

# Statuses that prove "something is listening" during the fuzzing stage.
# 401/403/405 mean the route exists but is protected / method-restricted.
LIVE_STATUSES = frozenset(
    {301, 302, 303, 307, 308, 401, 403, 405}  # 2xx handled by range check
)

# Generic HTTP verbs that sometimes appear as quoted strings in JS bundles.
_HTTP_VERBS = frozenset(
    {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
)

# ---------------------------------------------------------------------------
# Regex arsenal
# ---------------------------------------------------------------------------

# --- JavaScript endpoint mining -------------------------------------------------
# Each pattern exposes one named group: "path".
JS_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    # 1) Anything that smells like an API route by its markers.
    (
        "api-path",
        re.compile(
            r"""["'`](?P<path>/(?:api|rest|graphql|gql|rpc|webhooks?|internal|services?|admin|auth|oauth2?|sso|v\d+)\b[^"'`\s\\]{0,250})["'`]""",
            re.IGNORECASE,
        ),
    ),
    # 2) Strings passed to networking primitives / config keys.
    (
        "request-call",
        re.compile(
            r"""\b(?:fetch|axios(?:\.\w+)?|\.open|\.send|url|uri|endpoint|baseUrl|baseurl|apiUrl|api_url|api_base|API_BASE|API_URL)\s*[=(:,]\s*["'`](?P<path>[^"'`\s\\]{2,250})["'`]""",
            re.IGNORECASE,
        ),
    ),
    # 3) Absolute URLs (same-site filtering happens later).
    (
        "absolute-url",
        re.compile(
            r"""["'`](?P<path>https?://[^"'`\s\\<>]{4,300})["'`]""",
            re.IGNORECASE,
        ),
    ),
    # 4) Generic multi-segment paths and templated routes (/users/{id}).
    (
        "path-like",
        re.compile(
            r"""["'`](?P<path>/[A-Za-z0-9._~\-{}:]+(?:/[A-Za-z0-9._~\-{}:]*)+)["'`]"""
        ),
    ),
)

# Webpack/Vite-style chunk references, used to crawl lazy-loaded bundles.
JS_CHUNK_SRC = re.compile(
    r"""["']([^"'\s<>]{1,180}?\.(?:js|mjs))(?:\?[^"'\s]*)?["']""", re.IGNORECASE
)

# Swagger-UI / ReDoc HTML often reveals the real spec URL. Also matches
# inline SwaggerUIBundle({ url: "..." }) configuration.
UI_SPEC_URL = re.compile(
    r"""(?:spec-url|specUrl|spec|url)\s*[:=]\s*["'](?P<target>[^"']{1,300})["']""",
    re.IGNORECASE,
)

# --- Filtering heuristics -------------------------------------------------------

# File extensions that are never API endpoints. NOTE: ".json" is deliberately
# allowed - JSON endpoints are frequently real APIs.
STATIC_SUFFIX_BLACKLIST = re.compile(
    r"\.(?:js|mjs|cjs|css|map|png|jpe?g|gif|svg|webp|avif|ico|bmp|"
    r"woff2?|ttf|otf|eot|mp[34]|webm|ogg|wav|pdf|zip|tar|gz|7z|rar|"
    r"exe|dmg|apk|txt|xml|html?|md|ya?ml)$",
    re.IGNORECASE,
)

# API markers used to promote a path to "plausible route".
API_MARKERS = re.compile(
    r"/(?:api|rest|graphql|gql|rpc|webhooks?|internal|services?|admin|auth|"
    r"oauth2?|sso|v\d+)(?:/|$)",
    re.IGNORECASE,
)

# Template placeholders: {id}, :id, <id>.
PLACEHOLDER = re.compile(r"\{[^/{}]{1,64}\}|:[A-Za-z_][A-Za-z0-9_]{0,63}(?:/|$)|<[^/<>]{1,64}>")

# A candidate starting with a path segment (relative request like "api/x").
RELATIVE_SEGMENT = re.compile(r"^[A-Za-z0-9._~\-%]+/")

# Any plausibly meaningful segment (used to accept fetch("...") arguments).
SEGMENT_LIKE = re.compile(r"/[A-Za-z0-9._~\-%]{2,}")

SCRIPT_TAG = re.compile(r"<script\b[^>]*>", re.IGNORECASE)
LINK_TAG = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
ATTR_RE = re.compile(
    r"""([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"""
)


# ---------------------------------------------------------------------------
# Small pure helpers (unit-testable, no I/O)
# ---------------------------------------------------------------------------


def canonical_url(url: str) -> Optional[str]:
    """Normalise an endpoint URL into a stable dedupe key.

    Rules: lowercase host, strip leading ``www.``, drop default ports,
    drop query string and fragment, strip trailing slash (except root).
    Returns ``None`` for non-HTTP(S) or malformed input.
    """
    if not url:
        return None
    clean, _ = urldefrag(url.strip())
    try:
        parts = urlparse(clean)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not host:
        return None
    if host.startswith("www."):
        host = host[4:]
    netloc = host
    if port and port not in (80, 443):
        netloc = f"{host}:{port}"
    path = parts.path or "/"
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    return f"{parts.scheme}://{netloc}{path}"


def _root_domain(host: str) -> str:
    """Naive eTLD+1 approximation (last two labels). No Public Suffix List."""
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) > 2 else host


def _is_ip(host: str) -> bool:
    """True when ``host`` is an IPv4/IPv6 literal."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def same_site(host_a: str, host_b: str) -> bool:
    """Heuristic same-site check: exact host or shared root domain."""
    a = (host_a or "").lower().rstrip(".")
    b = (host_b or "").lower().rstrip(".")
    if not a or not b:
        return False
    if a == b:
        return True
    if _is_ip(a) or _is_ip(b):
        return a == b
    return _root_domain(a) == _root_domain(b)


# Hostnames that resolve to the local machine via convention (/etc/hosts,
# browser-reserved names) rather than a literal loopback string - blocked
# even though they don't parse as an ipaddress literal themselves.
_LOCAL_HOSTNAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})


def _ip_is_blocked(ip: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> bool:
    """SSRF guard core: is ``ip`` somewhere Wily must never connect to?

    Covers private/RFC1918, loopback, link-local (this is what blocks the
    169.254.169.254 cloud instance-metadata service on AWS/GCP/Azure/
    DigitalOcean), multicast, reserved and unspecified ranges. Using the
    stdlib's own classification rather than a hand-rolled CIDR list means
    IPv6 equivalents (::1, fe80::/10, the IPv4-mapped ::ffff:169.254.169.254
    form, ...) are covered for free instead of being a second list to keep
    in sync.
    """
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def plausible_route(path: str) -> bool:
    """Heuristic: does a path look like an API route (markers or placeholders)?"""
    return bool(API_MARKERS.search(path) or PLACEHOLDER.search(path))


PARAM_NAME_ID_MARKER = re.compile(
    r"(?:^|[_\-])(?:id|uuid|guid)$|tenant|account|customer|owner|org(?:anization)?[_\-]?id",
    re.IGNORECASE,
)


def id_like_names(names: Iterable[str]) -> List[str]:
    """Query/body parameter *names* that smell like an object or tenant
    reference, independent of what their value looks like.

    Separate from the ID-*shape* regexes (``_NUMERIC_ID``/``_UUID``/
    ``_MONGO_OBJECT_ID`` in ``traffic_monitor``), which only ever look at
    *path* segments. A cross-tenant parameter is very often carried as
    ``?tenant_id=123`` or a JSON body field instead of a path segment - a
    name-based check is the only way to catch that case.
    """
    return sorted(n for n in names if isinstance(n, str) and PARAM_NAME_ID_MARKER.search(n))


def _path_param_positions(raw_path: str, names: Set[str]) -> List[int]:
    """0-based path-segment index of each named path parameter.

    OpenAPI path templates write a parameter as a literal ``{name}``
    segment, so this is a straight string match against the declared
    parameter names - no guessing involved, unlike the ID-*shape* regexes
    ``traffic_monitor`` has to fall back on for live, already-filled-in URLs.
    """
    positions: List[int] = []
    segments = [s for s in raw_path.split("/") if s]
    for i, seg in enumerate(segments):
        if seg.startswith("{") and seg.endswith("}") and seg[1:-1] in names:
            positions.append(i)
    return positions


def _status_is_live(status: int) -> bool:
    """Fuzzing liveness: 2xx plus explicit protected/redirect statuses."""
    return 200 <= status < 300 or status in LIVE_STATUSES


def _to_int(value: Optional[str]) -> Optional[int]:
    """Best-effort int conversion for header values."""
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _parse_attrs(tag: str) -> Dict[str, str]:
    """Extract HTML attributes from a raw tag string."""
    attrs: Dict[str, str] = {}
    for match in ATTR_RE.finditer(tag):
        name = match.group(1).lower()
        attrs[name] = match.group(2) or match.group(3) or match.group(4) or ""
    return attrs


def extract_script_urls(html: str, base_url: str) -> List[str]:
    """Return absolute URLs of <script src> and modulepreload/preload scripts."""
    found: List[str] = []

    def _add(raw: str) -> None:
        raw = raw.strip()
        if not raw or raw.startswith(("data:", "javascript:", "blob:", "mailto:", "#")):
            return
        resolved = urljoin(base_url, raw)
        parts = urlparse(resolved)
        if parts.scheme in ("http", "https") and parts.hostname:
            found.append(resolved)

    for tag in SCRIPT_TAG.findall(html):
        attrs = _parse_attrs(tag)
        if attrs.get("src"):
            _add(attrs["src"])

    for tag in LINK_TAG.findall(html):
        attrs = _parse_attrs(tag)
        rel = attrs.get("rel", "").lower()
        if "modulepreload" in rel or ("preload" in rel and attrs.get("as", "").lower() == "script"):
            if attrs.get("href"):
                _add(attrs["href"])

    # Preserve order while removing duplicates.
    return list(dict.fromkeys(found))


def parse_spec_bytes(data: bytes) -> Optional[Dict[str, Any]]:
    """Parse JSON or YAML bytes into a dict that really looks like a spec."""
    text = data.decode("utf-8", errors="replace")
    obj: Any = None

    # Fast path: JSON. Only fall back to YAML when the payload hints at it.
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        if yaml is None:
            if re.search(r"^\s*(openapi|swagger)\s*:", text, re.IGNORECASE | re.MULTILINE):
                logger.warning(
                    "Found a YAML spec but PyYAML is not installed "
                    "(pip install PyYAML) - skipping this document"
                )
            return None
        if not re.search(r"^\s*(openapi|swagger|paths)\s*:|^---", text, re.IGNORECASE | re.MULTILINE):
            return None
        try:
            obj = yaml.safe_load(text)
        except Exception:  # noqa: BLE001 - YAML libs raise many exception types
            return None

    if not isinstance(obj, dict):
        return None
    if "openapi" in obj or "swagger" in obj:
        return obj
    if isinstance(obj.get("paths"), dict) and obj["paths"]:
        return obj
    return None


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class _RateLimiter:
    """Small async token-bucket pacing helper (requests per second).

    ``rate <= 0`` disables throttling entirely.
    """

    def __init__(self, rate: float) -> None:
        self._interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next_ts = 0.0

    async def acquire(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next_ts - now)
            self._next_ts = max(self._next_ts, now) + self._interval
        if wait:
            await asyncio.sleep(wait)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class _Response:
    """Lightweight HTTP response container."""

    status: int
    url: str
    headers: Dict[str, str]
    body: Optional[bytes] = None


@dataclass
class _Probe:
    """Result of a liveness probe (HEAD, GET fallback)."""

    status: int
    length: Optional[int]
    content_type: Optional[str]


@dataclass
class EndpointRecord:
    """One discovered endpoint and its provenance.

    ``replay_samples`` is intentionally runtime-only: it carries the concrete
    URL/query/body observed during authorised traffic capture so Stage 5 can
    replay a representative request, without serialising potentially sensitive
    request data into the JSON report.
    """

    url: str  # canonical URL (dedupe key)
    path: str
    methods: Set[str] = field(default_factory=lambda: {"*"})
    sources: Set[str] = field(default_factory=set)
    status: Optional[int] = None
    content_type: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    replay_samples: List[Dict[str, Any]] = field(default_factory=list, repr=False)


def _merge_replay_sample(samples: List[Dict[str, Any]], sample: Dict[str, Any]) -> None:
    """Keep distinct observed requests by method/URL/body, in memory only."""
    signature = (
        str(sample.get("method", "")).upper(),
        str(sample.get("url", "")),
        str(sample.get("body", "")),
    )
    if not signature[1]:
        return
    for existing in samples:
        existing_signature = (
            str(existing.get("method", "")).upper(),
            str(existing.get("url", "")),
            str(existing.get("body", "")),
        )
        if existing_signature == signature:
            return
    # Keep a small bounded set per canonical endpoint. Multiple observed IDs
    # are useful for ownership testing, but unbounded samples waste memory.
    if len(samples) < 10:
        samples.append(dict(sample))


@dataclass
class DiscoveryReport:
    """Aggregated discovery result; ``to_json()`` yields the final JSON map."""

    target: str
    spec_source: Optional[str] = None
    endpoints: Dict[str, EndpointRecord] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

    def add_endpoint(
        self,
        url: str,
        source: str,
        methods: Optional[Iterable[str]] = None,
        status: Optional[int] = None,
        content_type: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        replay_sample: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add or merge an endpoint, keyed by its canonical URL.

        ``details`` is an optional free-form payload (query/body/path params,
        auth info, a request/response sample, ...), populated by the
        traffic-monitoring stage and, now, by spec-sourced operations too. It
        is merged shallowly, with list-valued sub-keys ("query_params",
        "body_params", "path_param_positions") unioned so an endpoint seen
        across several sources (e.g. in both the spec and live traffic)
        accumulates detail from all of them instead of the second source
        being silently dropped.
        """
        key = canonical_url(url)
        if not key:
            return
        normalised_methods = {m.upper() for m in methods} if methods else {"*"}
        record = self.endpoints.get(key)
        if record is None:
            self.endpoints[key] = EndpointRecord(
                url=key,
                path=urlparse(key).path or "/",
                methods=normalised_methods,
                sources={source},
                status=status,
                content_type=content_type,
                details=dict(details) if details else None,
            )
            record = self.endpoints[key]
            if replay_sample:
                _merge_replay_sample(record.replay_samples, replay_sample)
            return
        # Merge into existing record.
        record.sources.add(source)
        if "*" in record.methods or "*" in normalised_methods:
            record.methods = {"*"}
        else:
            record.methods |= normalised_methods
        if status is not None:
            record.status = status
        if content_type and not record.content_type:
            record.content_type = content_type
        if replay_sample:
            _merge_replay_sample(record.replay_samples, replay_sample)
        if details:
            if record.details is None:
                record.details = dict(details)
            else:
                for dkey, dval in details.items():
                    if dkey in (
                        "query_params",
                        "body_params",
                        "path_param_positions",
                        "id_like_query_params",
                        "id_like_body_params",
                    ) and isinstance(dval, list):
                        existing = set(record.details.get(dkey) or [])
                        record.details[dkey] = sorted(existing | set(dval))
                    elif dkey not in record.details or not record.details[dkey]:
                        record.details[dkey] = dval

    def to_json(self) -> Dict[str, Any]:
        """Render the final, deterministic JSON map."""
        by_source: Dict[str, int] = {}
        for record in self.endpoints.values():
            for source in record.sources:
                by_source[source] = by_source.get(source, 0) + 1
        stats = dict(self.stats)
        stats["total_endpoints"] = len(self.endpoints)
        stats["by_source"] = by_source
        return {
            "tool": "wily-api-discovery",
            "target": self.target,
            "spec_source": self.spec_source,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "stats": stats,
            "endpoints": {
                url: {
                    "path": record.path,
                    "methods": sorted(record.methods),
                    "sources": sorted(record.sources),
                    "status": record.status,
                    "content_type": record.content_type,
                    **({"details": record.details} if record.details else {}),
                }
                for url, record in sorted(self.endpoints.items())
            },
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class DiscoveryConfig:
    """Everything the pipeline needs to run (safe defaults for CLI use)."""

    target: str
    spec: Optional[str] = None  # user-provided OpenAPI/Swagger spec (path or URL)
    augment: bool = False  # keep discovering even when a spec was supplied
    aggressive: bool = False  # run every stage regardless of early hits
    enable_fuzzing: bool = True
    fuzz_threshold: int = 8  # fuzz only when fewer endpoints were found
    # Off by default on purpose: FUZZ_ROUTES (~56 routes) is the quiet
    # fallback. Flip this on to also sweep EXTENDED_FUZZ_ROUTES, the
    # SecLists-derived wordlist (thousands of routes) - a deliberate,
    # heavier pass, not something every automatic run should pay for.
    deep_fuzz: bool = False
    concurrency: int = 15  # max in-flight HTTP requests
    timeout: float = 10.0  # per-request total timeout (seconds)
    rate_limit: float = 0.0  # requests/second; 0 disables throttling
    verify_ssl: bool = True
    include_external_js: bool = False  # off by default: third-party/CDN JS is
    # essentially never where a target's own API routes live, so fetching it
    # only adds SSRF surface and wasted budget. Flip on with --include-external-js
    # for a target you know lazy-loads its own bundles from another host you control.
    max_js_files: int = 40  # crawl budget for JS assets
    max_body_bytes: int = 3_000_000  # cap for any downloaded body


# ---------------------------------------------------------------------------
# The pipeline
# ---------------------------------------------------------------------------


class ApiDiscoveryPipeline:
    """Smart fallback pipeline for black-box API endpoint discovery."""

    def __init__(self, config: DiscoveryConfig) -> None:
        self.cfg = config
        target = (config.target or "").strip()
        if not re.match(r"^https?://", target, re.IGNORECASE):
            target = "https://" + target
        target = target.rstrip("/")
        parts = urlparse(target)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"Invalid target URL: {config.target!r}")
        self.base_url = target
        self.origin = f"{parts.scheme}://{parts.netloc}"
        self.host = parts.hostname or ""

        self._sem = asyncio.Semaphore(max(1, config.concurrency))
        self._limiter = _RateLimiter(config.rate_limit)
        self._session: Optional[aiohttp.ClientSession] = None
        self._requests = 0
        self._errors: List[str] = []
        # SSRF guard: cache DNS-resolution verdicts per host for this run only
        # (not persisted across runs) so repeated fuzz/doc/JS probes against
        # the same host don't each pay a fresh DNS round trip.
        self._host_safety_cache: Dict[str, bool] = {}

    # -- low-level HTTP ------------------------------------------------------

    async def _host_is_safe(self, hostname: str) -> bool:
        """Resolve ``hostname`` and confirm every address it maps to is public.

        This is the pipeline's SSRF guard. It is checked before the first
        connection attempt to a URL *and* again on every redirect hop (see
        ``_request``), so a malicious or compromised target cannot bounce
        Wily into 169.254.169.254 (cloud instance metadata on AWS/GCP/Azure/
        DigitalOcean), 127.0.0.1, an RFC1918-internal service, etc. - whether
        that address is reached directly, via DNS, or via a ``Location``
        header. Verdicts are cached per host for this run only; a host that
        re-resolves differently mid-scan (DNS rebinding) is a known, accepted
        residual risk for a scan that typically completes in minutes - see
        the module notes.
        """
        host = (hostname or "").strip().rstrip(".").lower()
        if not host:
            return False
        if host in _LOCAL_HOSTNAMES:
            return False
        if host in self._host_safety_cache:
            return self._host_safety_cache[host]

        safe = True
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
            safe = not _ip_is_blocked(ip)
        except ValueError:
            try:
                loop = asyncio.get_event_loop()
                infos = await loop.getaddrinfo(host, None)
            except (socket.gaierror, UnicodeError, OSError):
                safe = False  # unresolvable host is not a safe host
            else:
                for info in infos:
                    try:
                        candidate = ipaddress.ip_address(info[4][0].split("%")[0])
                    except ValueError:
                        safe = False
                        break
                    if _ip_is_blocked(candidate):
                        safe = False
                        break
        self._host_safety_cache[host] = safe
        return safe

    async def _request(
        self,
        url: str,
        *,
        method: str = "GET",
        read_body: bool = False,
        follow: bool = True,
    ) -> Optional[_Response]:
        """Perform one HTTP request with throttling, timeout, SSRF guarding
        and error capture.

        Returns ``None`` on any transport failure, or when the host (or a
        redirect target) resolves to a private/internal/metadata address.
        Redirects are followed manually, one hop at a time - specifically so
        every hop gets its own SSRF check. aiohttp's own ``allow_redirects``
        would follow a 302 straight to 169.254.169.254 without ever
        re-checking it, which defeats the point of checking the first URL.
        """
        assert self._session is not None, "pipeline session not initialised"
        current_url, current_method = url, method

        for hop in range(6):  # original attempt + up to 5 redirects
            hostname = urlparse(current_url).hostname or ""
            if not await self._host_is_safe(hostname):
                self._errors.append(
                    f"{current_method} {current_url}: blocked by SSRF guard "
                    "(private/internal/metadata address)"
                )
                logger.warning("SSRF guard: refusing to connect to %s", hostname)
                return None

            await self._limiter.acquire()
            async with self._sem:
                try:
                    async with self._session.request(
                        current_method, current_url, allow_redirects=False
                    ) as resp:
                        self._requests += 1
                        if (
                            follow
                            and resp.status in (301, 302, 303, 307, 308)
                            and hop < 5
                        ):
                            location = resp.headers.get("Location")
                            if location:
                                current_url = urljoin(str(resp.url), location)
                                if resp.status == 303 and current_method != "HEAD":
                                    current_method = "GET"
                                continue  # next hop re-checks host safety
                        body: Optional[bytes] = None
                        if read_body and current_method != "HEAD":
                            body = await resp.content.read(self.cfg.max_body_bytes)
                        return _Response(
                            status=resp.status,
                            url=str(resp.url),
                            headers=dict(resp.headers),
                            body=body,
                        )
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
                    self._errors.append(
                        f"{current_method} {current_url}: {type(exc).__name__}: {exc}"
                    )
                    logger.debug("Request failed: %s %s (%s)", current_method, current_url, exc)
                    return None

        self._errors.append(f"{method} {url}: too many redirects")
        return None

    async def _fetch_text(self, url: str) -> Optional[str]:
        """GET a URL and decode it as UTF-8 (with lossy fallback)."""
        resp = await self._request(url, read_body=True)
        if resp is None or resp.status >= 400 or not resp.body:
            return None
        return resp.body.decode("utf-8", errors="replace")

    async def _probe(self, url: str) -> Optional[_Probe]:
        """Liveness probe: HEAD first, GET fallback for method-blocking servers."""
        resp = await self._request(url, method="HEAD", follow=False)
        if resp is None:
            return None
        if resp.status in (405, 501):  # HEAD unsupported -> retry with GET
            resp = await self._request(url, method="GET", follow=False)
            if resp is None:
                return None
        return _Probe(
            status=resp.status,
            length=_to_int(resp.headers.get("Content-Length")),
            content_type=resp.headers.get("Content-Type"),
        )

    # -- stage 0: user-provided spec ----------------------------------------

    async def _stage_user_spec(self, report: DiscoveryReport) -> bool:
        """Load a user-supplied OpenAPI/Swagger spec (file or URL)."""
        spec_ref = self.cfg.spec
        if not spec_ref:
            return False

        data: Optional[bytes] = None
        source_url: Optional[str] = None

        if re.match(r"^https?://", spec_ref, re.IGNORECASE):
            resp = await self._request(spec_ref, read_body=True, follow=True)
            if resp is not None and resp.status == 200:
                data, source_url = resp.body, resp.url
        else:
            path = Path(spec_ref)
            if path.is_file():
                try:
                    data = path.read_bytes()
                except OSError as exc:
                    self._errors.append(f"cannot read spec file {spec_ref}: {exc}")
            else:
                self._errors.append(f"spec file not found: {spec_ref}")

        spec = parse_spec_bytes(data) if data else None
        if spec is None:
            logger.error("Could not load a valid OpenAPI/Swagger spec from %s", spec_ref)
            self._errors.append(f"invalid user spec: {spec_ref}")
            return False

        report.spec_source = source_url or spec_ref
        count = self._endpoints_from_spec(spec, report, "user_spec", source_url)
        logger.info("Loaded user spec from %s (%d operation(s))", report.spec_source, count)
        return count > 0

    # -- stage 1: documentation discovery ------------------------------------

    async def _stage_docs(self, report: DiscoveryReport) -> Optional[str]:
        """Probe common documentation paths; return the spec URL on a hit."""
        logger.info(
            "Stage 1 (doc discovery): probing %d common documentation paths", len(DOCUMENTATION_PATHS)
        )

        async def probe(doc_path: str) -> Optional[Tuple[str, Dict[str, Any]]]:
            """Try one doc path; returns (spec_url, spec_obj) when valid."""
            try:
                doc_url = self.origin + doc_path
                resp = await self._request(doc_url, read_body=True, follow=True)
                if resp is None or resp.status != 200 or not resp.body:
                    return None
                ctype = resp.headers.get("Content-Type", "")
                spec = parse_spec_bytes(resp.body)
                if spec is not None:
                    return doc_url, spec
                # Not a raw spec: maybe a Swagger-UI/ReDoc page or a
                # springfox /swagger-resources listing pointing at the spec.
                sniffed = await self._sniff_ui_spec(resp.body, doc_url, ctype)
                if sniffed is not None:
                    return sniffed
                return None
            except Exception as exc:  # noqa: BLE001 - never kill the stage
                logger.debug("Doc probe failed for %s: %s", doc_path, exc)
                return None

        pending = {asyncio.create_task(probe(p)) for p in DOCUMENTATION_PATHS}
        result: Optional[Tuple[str, Dict[str, Any]]] = None
        while pending and result is None:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                if task.cancelled():
                    continue
                try:
                    res = task.result()
                except Exception:  # noqa: BLE001 - defensive, probe is guarded
                    res = None
                if res:
                    result = res
                    break
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

        if result is None:
            logger.info("No documentation/spec found via common paths")
            return None

        spec_url, spec = result
        added = self._endpoints_from_spec(spec, report, "doc_discovery", spec_url)
        if added == 0:
            logger.info("Spec at %s contained no usable operations", spec_url)
            return None
        report.spec_source = spec_url
        logger.info("Discovered usable spec at %s (%d operation(s))", spec_url, added)
        return spec_url

    async def _sniff_ui_spec(
        self, body: bytes, doc_url: str, ctype: str
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """Follow Swagger-UI/ReDoc pages and springfox resource listings.

        Bounded to a single hop: sniff a candidate spec URL, fetch it once,
        parse it, return it - or give up quietly.
        """
        text = body[:262144].decode("utf-8", errors="replace")
        candidates: List[str] = []

        # springfox: /swagger-resources returns [{"name": ..., "url": "/v2/api-docs"}]
        if "json" in ctype.lower() or text.lstrip().startswith("["):
            try:
                listing = json.loads(text)
            except (ValueError, TypeError):
                listing = None
            if isinstance(listing, list):
                for item in listing:
                    if isinstance(item, dict) and isinstance(item.get("url"), str):
                        candidates.append(item["url"])

        # Swagger-UI / ReDoc HTML: url: "...", spec-url="..."
        low = text.lower()
        if not candidates and any(k in low for k in ("swagger", "redoc", "openapi", "api-docs")):
            for match in UI_SPEC_URL.finditer(text):
                target = match.group("target").strip()
                low_target = target.lower()
                if re.search(r"\.(?:json|ya?ml)$", low_target) or any(
                    k in low_target for k in ("api-docs", "openapi", "swagger", "/docs")
                ):
                    candidates.append(target)

        for candidate in candidates[:2]:  # keep it cheap and predictable
            spec_url = urljoin(doc_url, candidate)
            resp = await self._request(spec_url, read_body=True, follow=True)
            if resp is None or resp.status != 200 or not resp.body:
                continue
            spec = parse_spec_bytes(resp.body)
            if spec is not None:
                logger.info("Followed documentation reference -> %s", spec_url)
                return spec_url, spec
        return None

    # -- OpenAPI/Swagger parsing ---------------------------------------------

    def _endpoints_from_spec(
        self,
        spec: Dict[str, Any],
        report: DiscoveryReport,
        source: str,
        spec_url: Optional[str],
    ) -> int:
        """Extract method+path operations - *with their parameters* - from a
        parsed spec into the report.

        A spec is the single best source of truth the pipeline ever sees:
        unlike a JS-mined or fuzzed guess, it states directly which path
        segments are object identifiers and what a request body expects -
        exactly what a later two-account BOLA/authorization-testing stage
        needs to target. That detail is captured here in the same
        ``details`` shape ``traffic_monitor.CapturedEndpoint`` produces
        (``path_param_positions`` / ``query_params`` / ``body_params``), so
        a spec-sourced hit and a later traffic-sourced hit on the same URL
        merge into one richer record instead of either one being discarded.
        """
        paths = spec.get("paths")
        if not isinstance(paths, dict):
            return 0
        base = self._spec_base_url(spec, spec_url)
        added = 0
        for raw_path, item in paths.items():
            if not isinstance(raw_path, str) or not isinstance(item, dict):
                continue

            # Path-level parameters apply to every operation on this path;
            # each operation can add more of its own.
            path_level_params = item.get("parameters")
            path_level_params = path_level_params if isinstance(path_level_params, list) else []

            methods: Set[str] = set()
            path_names: Set[str] = set()
            query_names: Set[str] = set()
            body_names: Set[str] = set()

            for m, operation in item.items():
                if not (
                    isinstance(m, str)
                    and m.lower() in HTTP_METHODS
                    and isinstance(operation, dict)
                ):
                    continue
                methods.add(m.upper())
                op_params = operation.get("parameters")
                op_params = op_params if isinstance(op_params, list) else []
                for param in (*path_level_params, *op_params):
                    if not isinstance(param, dict):
                        continue
                    name, location = param.get("name"), param.get("in")
                    if not isinstance(name, str):
                        continue
                    if location == "path":
                        path_names.add(name)
                    elif location == "query":
                        query_names.add(name)
                body_names |= self._request_body_field_names(operation)

            if not methods:
                continue

            url = self._join_url(base, raw_path)
            details: Optional[Dict[str, Any]] = None
            path_positions = _path_param_positions(raw_path, path_names)
            id_like_query = id_like_names(query_names)
            id_like_body = id_like_names(body_names)
            if path_positions or query_names or body_names:
                details = {
                    "path_param_positions": path_positions,
                    "query_params": sorted(query_names),
                    "body_params": sorted(body_names),
                    "id_like_query_params": id_like_query,
                    "id_like_body_params": id_like_body,
                    # A path-position ID (/orders/{id}) and a tenant-shaped
                    # query/body field (?tenant_id=...) are the same BOLA
                    # risk class - this candidate from the Gemini walkthrough
                    # uses ?tenant_id=, which only the name-based check below
                    # ever catches.
                    "bola_candidate": bool(path_positions or id_like_query or id_like_body),
                }
            report.add_endpoint(url, source=source, methods=methods, details=details)
            added += 1
        return added

    @staticmethod
    def _request_body_field_names(operation: Dict[str, Any]) -> Set[str]:
        """Best-effort top-level property names from an OpenAPI 3.x ``requestBody``.

        Only resolves the common case - an inline object schema under a
        JSON/form media type. ``$ref``, ``allOf``/``oneOf`` and nested
        schemas are left alone; this seeds a candidate list for the testing
        stage, it is not a full OpenAPI schema resolver.
        """
        body = operation.get("requestBody")
        if not isinstance(body, dict):
            return set()
        content = body.get("content")
        if not isinstance(content, dict):
            return set()
        names: Set[str] = set()
        for media in content.values():
            if not isinstance(media, dict):
                continue
            schema = media.get("schema")
            if isinstance(schema, dict) and isinstance(schema.get("properties"), dict):
                names |= {k for k in schema["properties"].keys() if isinstance(k, str)}
        return names

    def _spec_base_url(self, spec: Dict[str, Any], spec_url: Optional[str]) -> str:
        """Resolve the server base URL from OpenAPI 3.x ``servers`` or Swagger 2.0."""
        servers = spec.get("servers")
        if isinstance(servers, list):
            for server in servers:
                if isinstance(server, dict) and server.get("url"):
                    return self._absolute_base(str(server["url"]), spec_url)

        host = spec.get("host")
        base_path = str(spec.get("basePath") or "")
        if isinstance(host, str) and host:
            schemes = spec.get("schemes")
            if isinstance(schemes, list) and schemes:
                scheme = str(schemes[0])
            elif spec_url:
                scheme = urlparse(spec_url).scheme or "https"
            else:
                scheme = urlparse(self.base_url).scheme or "https"
            return f"{scheme}://{host}{base_path}".rstrip("/")
        return (self.origin + base_path).rstrip("/")

    def _absolute_base(self, url: str, spec_url: Optional[str]) -> str:
        """Turn a possibly-relative server URL into an absolute base."""
        if url.startswith(("http://", "https://")):
            return url.rstrip("/")
        if url.startswith("/"):
            return (self.origin + url).rstrip("/")
        ref = self.origin
        if spec_url:
            parts = urlparse(spec_url)
            if parts.scheme in ("http", "https") and same_site(parts.hostname or "", self.host):
                ref = f"{parts.scheme}://{parts.netloc}"
        return urljoin(ref + "/", url).rstrip("/")

    def _join_url(self, base: str, path: str) -> str:
        """Concatenate base + spec path (spec paths are absolute by definition)."""
        base = (base or self.origin).rstrip("/")
        if path.startswith("/"):
            return base + path
        return base + "/" + path

    # -- stage 2: JavaScript scraping -----------------------------------------

    async def _stage_js(self, report: DiscoveryReport) -> None:
        """Mine endpoints from inline HTML config, <script> assets and chunks."""
        logger.info("Stage 2 (JS scraping): scraping homepage and JavaScript assets")
        html = await self._fetch_text(self.base_url)
        if not html:
            logger.info("Could not fetch homepage - skipping JS scraping")
            return

        queue: "asyncio.Queue[str]" = asyncio.Queue()
        seen: Set[str] = set()

        def enqueue(raw_url: str, base: str) -> None:
            """Schedule a JS asset for download (respecting scope and budget)."""
            resolved = urljoin(base, raw_url.strip())
            key = canonical_url(resolved)
            if not key or key in seen or len(seen) >= self.cfg.max_js_files:
                return
            host = urlparse(key).hostname or ""
            if not self.cfg.include_external_js and not same_site(host, self.host):
                return
            seen.add(key)
            queue.put_nowait(key)

        # 1) Inline HTML (window.__CONFIG__, data attributes, <a href> hints).
        self._mine_text(html, self.base_url, report, enqueue, scan_chunks=False)

        # 2) <script src> + modulepreload assets, then lazily discovered chunks.
        for script_url in extract_script_urls(html, self.base_url):
            enqueue(script_url, self.base_url)

        if queue.empty():
            logger.info("No JavaScript assets referenced by the homepage")
            return

        workers = [
            asyncio.create_task(self._js_worker(queue, report, enqueue))
            for _ in range(max(1, min(4, self.cfg.concurrency)))
        ]
        try:
            await queue.join()  # waits until all (incl. newly enqueued) items are done
        finally:
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

        logger.info("JS scraping finished: %d asset(s) analysed", len(seen))

    async def _js_worker(
        self,
        queue: "asyncio.Queue[str]",
        report: DiscoveryReport,
        enqueue: Any,
    ) -> None:
        """Consume JS asset URLs, mine endpoints and discover more chunks."""
        while True:
            asset_url = await queue.get()
            try:
                text = await self._fetch_text(asset_url)
                if text:
                    self._mine_text(text, asset_url, report, enqueue, scan_chunks=True)
            except Exception as exc:  # noqa: BLE001 - one bad asset never stops the pool
                logger.debug("JS mining failed for %s: %s", asset_url, exc)
            finally:
                queue.task_done()

    def _mine_text(
        self,
        text: str,
        base_url: str,
        report: DiscoveryReport,
        enqueue: Any,
        *,
        scan_chunks: bool,
    ) -> None:
        """Apply the regex arsenal to a text blob (HTML or JS)."""
        for label, pattern in JS_PATTERNS:
            for match in pattern.finditer(text):
                self._ingest_candidate(match.group("path"), base_url, label, report)
        if scan_chunks:
            for match in JS_CHUNK_SRC.finditer(text):
                enqueue(match.group(1), base_url)

    def _ingest_candidate(
        self, raw: str, base_url: str, label: str, report: DiscoveryReport
    ) -> None:
        """Normalise, filter and record one regex-extracted candidate endpoint."""
        if not raw:
            return
        raw = raw.strip()
        if not raw or len(raw) > 300:
            return
        if any(ch in raw for ch in (" ", "\t", "\\", "<", ">", "\n")):
            return
        if raw.upper() in _HTTP_VERBS:
            return
        if not raw.startswith(("/", "http://", "https://")) and not RELATIVE_SEGMENT.match(raw):
            return

        resolved = urljoin(base_url, raw)
        parts = urlparse(resolved)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return
        # Endpoint scope: only the target's own site (heuristic eTLD+1).
        if not same_site(parts.hostname, self.host):
            return

        path = parts.path or ""
        if len(path) < 2 or len(path) > 300:
            return
        if STATIC_SUFFIX_BLACKLIST.search(path):
            return

        # Noise control by match provenance:
        #  - api-path        : already marker-qualified by the regex
        #  - request-call    : explicit network/config string -> require at
        #                      least one meaningful segment
        #  - absolute-url /
        #    path-like       : require an API marker or template placeholder
        if label == "request-call":
            if not plausible_route(path) and not SEGMENT_LIKE.search(path):
                return
        elif label in ("absolute-url", "path-like") and not plausible_route(path):
            return

        report.add_endpoint(resolved, source="js_scraping", methods={"*"})

    # -- stage 3: smart fuzzing -----------------------------------------------

    async def _stage_fuzz(self, report: DiscoveryReport) -> None:
        """Probe a route wordlist, filtering soft-404s via a baseline.

        Uses the quiet, built-in FUZZ_ROUTES by default. With
        ``cfg.deep_fuzz``, also sweeps EXTENDED_FUZZ_ROUTES (SecLists-derived
        api-endpoints.txt + api-seen-in-wild.txt, thousands of routes) - a
        deliberately heavier, opt-in pass.
        """
        wordlist: Tuple[str, ...] = FUZZ_ROUTES
        if self.cfg.deep_fuzz:
            if EXTENDED_FUZZ_ROUTES:
                wordlist = FUZZ_ROUTES + EXTENDED_FUZZ_ROUTES
            else:
                logger.warning(
                    "deep_fuzz requested but no extended wordlist file was found "
                    "(expected wily/wordlists/api_fuzz_extended.txt) - falling back "
                    "to the built-in %d routes only",
                    len(FUZZ_ROUTES),
                )
        logger.info(
            "Stage 3 (smart fuzzing): running (%d candidate routes%s)",
            len(wordlist),
            ", deep fuzz / SecLists" if self.cfg.deep_fuzz and len(wordlist) > len(FUZZ_ROUTES) else "",
        )

        # Baseline: a random, certainly-absent path reveals how this server
        # answers "unknown" requests (soft-404 pages, blanket WAF blocks...).
        baseline = await self._probe(f"{self.origin}/wily-{secrets.token_hex(4)}")
        soft_signature: Optional[Tuple[int, int, str]] = None
        if baseline is not None and baseline.length is not None:
            soft_signature = (baseline.status, baseline.length, (baseline.content_type or "").split(";")[0])

        targets: List[str] = []
        queued_keys: Set[str] = set()
        for route in wordlist:
            key = canonical_url(self.origin + route)
            if not key or key in report.endpoints or key in queued_keys:
                continue
            queued_keys.add(key)
            targets.append(key)

        async def check(key_url: str) -> None:
            try:
                probe = await self._probe(key_url)
                if probe is None or not _status_is_live(probe.status):
                    return
                # Soft-404 / blanket-response filter: same status, near-same
                # body size and same content type as the "nothing here" baseline.
                if soft_signature is not None:
                    sig_status, sig_length, sig_ctype = soft_signature
                    if probe.status == sig_status and probe.length is not None:
                        same_type = (
                            not probe.content_type
                            or not sig_ctype
                            or probe.content_type.split(";")[0] == sig_ctype
                        )
                        if same_type and abs(probe.length - sig_length) <= 24:
                            logger.debug("Soft-404 filtered: %s", key_url)
                            return
                report.add_endpoint(
                    key_url,
                    source="fuzzing",
                    status=probe.status,
                    content_type=probe.content_type,
                )
            except Exception as exc:  # noqa: BLE001 - keep the swarm alive
                logger.debug("Fuzz probe failed for %s: %s", key_url, exc)

        await asyncio.gather(*(check(key) for key in targets))
        logger.info("Fuzzing finished")

    # -- orchestration ----------------------------------------------------------

    async def run(self) -> DiscoveryReport:
        """Execute the fallback pipeline and return the aggregated report."""
        started = time.monotonic()
        report = DiscoveryReport(target=self.base_url)

        connector_kwargs: Dict[str, Any] = {
            "limit": max(2, self.cfg.concurrency * 2),
        }
        if not self.cfg.verify_ssl:
            connector_kwargs["ssl"] = False
            logger.warning("TLS certificate verification disabled (--insecure)")

        timeout = aiohttp.ClientTimeout(
            total=self.cfg.timeout, connect=min(self.cfg.timeout, 6.0)
        )

        async with aiohttp.ClientSession(
            headers=DEFAULT_HEADERS,
            timeout=timeout,
            connector=aiohttp.TCPConnector(**connector_kwargs),
        ) as session:
            self._session = session
            discovery_requested = self.cfg.spec is None or self.cfg.augment

            # Stage 0: user-provided spec short-circuits discovery by default.
            if self.cfg.spec:
                logger.info("Stage 0 (user spec): loading %s", self.cfg.spec)
                await self._stage_user_spec(report)
                if not discovery_requested:
                    return self._finalise(report, started)

            if discovery_requested:
                # Stage 1: documentation discovery.
                doc_spec_url = await self._stage_docs(report)

                # Stage 2: JS scraping (fallback unless running aggressively).
                if doc_spec_url is None or self.cfg.aggressive:
                    await self._stage_js(report)

                # Stage 3: fuzzing when the harvest is still thin.
                if self.cfg.enable_fuzzing and (
                    self.cfg.aggressive
                    or len(report.endpoints) < self.cfg.fuzz_threshold
                ):
                    await self._stage_fuzz(report)

        return self._finalise(report, started)

    def _finalise(self, report: DiscoveryReport, started: float) -> DiscoveryReport:
        """Attach errors and telemetry, then log the summary."""
        report.errors.extend(self._errors)
        report.stats.update(
            {
                "duration_seconds": round(time.monotonic() - started, 2),
                "requests_made": self._requests,
                "discovery_errors": len(self._errors),
            }
        )
        logger.info(
            "Discovery finished: %d endpoint(s), %d request(s), %d error(s) in %.2fs",
            len(report.endpoints),
            self._requests,
            len(self._errors),
            report.stats["duration_seconds"],
        )
        return report


# ---------------------------------------------------------------------------
# CLI (thin wrapper so the module drops into the larger Wily CLI later)
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wily-api-discovery",
        description=(
            "Wily API discovery pipeline: user spec -> docs -> JS scraping -> "
            "smart fuzzing. Only scan targets you are authorised to test."
        ),
    )
    parser.add_argument("target", help="Target domain or URL (https:// assumed)")
    parser.add_argument(
        "--spec",
        metavar="PATH_OR_URL",
        help="OpenAPI/Swagger spec to use directly (skips discovery unless --augment)",
    )
    parser.add_argument(
        "--augment",
        action="store_true",
        help="Continue discovery even when --spec is provided",
    )
    parser.add_argument(
        "--aggressive",
        action="store_true",
        help="Run every stage regardless of early hits",
    )
    parser.add_argument("--no-fuzz", action="store_true", help="Disable smart fuzzing")
    parser.add_argument(
        "--deep-fuzz",
        action="store_true",
        help=(
            f"Also sweep the SecLists-derived wordlist "
            f"({len(EXTENDED_FUZZ_ROUTES)} extra routes) - slower, noisier, opt-in"
        ),
    )
    parser.add_argument(
        "--fuzz-threshold",
        type=int,
        default=8,
        metavar="N",
        help="Fuzz when fewer than N endpoints were found (default: 8)",
    )
    parser.add_argument("--concurrency", type=int, default=15, help="Max in-flight requests")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout (s)")
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        metavar="RPS",
        help="Throttle to N requests/second (0 = unlimited)",
    )
    parser.add_argument(
        "--insecure", action="store_true", help="Disable TLS certificate verification"
    )
    parser.add_argument(
        "--include-external-js",
        action="store_true",
        help="Also fetch third-party/CDN JavaScript assets (off by default)",
    )
    parser.add_argument("--max-js", type=int, default=40, help="Max JS assets to crawl")
    parser.add_argument("-o", "--output", metavar="FILE", help="Write JSON report to FILE")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug-level logging")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
        stream=sys.stderr,
    )

    config = DiscoveryConfig(
        target=args.target,
        spec=args.spec,
        augment=args.augment,
        aggressive=args.aggressive,
        enable_fuzzing=not args.no_fuzz,
        fuzz_threshold=args.fuzz_threshold,
        deep_fuzz=args.deep_fuzz,
        concurrency=max(1, args.concurrency),
        timeout=max(1.0, args.timeout),
        rate_limit=max(0.0, args.rate_limit),
        verify_ssl=not args.insecure,
        include_external_js=args.include_external_js,
        max_js_files=max(1, args.max_js),
    )

    try:
        report = asyncio.run(ApiDiscoveryPipeline(config).run())
    except KeyboardInterrupt:
        return 130

    payload = json.dumps(report.to_json(), indent=2)
    if args.output:
        Path(args.output).write_text(payload + "\n", encoding="utf-8")
        logger.info("Report written to %s", args.output)
    else:
        print(payload)
    return 0 if report.endpoints else 1


if __name__ == "__main__":
    raise SystemExit(main())
