#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wily :: wily/bola_tester.py
============================
Stage 5: cross-identity BOLA / Multi-Tenant / Cross-Tenant Access testing.

Where Stage 0-4 (api_discovery.py, traffic_monitor.py) only ever answer
"does this endpoint exist and respond", this stage answers the actual
security question: *does the server enforce who is allowed to see it*.

Design, in one sentence
------------------------
For every candidate resource observed under a tagged test-account session,
replay the same concrete request as a different identity and compare responses.
A tagged session is useful ownership evidence, but does not alone prove the
resource is exclusive to that tenant; the report must be reviewed against the
application's expected sharing policy. The same core idea as Burp's
Autorize/AuthMatrix and the standalone ``bola`` CLI (github.com/Mutasem-mk4/
bola), whose confidence-scoring approach this module's ``compare()``
deliberately follows: status match + response-size delta + JSON-structure
(Jaccard) similarity + a "200 with an error body" sniff, combined into a
HIGH/MEDIUM/LOW/NONE verdict instead of trusting any single signal alone.

Two candidate classes, two confidence ceilings
------------------------------------------------
* **Identity-tagged candidates** - a resource captured by ``traffic_monitor.py``
  while ``TrafficConfig.identity_name`` was set. That identifies the account
  whose session observed the resource, not conclusive proof of exclusive ownership.
  It is compared with every other supplied test identity and can reach HIGH
  heuristic confidence when identity-bearing response values overlap.
* **Unowned candidates** - a ``bola_candidate`` endpoint from a spec or JS
  scrape, or traffic captured with no identity stamped. We don't know who it
  belongs to, so the best this module can honestly do is request it with
  every identity supplied and flag it (capped at MEDIUM) if more than one
  gets a matching, non-error response - "possible shared access, ownership
  unconfirmed", not a confirmed finding. Run Stage 4 once per identity (see
  ``TrafficConfig.identity_name``) to tag the observed session; ownership still requires confirmation against the application's access policy.

Templated endpoints straight from a spec (``/users/{id}``, never seen live)
cannot be replayed at all - there is no real ID to substitute - and are
skipped with a note rather than guessed at.

Safety
------
* GET/HEAD replays only by default. A candidate whose only known method is
  state-changing (POST/PUT/PATCH/DELETE) is reported as "needs confirmation"
  rather than replayed, unless ``allow_destructive=True`` - the same opt-in
  pattern already used for S3 write-checks and token-entropy probing
  elsewhere in Wily.
* Replays never follow redirects. Each URL is checked against the configured
  target host, and a guarded aiohttp resolver rejects non-public IP addresses
  at connection time (including DNS answers that change between requests).
* Rate-limited and concurrency-bounded, same philosophy as the discovery
  stages: a scanner should never itself become a denial-of-service source.

Library integration
--------------------
    from wily.api_discovery import ApiDiscoveryPipeline, DiscoveryConfig
    from wily.bola_tester import BolaTester, Identity

    report = await ApiDiscoveryPipeline(DiscoveryConfig(target=url)).run()
    tester = BolaTester([
        Identity("accountA", {"Authorization": "Bearer <A's token>"}),
        Identity("accountB", {"Authorization": "Bearer <B's token>"}),
    ])
    findings = await tester.run(report)
    for f in findings:
        print(f.confidence, f.method, f.endpoint, f.owner_identity, "->", f.tester_identity)

Only test identities and targets you are authorised to use.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import shlex
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

try:
    import aiohttp
except ImportError:  # pragma: no cover
    import sys

    sys.stderr.write("Wily requires aiohttp. Install it with:  pip install aiohttp\n")
    raise SystemExit(2)

from .api_discovery import DiscoveryReport, EndpointRecord, id_like_names

logger = logging.getLogger("wily.bola_tester")

__all__ = ["BolaTester", "Identity", "BolaFinding", "ReplaySample", "jaccard_key_similarity"]

DESTRUCTIVE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Short, generic phrases that show up on "200 OK but actually denied" pages -
# exactly the false-positive pattern bola's README calls out by name.
_ERROR_BODY_MARKERS = (
    "access denied", "forbidden", "unauthorized", "not authorized",
    "permission denied", "not allowed", "login required", "please sign in",
    "ليس لديك", "غير مصرح",
)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass
class Identity:
    """One test account. ``headers`` is sent on every replay for this identity."""

    name: str
    headers: Dict[str, str]


@dataclass
class ReplaySample:
    """One replay attempt's outcome."""

    status: Optional[int]
    length: Optional[int]
    content_type: Optional[str]
    body_snippet: Optional[str]  # capped, used only for comparison - never stored raw/long
    elapsed_ms: Optional[float]
    error: Optional[str] = None  # transport failure reason, if any


@dataclass
class BolaFinding:
    """One cross-identity result worth a human's attention."""

    endpoint: str
    method: str
    owner_identity: Optional[str]  # None for an "unowned" candidate
    tester_identity: str
    confidence: str  # HIGH / MEDIUM / LOW
    owner_sample: Optional[ReplaySample]
    other_sample: ReplaySample
    json_similarity: Optional[float]
    notes: List[str]
    curl_command: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "owner_identity": self.owner_identity,
            "ownership_basis": (
                "identity-tagged traffic; verify the resource is tenant-exclusive"
                if self.owner_identity else "unconfirmed; no identity-tagged owner baseline"
            ),
            "tester_identity": self.tester_identity,
            "confidence": self.confidence,
            "owner_status": self.owner_sample.status if self.owner_sample else None,
            "other_status": self.other_sample.status,
            "json_similarity": self.json_similarity,
            "notes": self.notes,
            "curl_command": self.curl_command,
        }


# ---------------------------------------------------------------------------
# Pure helpers (unit-testable, no I/O)
# ---------------------------------------------------------------------------


def _flatten_keys(obj: Any, prefix: str = "") -> Set[str]:
    """All key *paths* in a JSON-decoded structure, e.g. {'user.id', 'user.name', 'items[].sku'}.

    Comparing the key-path SET between two responses (Jaccard similarity)
    catches "same shape, different data" (a real BOLA: identity B received
    someone else's record in the same structure identity A would've gotten)
    while correctly telling it apart from "completely different shape"
    (identity B actually got a generic error/empty object back).
    """
    keys: Set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            keys.add(path)
            keys |= _flatten_keys(v, path)
    elif isinstance(obj, list):
        for item in obj[:5]:  # cap - we need the shape, not every array element
            keys |= _flatten_keys(item, f"{prefix}[]")
    return keys


def jaccard_key_similarity(body_a: Optional[str], body_b: Optional[str]) -> Optional[float]:
    """Jaccard similarity of two responses' JSON key-path sets, or ``None``
    when either body isn't parseable JSON (comparison falls back to size/
    status alone in that case - see ``compare()``)."""
    if not body_a or not body_b:
        return None
    try:
        keys_a = _flatten_keys(json.loads(body_a))
        keys_b = _flatten_keys(json.loads(body_b))
    except (ValueError, TypeError, RecursionError):
        return None
    if not keys_a and not keys_b:
        return None
    union = keys_a | keys_b
    if not union:
        return None
    return len(keys_a & keys_b) / len(union)


def _looks_like_error_body(sample: ReplaySample) -> bool:
    """A 200 whose body reads like a denial page - the false positive both
    bola's README and our own A02 'verbose errors' check both warn about."""
    if sample.status != 200 or not sample.body_snippet:
        return False
    low = sample.body_snippet.lower()
    return any(marker in low for marker in _ERROR_BODY_MARKERS) and len(sample.body_snippet) < 2000


def compare(
    owner: Optional[ReplaySample], other: ReplaySample, *, grounded: bool
) -> Tuple[str, Optional[float], List[str]]:
    """Multi-factor comparison -> (confidence, json_similarity, notes).

    Mirrors ``bola``'s own scoring recipe: status-code match, response-size
    delta, JSON structural (Jaccard) similarity, and an error-body sniff,
    combined rather than trusting any one signal - a size-only or
    status-only check is exactly what produces the false positives/negatives
    a reviewer would ask about first.

    ``grounded`` must be ``True`` only when ``owner`` is a sample taken with
    a *verified* owner's identity (the traffic-monitor-with-identity-name
    case) - **not** merely "a sample happens to be available". Passing
    ``grounded=False`` is what keeps the "unowned candidate" path (no known
    owner, just comparing whichever identities responded) capped at MEDIUM
    regardless of how well the two responses match; conflating "no baseline
    at all" with "an unverified baseline" here is exactly the bug that let
    an unowned match reach HIGH in testing.
    """
    notes: List[str] = []
    if other.error:
        return "NONE", None, [f"replay failed: {other.error}"]
    if other.status is None:
        return "NONE", None, ["no response"]

    # A clean denial or a non-success response is not evidence of data access.
    if other.status in (401, 403, 404):
        return "NONE", None, [f"got {other.status} - access control appears enforced"]
    if not 200 <= other.status < 300:
        return "NONE", None, [f"got HTTP {other.status} - no successful data response"]
    if owner is not None and (owner.status is None or not 200 <= owner.status < 300):
        return "NONE", None, ["owner baseline was not a successful 2xx response"]

    status_match = owner is not None and owner.status == other.status
    if status_match:
        notes.append(f"status matched baseline's ({other.status})")

    if _looks_like_error_body(other):
        notes.append("200 but body reads like a denial page - likely false positive")
        return "LOW", None, notes

    size_delta_pct: Optional[float] = None
    if owner and owner.length and other.length is not None:
        size_delta_pct = abs(owner.length - other.length) / max(owner.length, 1)
        notes.append(f"response size delta {size_delta_pct:.0%}")

    owner_body = owner.body_snippet if owner else None
    similarity = jaccard_key_similarity(owner_body, other.body_snippet)
    if similarity is not None:
        notes.append(f"JSON key-structure similarity {similarity:.0%}")
    value_overlap = _identity_value_overlap(owner_body, other.body_snippet)
    if value_overlap is not None:
        notes.append(f"identity-specific JSON value overlap {value_overlap:.0%}")

    if not grounded:
        # Ownership unverified: the ceiling is MEDIUM no matter how well the
        # two responses match - "two identities both got 200 with similar
        # JSON" is consistent with a real cross-tenant leak, but equally
        # consistent with an intentionally shared/public resource. Only a
        # verified owner sample can push this to HIGH.
        if other.status == 200 and status_match and (similarity is None or similarity >= 0.5):
            return "MEDIUM", similarity, notes
        return "LOW", similarity, notes

    # Matching response shape alone is not proof of cross-tenant data access:
    # distinct tenant records often have identical JSON schemas. HIGH requires
    # both a similar structure and a substantial overlap of identity-bearing
    # values from the known owner's response.
    if (
        status_match
        and similarity is not None and similarity >= 0.85
        and value_overlap is not None and value_overlap >= 0.6
    ):
        return "HIGH", similarity, notes
    if status_match and (similarity is None or similarity >= 0.5) and (
        size_delta_pct is None or size_delta_pct <= 0.3
    ):
        return "MEDIUM", similarity, notes
    if status_match:
        return "LOW", similarity, notes
    return "NONE", similarity, notes


class _PublicOnlyResolver(aiohttp.abc.AbstractResolver):
    """Resolve DNS at connection time and reject any non-public destination.

    Returning the vetted addresses to aiohttp's connector (instead of merely
    doing a separate DNS preflight) avoids a check-then-resolve DNS-rebinding
    gap in Stage 5.
    """

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> List[Dict[str, Any]]:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(
            host, port, family=family, type=socket.SOCK_STREAM
        )
        if not infos:
            raise OSError(f"No DNS addresses returned for {host}")

        results: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, int]] = set()
        for fam, _socktype, proto, _canonname, sockaddr in infos:
            address = str(sockaddr[0]).split("%", 1)[0]
            try:
                parsed_ip = ipaddress.ip_address(address)
            except ValueError as exc:
                raise OSError(f"Invalid DNS address for {host}") from exc
            if not parsed_ip.is_global:
                raise OSError(f"Blocked non-public destination address for {host}: {address}")
            key = (address, fam)
            if key in seen:
                continue
            seen.add(key)
            results.append({
                "hostname": host,
                "host": address,
                "port": port,
                "family": fam,
                "proto": proto,
                "flags": 0,
            })
        return results

    async def close(self) -> None:
        return None


def _samples_for_method(record: EndpointRecord, method: str) -> List[Dict[str, Any]]:
    return [
        sample for sample in record.replay_samples
        if str(sample.get("method", "")).upper() == method.upper()
    ]


def _sample_for_method(record: EndpointRecord, method: str) -> Optional[Dict[str, Any]]:
    samples = _samples_for_method(record, method)
    return samples[-1] if samples else None


def _sample_has_id_reference(sample: Dict[str, Any], details: Dict[str, Any]) -> bool:
    try:
        query_names = set(parse_qs(urlsplit(str(sample.get("url", ""))).query, keep_blank_values=True))
    except ValueError:
        return False
    body_names: Set[str] = set()
    sample_body = sample.get("body")
    if isinstance(sample_body, str):
        try:
            decoded_body = json.loads(sample_body)
            if isinstance(decoded_body, dict):
                body_names = set(decoded_body)
        except (ValueError, TypeError):
            pass
    known_query = set(details.get("id_like_query_params") or [])
    known_body = set(details.get("id_like_body_params") or [])
    return bool(
        known_query & set(id_like_names(query_names))
        or known_body & set(id_like_names(body_names))
    )


def _has_concrete_path_id(url: str) -> bool:
    path = urlparse(url).path
    for segment in (part for part in path.split("/") if part):
        if segment.isdigit() or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            segment, re.IGNORECASE,
        ) or re.fullmatch(r"[0-9a-f]{24}", segment, re.IGNORECASE):
            return True
    return False


def _identity_scalar_pairs(body: Optional[str]) -> Optional[Set[str]]:
    """Extract exact, likely identity-bearing JSON values, not just key names."""
    if not body:
        return None
    try:
        root = json.loads(body)
    except (ValueError, TypeError, RecursionError):
        return None

    identity_key = re.compile(
        r"(?:^|[_-])(id|uuid|tenant|user|account|customer|owner|email|username|"
        r"order|project|resource|record|organization|org)(?:$|[_-])|"
        r"^(?:id|uuid|email|username|name|title)$", re.IGNORECASE
    )
    common_values = {
        "active", "inactive", "pending", "success", "failed", "ok", "true",
        "false", "free", "basic", "standard", "premium", "user", "admin",
    }
    pairs: Set[str] = set()

    def walk(value: Any, path: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                next_path = f"{path}.{key}" if path else str(key)
                if isinstance(child, (dict, list)):
                    walk(child, next_path)
                elif child is not None and not isinstance(child, bool):
                    text = str(child).strip()
                    lowered = text.lower()
                    identity_field = bool(identity_key.search(str(key)))
                    long_value = len(text) >= 12 and lowered not in common_values
                    if (identity_field or long_value) and lowered not in common_values:
                        # Keep the field path with the value, so coincidental
                        # duplicates in unrelated fields do not score as overlap.
                        pairs.add(f"{next_path.lower()}={lowered}")
        elif isinstance(value, list):
            for child in value[:10]:
                walk(child, f"{path}[]")

    walk(root)
    return pairs


def _identity_value_overlap(body_a: Optional[str], body_b: Optional[str]) -> Optional[float]:
    values_a = _identity_scalar_pairs(body_a)
    values_b = _identity_scalar_pairs(body_b)
    if not values_a or not values_b:
        return None
    union = values_a | values_b
    return len(values_a & values_b) / len(union) if union else None


_AUTH_QUERY_NAME = re.compile(
    r"^(?:access_token|refresh_token|auth_token|token|(?:x[_-])?api[_-]?key|apikey|password|"
    r"passwd|session|sessionid|signature|sig|client[_-]?secret|private[_-]?key|authorization|code|jwt)$",
    re.IGNORECASE,
)
_AUTH_BODY_NAME = re.compile(
    r"(?:^|[_-])(?:access[_-]?token|refresh[_-]?token|auth[_-]?token|token|secret|"
    r"password|passwd|api[_-]?key|client[_-]?secret|authorization|session|cookie|"
    r"signature|credential|private[_-]?key|jwt)(?:$|[_-])",
    re.IGNORECASE,
)


def _sample_contains_auth_material(sample: Dict[str, Any]) -> bool:
    """Do not carry a captured account's query/body credentials into another identity."""
    try:
        query_names = parse_qs(urlsplit(str(sample.get("url", ""))).query, keep_blank_values=True)
    except ValueError:
        return True
    if any(_AUTH_QUERY_NAME.fullmatch(name) for name in query_names):
        return True
    body = sample.get("body")
    if not isinstance(body, str) or not body:
        return False
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        # Form-like bodies are common for login/auth endpoints; conservatively
        # avoid replay if field names reveal credentials.
        try:
            body_names = parse_qs(body, keep_blank_values=True)
        except ValueError:
            return True
        return any(_AUTH_BODY_NAME.search(name) for name in body_names)

    def has_secret_key(value: Any) -> bool:
        if isinstance(value, dict):
            return any(_AUTH_BODY_NAME.search(str(k)) or has_secret_key(v) for k, v in value.items())
        if isinstance(value, list):
            return any(has_secret_key(v) for v in value[:100])
        return False

    return has_secret_key(parsed)


def _redact_body(body: Optional[str]) -> Optional[str]:
    """Redact secret-bearing JSON fields before including a sample in a report."""
    if body is None:
        return None
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return "<request body omitted; non-JSON body may contain secrets>"
    secret_name = re.compile(
        r"(?:token|secret|password|passwd|api[_-]?key|authorization|session|cookie|"
        r"signature|client[_-]?secret|private[_-]?key|credential|csrf)", re.IGNORECASE
    )

    def scrub(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: "<REDACTED>" if secret_name.search(str(key)) else scrub(child)
                for key, child in value.items()
            }
        if isinstance(value, list):
            return [scrub(child) for child in value[:100]]
        return value

    try:
        return json.dumps(scrub(parsed), ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return "<request body omitted>"


def _redact_url(url: str) -> str:
    """Hide secret-like query values in generated reproduction commands."""
    try:
        parts = urlsplit(url)
        secret_name = re.compile(
            r"(?:token|secret|password|passwd|api[_-]?key|authorization|session|cookie|"
            r"signature|sig|access[_-]?key|client[_-]?secret|private[_-]?key|^code$)", re.IGNORECASE
        )
        query = [
            (key, "<REDACTED>" if secret_name.search(key) else value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
        ]
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
    except (TypeError, ValueError):
        return "<URL REDACTED>"


def _url_in_scope(url: str, target: str) -> bool:
    """Require HTTP(S), the target host (or its subdomains), and same scheme."""
    try:
        target_parts = urlsplit(target if "://" in target else "https://" + target)
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        target_host = (target_parts.hostname or "").lower().rstrip(".")
        # canonical_url() strips leading www.; normalise the target the same way.
        host = host.removeprefix("www.")
        target_host = target_host.removeprefix("www.")
        # IP-literal targets may only match exactly, never via hostname suffix.
        # A target's subdomains are in scope; sibling hosts are not.
        try:
            target_ip = ipaddress.ip_address(target_host)
        except ValueError:
            target_ip = None
        if target_ip is not None:
            host_ok = host == target_host
        else:
            host_ok = bool(target_host) and (host == target_host or host.endswith("." + target_host))
        url_port = parts.port or (443 if parts.scheme == "https" else 80)
        target_port = target_parts.port or (443 if target_parts.scheme == "https" else 80)
        return (
            parts.scheme in {"http", "https"}
            and parts.scheme == target_parts.scheme
            and url_port == target_port
            and host_ok
            and parts.username is None
            and parts.password is None
        )
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Rate limiting (same small token-bucket as api_discovery.py, kept local to
# avoid importing pipeline internals that aren't part of its public surface)
# ---------------------------------------------------------------------------


class _RateLimiter:
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
# The tester
# ---------------------------------------------------------------------------


class BolaTester:
    """Replays bola_candidate endpoints across identities and scores the result."""

    def __init__(
        self,
        identities: List[Identity],
        *,
        concurrency: int = 5,
        rate_limit: float = 2.0,
        timeout: float = 10.0,
        max_body_bytes: int = 50_000,
        allow_destructive: bool = False,
        min_confidence: str = "LOW",
    ) -> None:
        if len(identities) < 2:
            raise ValueError("BolaTester needs at least two identities to compare")
        self.identities = identities
        self._by_name = {i.name: i for i in identities}
        self.cfg_concurrency = max(1, concurrency)
        self.allow_destructive = allow_destructive
        self.max_body_bytes = max_body_bytes
        self._rank = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
        self.min_confidence = min_confidence if min_confidence in self._rank else "LOW"

        self._sem = asyncio.Semaphore(self.cfg_concurrency)
        self._limiter = _RateLimiter(rate_limit)
        self._session: Optional[aiohttp.ClientSession] = None
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self.errors: List[str] = []
        self._scope_target: Optional[str] = None

    # -- candidate selection --------------------------------------------------

    @staticmethod
    def _is_concrete(url: str) -> bool:
        """False for a still-templated spec path like /users/{id} - nothing to replay."""
        return "{" not in url and "}" not in url

    def _replayable_method(self, record: EndpointRecord) -> Optional[str]:
        methods = record.methods - {"*"} or {"GET"}
        if "GET" in methods:
            return "GET"
        if "HEAD" in methods:
            return "HEAD"
        if methods & DESTRUCTIVE_METHODS and not self.allow_destructive:
            return None  # exists, but needs --allow-destructive to replay
        return sorted(methods)[0] if methods else None

    def candidates(self, report: DiscoveryReport) -> List[Tuple[EndpointRecord, str]]:
        """Return concrete, in-scope candidates with enough data to replay.

        Spec-only query/body candidates are deliberately skipped: parameter
        *names* are not concrete values, and replaying a bare path would test
        the wrong request and create misleading results.
        """
        out: List[Tuple[EndpointRecord, str]] = []
        path_has_id = _has_concrete_path_id
        for url, record in report.endpoints.items():
            details = record.details or {}
            if not details.get("bola_candidate"):
                continue
            if not _url_in_scope(url, report.target):
                continue
            if not self._is_concrete(url):
                continue

            has_path_id = path_has_id(url)
            sampled_methods = {
                str(sample.get("method", "")).upper()
                for sample in record.replay_samples
                if sample.get("method")
            }
            methods = sampled_methods or (record.methods - {"*"} or {"GET"})
            for method in sorted(methods):
                method = method.upper()
                if method in {"OPTIONS", "TRACE", "CONNECT"}:
                    continue
                if method in DESTRUCTIVE_METHODS and not self.allow_destructive:
                    continue
                method_samples = _samples_for_method(record, method)
                eligible_samples = [
                    sample for sample in method_samples
                    if not _sample_contains_auth_material(sample)
                ]
                if method_samples and not eligible_samples:
                    # Avoid falling back to a stripped URL when every captured
                    # request for this method embeds authentication material.
                    continue
                if method in DESTRUCTIVE_METHODS and not eligible_samples:
                    # Never synthesize a write request from an endpoint name.
                    continue
                if not has_path_id:
                    if not any(_sample_has_id_reference(sample, details) for sample in eligible_samples):
                        # No concrete path ID or observed query/body identifier.
                        continue
                out.append((record, method))
        return out

    # -- low-level replay -------------------------------------------------------

    async def _replay(
        self, url: str, method: str, identity: Identity,
        sample: Optional[Dict[str, Any]] = None,
    ) -> ReplaySample:
        target = self._scope_target or url
        replay_url = str((sample or {}).get("url") or url)
        if not _url_in_scope(replay_url, target):
            msg = "blocked by BOLA target-scope guard"
            self.errors.append(f"{method} {_redact_url(replay_url)} as {identity.name}: {msg}")
            return ReplaySample(None, None, None, None, None, error=msg)

        body = (sample or {}).get("body")
        content_type = (sample or {}).get("content_type")
        headers = dict(identity.headers)
        if content_type and not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = str(content_type)

        await self._limiter.acquire()
        async with self._sem:
            started = time.monotonic()
            try:
                assert self._session is not None
                async with self._session.request(
                    method, replay_url, headers=headers,
                    data=body if body is not None and method not in {"GET", "HEAD"} else None,
                    allow_redirects=False,
                ) as resp:
                    body_bytes = await resp.content.read(self.max_body_bytes)
                    text = body_bytes.decode("utf-8", errors="replace") if body_bytes else None
                    return ReplaySample(
                        status=resp.status,
                        length=len(body_bytes) if body_bytes else _to_int(resp.headers.get("Content-Length")),
                        content_type=resp.headers.get("Content-Type"),
                        body_snippet=text,
                        elapsed_ms=(time.monotonic() - started) * 1000,
                    )
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
                msg = f"{type(exc).__name__}: {exc}"
                self.errors.append(f"{method} {_redact_url(replay_url)} as {identity.name}: {msg}")
                return ReplaySample(None, None, None, None, None, error=msg)

    @staticmethod
    def _curl(
        url: str, method: str, identity: Identity,
        sample: Optional[Dict[str, Any]] = None,
    ) -> str:
        safe_url = _redact_url(url)
        parts = [f"curl -X {shlex.quote(method)} {shlex.quote(safe_url)}"]
        sensitive_header = re.compile(
            r"(?:authorization|cookie|set-cookie|api[_-]?key|token|secret|password|"
            r"session|csrf|signature|credential|auth)", re.IGNORECASE
        )
        for key, value in identity.headers.items():
            shown = "<REDACTED>" if sensitive_header.search(key) else value
            parts.append("  -H " + shlex.quote(f"{key}: {shown}"))
        safe_body = _redact_body((sample or {}).get("body"))
        if safe_body is not None and method.upper() not in {"GET", "HEAD"}:
            parts.append("  --data-binary " + shlex.quote(safe_body))
        return f" {chr(92)}\n".join(parts)

    # -- orchestration ----------------------------------------------------------

    async def run(self, report: DiscoveryReport) -> List[BolaFinding]:
        """Test every candidate in ``report`` across all supplied identities."""
        findings: List[BolaFinding] = []
        self._scope_target = report.target
        pairs = self.candidates(report)
        logger.info(
            "BOLA testing: %d candidate(s) across %d identit(y/ies)",
            len(pairs), len(self.identities),
        )
        if not pairs:
            return findings

        connector = aiohttp.TCPConnector(
            limit=max(2, self.cfg_concurrency * 2),
            resolver=_PublicOnlyResolver(),
        )
        async with aiohttp.ClientSession(timeout=self._timeout, connector=connector) as session:
            self._session = session
            tasks = [self._test_one(record, method) for record, method in pairs]
            results = await asyncio.gather(*tasks)
            for group in results:
                findings.extend(group)

        findings = [f for f in findings if self._rank[f.confidence] >= self._rank[self.min_confidence]]
        findings.sort(key=lambda f: self._rank[f.confidence], reverse=True)
        logger.info("BOLA testing finished: %d finding(s) at/above %s", len(findings), self.min_confidence)
        return findings

    async def _test_one(self, record: EndpointRecord, method: str) -> List[BolaFinding]:
        """Test each bounded, concrete captured sample for this endpoint/method."""
        samples = [
            sample for sample in _samples_for_method(record, method)
            if not _sample_contains_auth_material(sample)
        ]
        if not samples:
            # This fallback is only for concrete path-ID candidates discovered
            # without traffic samples (e.g. a preconfigured report).
            samples = [None]
        findings: List[BolaFinding] = []
        for sample in samples:
            findings.extend(await self._test_one_sample(record, method, sample))
        return findings

    async def _test_one_sample(
        self, record: EndpointRecord, method: str,
        replay_sample: Optional[Dict[str, Any]],
    ) -> List[BolaFinding]:
        details = record.details or {}
        owner_name = details.get("owner_identity")
        out: List[BolaFinding] = []

        if owner_name and owner_name in self._by_name:
            owner = self._by_name[owner_name]
            replay_url = str((replay_sample or {}).get("url") or record.url)
            owner_sample = await self._replay(replay_url, method, owner, replay_sample)
            for other in self.identities:
                if other.name == owner_name:
                    continue
                other_sample = await self._replay(replay_url, method, other, replay_sample)
                confidence, similarity, notes = compare(owner_sample, other_sample, grounded=True)
                if confidence == "NONE":
                    continue
                out.append(BolaFinding(
                    endpoint=record.url, method=method,
                    owner_identity=owner_name, tester_identity=other.name,
                    confidence=confidence, owner_sample=owner_sample, other_sample=other_sample,
                    json_similarity=similarity, notes=notes,
                    curl_command=self._curl(replay_url, method, other, replay_sample),
                ))
            return out

        # Unowned candidate: no identity to use as the baseline. Try every
        # identity and flag it (capped at MEDIUM in compare()) if more than
        # one gets a non-error response - see the module docstring.
        replay_url = str((replay_sample or {}).get("url") or record.url)
        samples = [
            (ident, await self._replay(replay_url, method, ident, replay_sample))
            for ident in self.identities
        ]
        successful = [(i, s) for i, s in samples if s.status == 200 and not _looks_like_error_body(s)]
        if len(successful) < 2:
            return out
        baseline_ident, baseline_sample = successful[0]
        for ident, sample in successful[1:]:
            confidence, similarity, notes = compare(baseline_sample, sample, grounded=False)
            if confidence == "NONE":
                continue
            notes = notes + ["ownership unconfirmed - ran Stage 4 without --identity-name, or a spec/JS hit"]
            out.append(BolaFinding(
                endpoint=record.url, method=method,
                owner_identity=None, tester_identity=ident.name,
                confidence=confidence, owner_sample=baseline_sample, other_sample=sample,
                json_similarity=similarity, notes=notes,
                curl_command=self._curl(replay_url, method, ident, replay_sample),
            ))
        return out


def _to_int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
