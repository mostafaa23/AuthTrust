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
For every candidate resource we know one identity legitimately owns, replay
the exact same request as a different identity and compare the two
responses with more than a status code - the same core idea as Burp's
Autorize/AuthMatrix and the standalone ``bola`` CLI (github.com/Mutasem-mk4/
bola), whose confidence-scoring approach this module's ``compare()``
deliberately follows: status match + response-size delta + JSON-structure
(Jaccard) similarity + a "200 with an error body" sniff, combined into a
HIGH/MEDIUM/LOW/NONE verdict instead of trusting any single signal alone.

Three candidate classes, three confidence ceilings
----------------------------------------------------
* **Owned candidates** - a resource captured by ``traffic_monitor.py`` while
  ``TrafficConfig.identity_name`` was set, so we *know* whose it is (directly
  observed, not inferred). Tested against every *other* identity. This is
  real Cross-Tenant/BOLA testing and can reach HIGH confidence.
* **Seeded candidates** - a templated endpoint straight from a spec or JS
  scrape (``/users/{id}``, never seen live) that we can now render: if an
  identity's bearer token is a JWT, ``Identity`` harvests its claims
  (``sub``, ``user_id``, ``email``, ...) as seed values at construction time,
  and any ``{param}`` whose *name* looks like an object/tenant reference
  (shared ``PARAM_NAME_ID_MARKER`` from api_discovery.py) gets substituted
  with that identity's own claim - never guessed, never enumerated. The
  identity is then the presumed owner of that concrete URL. Presumed, not
  observed, is the operative word: ownership here rests on the assumption
  that a token's own claims describe the token holder's own resource, which
  is usually true but not guaranteed - so this class is capped at MEDIUM,
  the same ceiling as unowned candidates, never HIGH.
* **Unowned candidates** - a ``bola_candidate`` endpoint with no owner at all
  (traffic captured with no identity stamped, and no JWT seed could render
  it). The best this module can honestly do is request it with every
  identity supplied and flag it (capped at MEDIUM) if more than one gets a
  matching, non-error response - "possible shared access, ownership
  unconfirmed", not a confirmed finding. Run Stage 4 once per identity (see
  ``TrafficConfig.identity_name``) to turn these into directly-owned
  candidates instead.

A templated endpoint with a placeholder that *isn't* id-shaped (``/api/
{version}/items``) is still never rendered - only id/tenant-shaped names are
ever substituted, and only with a value an identity's own token actually
claims.

Owner-baseline volatility and stability
-----------------------------------------
Before scoring an **owned** candidate (observed or seeded), the owner's own
request is sampled three times rather than once. Two things come out of
that:

* **Volatility diffing** - JSON key-paths whose *value* changes across the
  three identical, same-identity calls (timestamps, nonces, request IDs,
  rotating CSRF tokens, ...) are excluded from the Jaccard structural
  comparison. Without this, a perfectly correctly-scoped endpoint can look
  "different" between owner and other purely because of a timestamp field,
  producing a false LOW/NONE; or, more dangerously, a genuinely leaked
  record can look "more similar than it should" skew the other direction if
  volatile fields happen to coincide. Comparing on the *stable* fields only
  is what both directions of error need.
* **Stability check** - if the owner's own three baseline calls don't even
  agree with *each other* (status flaps, or the body is too unstable to
  trust even after excluding known-volatile fields), the endpoint itself is
  too noisy to draw a conclusion from. Rather than silently skip it (and
  lose visibility that something's odd), the comparison still runs but its
  confidence is forced down to at most LOW, with a note explaining why - an
  unstable baseline is not evidence of anything, in either direction.

Safety
------
* GET/HEAD replays only by default. A candidate whose only known method is
  state-changing (POST/PUT/PATCH/DELETE) is reported as "needs confirmation"
  rather than replayed, unless ``allow_destructive=True`` - the same opt-in
  pattern already used for S3 write-checks and token-entropy probing
  elsewhere in Wily.
* Replays never follow redirects and require an explicit ``ScopeManager``.
  Every URL is checked immediately before sending; missing or out-of-scope
  URLs fail closed.
* Rate-limited and concurrency-bounded, same philosophy as the discovery
  stages: a scanner should never itself become a denial-of-service source.

Library integration
--------------------
    from wily.api_discovery import ApiDiscoveryPipeline, DiscoveryConfig
    from wily.bola_tester import BolaTester, Identity
    from wily.target_scope_manager.scope_manager import ScopeManager

    scope = ScopeManager("example.com")
    report = await ApiDiscoveryPipeline(
        DiscoveryConfig(target=url, scope=scope)
    ).run()
    tester = BolaTester(
        [
        Identity("accountA", {"Authorization": "Bearer <A's token>"}),
        Identity("accountB", {"Authorization": "Bearer <B's token>"}),
        ],
        scope_manager=scope,
    )
    findings = await tester.run(report)
    for f in findings:
        print(f.confidence, f.method, f.endpoint, f.owner_identity, "->", f.tester_identity)

Only test identities and targets you are authorised to use.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import aiohttp
except ImportError:  # pragma: no cover
    import sys

    sys.stderr.write("Wily requires aiohttp. Install it with:  pip install aiohttp\n")
    raise SystemExit(2)

from wily.recon.api_discovery import DiscoveryReport, EndpointRecord, PARAM_NAME_ID_MARKER
from wily.core.http_policy import REDIRECT_STATUSES, resolve_redirect
from wily.core.rate_limiter import AdaptiveRateLimiter
from wily.core.scope_manager import ScopeError, ScopeManager

logger = logging.getLogger("wily.bola_tester")

__all__ = [
    "BolaTester",
    "Identity",
    "BolaFinding",
    "ReplaySample",
    "jaccard_key_similarity",
    "decode_jwt_claims",
    "render_templated_url",
    "detect_volatile_keys",
]

DESTRUCTIVE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Short, generic phrases that show up on "200 OK but actually denied" pages -
# exactly the false-positive pattern bola's README calls out by name.
_ERROR_BODY_MARKERS = (
    "access denied", "forbidden", "unauthorized", "not authorized",
    "permission denied", "not allowed", "login required", "please sign in",
    "ليس لديك", "غير مصرح",
)


# ---------------------------------------------------------------------------
# JWT claim harvesting (seeds for templated endpoints)
# ---------------------------------------------------------------------------

# Claim names worth harvesting as seed values. All are kept; which one
# actually fills a given {placeholder} is resolved by name at render time
# (see render_templated_url) - a token rarely has all of these at once.
_JWT_ID_CLAIMS = (
    "sub", "user_id", "userId", "uid", "id",
    "account_id", "accountId", "customer_id", "customerId",
    "tenant_id", "tenantId", "org_id", "orgId", "organization_id",
    "email",
)


def decode_jwt_claims(token: str) -> Dict[str, Any]:
    """Best-effort decode of a JWT's payload claims.

    Never verifies the signature - we don't have the key, and don't need
    one: this reads data the client already trusted enough to send on every
    request, it doesn't authenticate anything itself. Never raises; a
    malformed or non-JWT token (most bearer tokens aren't JWTs at all)
    simply yields no claims.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload + padding)
        data = json.loads(raw)
    except (ValueError, TypeError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _harvest_jwt_seed_values(headers: Dict[str, str]) -> Dict[str, str]:
    """Pull id-shaped seed values out of an ``Authorization: Bearer <JWT>`` header, if any."""
    auth = ""
    for k, v in headers.items():
        if k.lower() == "authorization":
            auth = v
            break
    if not auth.lower().startswith("bearer "):
        return {}
    claims = decode_jwt_claims(auth[7:].strip())
    seeds: Dict[str, str] = {}
    for claim_name in _JWT_ID_CLAIMS:
        value = claims.get(claim_name)
        if value is not None and not isinstance(value, (dict, list)):
            seeds[claim_name] = str(value)
    return seeds


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass
class Identity:
    """One test account. ``headers`` is sent on every replay for this identity.

    ``seed_values`` maps an id-shaped field name (``"id"``, ``"user_id"``,
    ``"sub"``, ...) to a concrete value for this identity - used to render
    templated endpoints like ``/users/{id}`` that were never seen live (see
    ``render_templated_url``). Auto-harvested from the Authorization bearer
    token's own JWT claims when possible; pass your own (or add to it after
    construction) to cover a non-JWT token or a project-specific claim name -
    caller-supplied values always win over harvested ones.
    """

    name: str
    headers: Dict[str, str]
    seed_values: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        harvested = _harvest_jwt_seed_values(self.headers)
        self.seed_values = {**harvested, **self.seed_values}


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
    # "observed"  - owner_identity came from traffic_monitor.py's identity_name (directly watched)
    # "seeded"    - owner_identity is a guess: the URL was rendered from that identity's own JWT claim
    # "unowned"   - no owner at all; comparing whichever identities responded
    grounding: str = "observed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "owner_identity": self.owner_identity,
            "grounding": self.grounding,
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


def _flatten_kv(obj: Any, prefix: str = "") -> Dict[str, str]:
    """Like ``_flatten_keys``, but keeps one representative *value* (as a
    string) per key-path too. Used only by ``detect_volatile_keys`` to spot
    which fields change across repeated, same-identity calls - the shape
    (``_flatten_keys``) is what ``jaccard_key_similarity`` compares; the
    value is only ever looked at here, never surfaced in a finding.
    """
    out: Dict[str, str] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                out.update(_flatten_kv(v, path))
            else:
                out[path] = repr(v)
    elif isinstance(obj, list):
        for item in obj[:5]:
            out.update(_flatten_kv(item, f"{prefix}[]"))
    return out


def detect_volatile_keys(bodies: List[Optional[str]]) -> Set[str]:
    """Given >=2 same-identity, same-request baseline bodies, return the
    JSON key-paths whose value changed between them - timestamps, nonces,
    rotating tokens, request IDs. Fewer than 2 parseable bodies -> no
    evidence either way, so nothing is excluded (empty set), not "everything
    is volatile"."""
    parsed = []
    for body in bodies:
        if not body:
            continue
        try:
            parsed.append(_flatten_kv(json.loads(body)))
        except (ValueError, TypeError, RecursionError):
            continue
    if len(parsed) < 2:
        return set()
    all_keys: Set[str] = set()
    for p in parsed:
        all_keys |= p.keys()
    _MISSING = object()
    volatile: Set[str] = set()
    for key in all_keys:
        values = {p.get(key, _MISSING) for p in parsed}
        if len(values) > 1:
            volatile.add(key)
    return volatile


def jaccard_key_similarity(
    body_a: Optional[str], body_b: Optional[str], *, exclude_keys: Optional[Set[str]] = None
) -> Optional[float]:
    """Jaccard similarity of two responses' JSON key-path sets, or ``None``
    when either body isn't parseable JSON (comparison falls back to size/
    status alone in that case - see ``compare()``).

    ``exclude_keys`` (normally the owner's own ``detect_volatile_keys``
    output) is subtracted from both sides first, so a timestamp or nonce
    field that legitimately differs on every call can't itself tank - or
    inflate - the similarity score.
    """
    if not body_a or not body_b:
        return None
    try:
        keys_a = _flatten_keys(json.loads(body_a))
        keys_b = _flatten_keys(json.loads(body_b))
    except (ValueError, TypeError, RecursionError):
        return None
    if exclude_keys:
        keys_a -= exclude_keys
        keys_b -= exclude_keys
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


_TEMPLATE_PARAM = re.compile(r"\{([^{}]+)\}")

# A placeholder that names the token holder's own identifier generically
# (id, uuid, userId, user_id, ...) rather than a *different* entity
# (tenant/account/customer/owner/org - see PARAM_NAME_ID_MARKER). Only this
# narrower set is allowed to fall back to the JWT "sub" claim below.
_GENERIC_ID_PLACEHOLDER = re.compile(
    r"(?:^|[_\-])(?:id|uuid|guid)$|(?-i:[a-z]Id$)", re.IGNORECASE
)


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def render_templated_url(url: str, seed_values: Dict[str, str]) -> Optional[str]:
    """Substitute every ``{param}`` in ``url`` using ``seed_values``, or
    return ``None`` if it can't be done safely.

    Two things make this safe rather than a guess: every placeholder in the
    URL must look like an object/tenant reference by *name*
    (``PARAM_NAME_ID_MARKER``, the same regex api_discovery.py uses) - a
    non-id placeholder such as ``{version}`` aborts the whole render, nothing
    partial is returned - and every id-shaped placeholder must resolve to an
    actual seed value (never a placeholder or empty string standing in for
    one).

    Matching order per placeholder: the seed_values key by its exact name,
    then lowercase, then snake_case (a spec's ``{userId}`` and a JWT's
    ``user_id`` claim don't always agree on casing) - and only for a *bare*
    id placeholder (``_GENERIC_ID_PLACEHOLDER``: ``id``, ``uuid``, ``userId``,
    ... - never ``tenantId``/``accountId``/etc, which name a different
    entity), a last fallback to the JWT ``sub`` claim: by RFC 7519, ``sub``
    *is* the token holder's own canonical identifier, so ``{id}``/``{userId}``
    almost always means "this identity's own ID" even when the token has no
    claim literally called ``id``.
    """
    out = url
    for match in _TEMPLATE_PARAM.finditer(url):
        name = match.group(1)
        if not PARAM_NAME_ID_MARKER.search(name):
            return None
        value = (
            seed_values.get(name)
            or seed_values.get(name.lower())
            or seed_values.get(_snake(name))
        )
        if not value and _GENERIC_ID_PLACEHOLDER.search(name):
            value = seed_values.get("sub")
        if not value:
            return None
        out = out.replace(match.group(0), value, 1)
    return out


def check_baseline_stability(statuses: List[Optional[int]], volatile_key_count: int, total_key_count: int) -> Tuple[bool, List[str]]:
    """Is the owner's own repeated baseline trustworthy enough to score against?

    Two independent red flags, either one enough to call it unstable:
    the owner's *own* status code isn't even consistent across identical
    calls (session expiring mid-test, a flaky backend, load-balanced
    instances disagreeing - any of which would make a mismatch meaningless),
    or almost the entire body changes between calls (nothing stable left to
    compare on). A completely empty/non-JSON body (``total_key_count == 0``)
    is judged on status alone - there's no "volatile fraction" to compute.
    """
    notes: List[str] = []
    real_statuses = {s for s in statuses if s is not None}
    if len(real_statuses) > 1:
        notes.append(f"owner baseline status is inconsistent across repeats: {sorted(real_statuses)}")
        return False, notes
    if total_key_count > 0 and volatile_key_count / total_key_count > 0.6:
        notes.append(
            f"owner baseline body is mostly volatile ({volatile_key_count}/{total_key_count} fields change "
            f"call to call) - too noisy to trust a single-call comparison"
        )
        return False, notes
    return True, notes


def compare(
    owner: Optional[ReplaySample],
    other: ReplaySample,
    *,
    grounded: bool,
    exclude_keys: Optional[Set[str]] = None,
    baseline_stable: bool = True,
) -> Tuple[str, Optional[float], List[str]]:
    """Multi-factor comparison -> (confidence, json_similarity, notes).

    Mirrors ``bola``'s own scoring recipe: status-code match, response-size
    delta, JSON structural (Jaccard) similarity, and an error-body sniff,
    combined rather than trusting any one signal - a size-only or
    status-only check is exactly what produces the false positives/negatives
    a reviewer would ask about first.

    ``grounded`` must be ``True`` only when ``owner`` is a sample taken with
    a *directly verified* owner's identity (traffic captured with
    ``identity_name`` set) - **not** merely "a sample happens to be
    available". A JWT-seeded owner (plausible, but inferred from a claim)
    also passes ``grounded=False`` for this reason, same ceiling as an
    unowned candidate; conflating "no baseline at all" with "an unverified
    baseline" here is exactly the bug that let an unowned match reach HIGH
    in testing.

    ``exclude_keys`` is normally the owner's own ``detect_volatile_keys()``
    output: fields that change across repeated owner-only calls (timestamps,
    nonces, ...) and so shouldn't count for or against a structural match.

    ``baseline_stable=False`` (the owner's own repeated calls didn't agree
    with each other - see ``check_baseline_stability``) forces the result
    down to at most LOW: an unstable baseline isn't evidence of anything.
    """
    notes: List[str] = []
    if other.error:
        return "NONE", None, [f"replay failed: {other.error}"]
    if other.status is None:
        return "NONE", None, ["no response"]

    # A clean denial is success, not a finding.
    if other.status in (401, 403, 404):
        return "NONE", None, [f"got {other.status} - access control appears enforced"]

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

    similarity = jaccard_key_similarity(
        owner.body_snippet if owner else None, other.body_snippet, exclude_keys=exclude_keys
    )
    if similarity is not None:
        notes.append(f"JSON key-structure similarity {similarity:.0%}" + (
            " (volatile fields excluded)" if exclude_keys else ""
        ))

    def _cap(confidence: str) -> str:
        if not baseline_stable and confidence in ("HIGH", "MEDIUM"):
            notes.append(f"capped from {confidence} to LOW - owner baseline was unstable, see notes above")
            return "LOW"
        return confidence

    if not grounded:
        # Ownership unverified (unowned, or JWT-seeded guess): the ceiling is
        # MEDIUM no matter how well the two responses match - "two
        # identities both got 200 with similar JSON" is consistent with a
        # real cross-tenant leak, but equally consistent with an
        # intentionally shared/public resource. Only a directly-observed
        # owner sample can push this to HIGH.
        if other.status == 200 and status_match and (similarity is None or similarity >= 0.5):
            return _cap("MEDIUM"), similarity, notes
        return "LOW", similarity, notes

    if status_match and similarity is not None and similarity >= 0.85:
        return _cap("HIGH"), similarity, notes
    if status_match and (similarity is None or similarity >= 0.5) and (
        size_delta_pct is None or size_delta_pct <= 0.3
    ):
        return _cap("MEDIUM"), similarity, notes
    if status_match:
        return "LOW", similarity, notes
    return "NONE", similarity, notes


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
        scope_manager: Optional[ScopeManager] = None,
    ) -> None:
        if len(identities) < 2:
            raise ValueError("BolaTester needs at least two identities to compare")
        self.identities = identities
        self.scope_manager = scope_manager
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
        self._backoff = AdaptiveRateLimiter()
        self._max_redirects = 5
        self._max_429_retries = 3
        self.errors: List[str] = []

    # -- candidate selection --------------------------------------------------

    @staticmethod
    def _is_concrete(url: str) -> bool:
        """False for a still-templated spec path like /users/{id} - nothing to replay."""
        return "{" not in url and "}" not in url

    def _replayable_method(self, record: EndpointRecord) -> Optional[str]:
        methods = record.methods - {"*"} or {"GET"}
        if "GET" in methods or "HEAD" in methods:
            return "GET"
        if methods & DESTRUCTIVE_METHODS and not self.allow_destructive:
            return None  # exists, but needs --allow-destructive to replay
        return sorted(methods)[0] if methods else None

    def candidates(self, report: DiscoveryReport) -> List[Tuple[EndpointRecord, str]]:
        """``(record, method)`` pairs worth testing: concrete, bola_candidate,
        and either read-only or explicitly allowed to be replayed.

        Templated URLs (``{id}`` still unresolved) are excluded here -
        ``seed_candidates()`` is what tries to resolve those via JWT claims.
        """
        out: List[Tuple[EndpointRecord, str]] = []
        for url, record in report.endpoints.items():
            details = record.details or {}
            if not details.get("bola_candidate"):
                continue
            if not self._is_concrete(url):
                continue
            method = self._replayable_method(record)
            if method is None:
                continue
            out.append((record, method))
        return out

    def seed_candidates(self, report: DiscoveryReport) -> List[Tuple[EndpointRecord, str, str, str]]:
        """``(record, method, rendered_url, owner_name)`` for templated
        ``bola_candidate`` endpoints (``/users/{id}``, never observed live)
        that at least one identity's own harvested JWT claims let us render
        into a concrete URL - see ``render_templated_url`` and the module
        docstring's "Seeded candidates" section. ``owner_name`` is that
        identity: plausible, not verified.

        One render per endpoint (the first identity whose claims fit) - if
        several identities could render the same template, that's still one
        candidate resource to test, not a reason to multiply requests.
        """
        out: List[Tuple[EndpointRecord, str, str, str]] = []
        for url, record in report.endpoints.items():
            if self._is_concrete(url):
                continue
            details = record.details or {}
            if not details.get("bola_candidate"):
                continue
            method = self._replayable_method(record)
            if method is None:
                continue
            for identity in self.identities:
                if not identity.seed_values:
                    continue
                rendered = render_templated_url(url, identity.seed_values)
                if rendered:
                    out.append((record, method, rendered, identity.name))
                    break
        return out

    # -- low-level replay -------------------------------------------------------

    async def _replay(self, url: str, method: str, identity: Identity) -> ReplaySample:
        if self.scope_manager is None:
            msg = "No scope manager configured; replay refused"
            self.errors.append(f"{method} {url} as {identity.name}: {msg}")
            return ReplaySample(None, None, None, None, None, error=msg)

        try:
            self.scope_manager.require_in_scope(url)
        except ScopeError as exc:
            msg = f"URL outside authorized scope; replay refused ({exc})"
            self.errors.append(f"{method} {url} as {identity.name}: {msg}")
            return ReplaySample(None, None, None, None, None, error=msg)

        await self._limiter.acquire()
        async with self._sem:
            started = time.monotonic()
            current_url = url
            redirect_count = 0
            retry_429_count = 0

            while True:
                try:
                    assert self._session is not None
                    async with self._session.request(
                        method, current_url, headers=identity.headers, allow_redirects=False
                    ) as resp:
                        if resp.status == 429 and retry_429_count < self._max_429_retries:
                            delay = self._backoff.backoff_delay(
                                retry_429_count, resp.headers.get("Retry-After")
                            )
                            retry_429_count += 1
                            await asyncio.sleep(delay)
                            continue

                        if resp.status in REDIRECT_STATUSES and "Location" in resp.headers:
                            if redirect_count >= self._max_redirects:
                                msg = f"too many redirects (> {self._max_redirects})"
                                self.errors.append(f"{method} {url} as {identity.name}: {msg}")
                                return ReplaySample(None, None, None, None, None, error=msg)

                            try:
                                current_url = resolve_redirect(
                                    self.scope_manager, current_url, resp.headers["Location"]
                                )
                            except ScopeError as exc:
                                msg = f"redirect left authorized scope: {exc}"
                                self.errors.append(f"{method} {url} as {identity.name}: {msg}")
                                return ReplaySample(None, None, None, None, None, error=msg)
                            redirect_count += 1
                            continue

                        body = await resp.content.read(self.max_body_bytes)
                        text = body.decode("utf-8", errors="replace") if body else None
                        return ReplaySample(
                            status=resp.status,
                            length=len(body) if body else _to_int(resp.headers.get("Content-Length")),
                            content_type=resp.headers.get("Content-Type"),
                            body_snippet=text,
                            elapsed_ms=(time.monotonic() - started) * 1000,
                        )
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
                    msg = f"{type(exc).__name__}: {exc}"
                    self.errors.append(f"{method} {current_url} as {identity.name}: {msg}")
                    return ReplaySample(None, None, None, None, None, error=msg)

    @staticmethod
    def _curl(url: str, method: str, identity: Identity) -> str:
        parts = [f"curl -X {method} '{url}'"]
        for k, v in identity.headers.items():
            shown = v if k.lower() != "authorization" else v[:16] + "...<redacted>"
            parts.append(f"  -H '{k}: {shown}'")
        return " \\\n".join(parts)

    # -- orchestration ----------------------------------------------------------

    async def run(self, report: DiscoveryReport) -> List[BolaFinding]:
        """Test every candidate in ``report`` across all supplied identities,
        plus every templated endpoint a JWT seed can render."""
        findings: List[BolaFinding] = []
        pairs = self.candidates(report)
        seeded = self.seed_candidates(report)
        logger.info(
            "BOLA testing: %d candidate(s) + %d JWT-seeded template(s) across %d identit(y/ies)",
            len(pairs), len(seeded), len(self.identities),
        )
        if not pairs and not seeded:
            return findings

        connector = aiohttp.TCPConnector(limit=max(2, self.cfg_concurrency * 2))
        async with aiohttp.ClientSession(timeout=self._timeout, connector=connector) as session:
            self._session = session
            tasks = [self._test_one(record, method) for record, method in pairs]
            tasks += [
                self._test_owned(rendered_url, method, owner_name, grounding="seeded")
                for _record, method, rendered_url, owner_name in seeded
            ]
            results = await asyncio.gather(*tasks)
            for group in results:
                findings.extend(group)

        findings = [f for f in findings if self._rank[f.confidence] >= self._rank[self.min_confidence]]
        findings.sort(key=lambda f: self._rank[f.confidence], reverse=True)
        logger.info("BOLA testing finished: %d finding(s) at/above %s", len(findings), self.min_confidence)
        return findings

    async def _sample_owner_baseline(
        self, url: str, method: str, owner: Identity
    ) -> Tuple[ReplaySample, Set[str], bool, List[str]]:
        """Replay (url, method) as ``owner`` three times (not once) and
        return (first sample - used as the actual baseline for comparison,
        volatile key-paths to exclude, whether the baseline is stable enough
        to trust, stability notes). See the module docstring's "Owner-
        baseline volatility and stability" section.
        """
        samples = [await self._replay(url, method, owner) for _ in range(3)]
        primary = samples[0]
        volatile = detect_volatile_keys([s.body_snippet for s in samples])
        try:
            total_keys = len(_flatten_keys(json.loads(primary.body_snippet))) if primary.body_snippet else 0
        except (ValueError, TypeError, RecursionError):
            total_keys = 0
        stable, stability_notes = check_baseline_stability(
            [s.status for s in samples], len(volatile), total_keys
        )
        return primary, volatile, stable, stability_notes

    async def _test_owned(
        self, url: str, method: str, owner_name: str, *, grounding: str
    ) -> List[BolaFinding]:
        """Shared replay+compare loop for any candidate with a presumed
        owner - whether ``grounding="observed"`` (traffic-captured with
        ``identity_name``) or ``grounding="seeded"`` (JWT-claim-rendered
        template). Only "observed" can reach HIGH; ``compare()`` enforces
        that via ``grounded=(grounding == "observed")``.
        """
        out: List[BolaFinding] = []
        owner = self._by_name.get(owner_name)
        if owner is None:
            return out
        owner_sample, volatile_keys, stable, stability_notes = await self._sample_owner_baseline(
            url, method, owner
        )
        for other in self.identities:
            if other.name == owner_name:
                continue
            other_sample = await self._replay(url, method, other)
            confidence, similarity, notes = compare(
                owner_sample, other_sample,
                grounded=(grounding == "observed"),
                exclude_keys=volatile_keys,
                baseline_stable=stable,
            )
            if confidence == "NONE":
                continue
            extra = list(stability_notes)
            if grounding == "seeded":
                extra.append(
                    f"owner inferred from {owner_name}'s own JWT claim, not directly observed"
                )
            out.append(BolaFinding(
                endpoint=url, method=method,
                owner_identity=owner_name, tester_identity=other.name,
                confidence=confidence, owner_sample=owner_sample, other_sample=other_sample,
                json_similarity=similarity, notes=extra + notes,
                curl_command=self._curl(url, method, other),
                grounding=grounding,
            ))
        return out

    async def _test_one(self, record: EndpointRecord, method: str) -> List[BolaFinding]:
        details = record.details or {}
        owner_name = details.get("owner_identity")

        if owner_name and owner_name in self._by_name:
            return await self._test_owned(record.url, method, owner_name, grounding="observed")

        # Unowned candidate: no identity to use as the baseline. Try every
        # identity and flag it (capped at MEDIUM in compare()) if more than
        # one gets a non-error response - see the module docstring.
        out: List[BolaFinding] = []
        samples = [(ident, await self._replay(record.url, method, ident)) for ident in self.identities]
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
                curl_command=self._curl(record.url, method, ident),
                grounding="unowned",
            ))
        return out


def _to_int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
