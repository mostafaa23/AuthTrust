"""HTTPX-style live-asset filtering (Phase 4, the "light ML" layer).

Before the orchestrator spends real scanner budget on a list of discovered /
imported endpoints, it runs them through this filter to cut three kinds of
waste:

  1. Exact duplicates - the same endpoint reached by several discovery sources
     (docs + JS + import) that normalise to one canonical URL.
  2. Near-identical duplicates - the same route with a different object id in a
     path segment (``/users/1`` vs ``/users/42``). For the per-endpoint scan
     loop these are the *same* endpoint; one representative is enough.
  3. Clearly-dead endpoints - optionally, a cheap liveness probe (HEAD, GET
     fallback) drops hosts that don't answer at all.

Design: the normalisation / dedup logic is a set of **pure functions** with no
I/O (easy to unit-test, offline, deterministic). The one function that touches
the network, :func:`filter_live_assets`, takes an injected ``http_engine`` so
every network call still goes through the shared, scope-enforcing
:class:`~wily.scanners.http_engine.HttpEngine`, and so tests can drive it with a
fake engine. The probe is **opt-in** (``probe=False`` by default); dedup always
runs because it is free.

This is deliberately heuristic - no model, no training. It is the "filter the
asset list down to live, distinct targets" step every recon chain (httpx, nuclei)
does before the expensive stage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

from wily.recon.api_discovery import canonical_url

# Path segments that are object identifiers rather than route structure. Two
# URLs that differ only in such a segment are the same endpoint for scanning
# purposes, so they collapse to one representative.
#   - a run of digits                     /orders/1024
#   - a uuid / guid                       /u/9f1c.../
#   - a long hex / mongo-objectid blob    /x/5f8d0c... (>=12 hex chars)
_NUMERIC_SEG = re.compile(r"^\d+$")
_UUID_SEG = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_HEXBLOB_SEG = re.compile(r"^[0-9a-f]{12,}$", re.IGNORECASE)

_ID_PLACEHOLDER = "{id}"


def normalize_url(url: str) -> str | None:
    """Canonicalise an endpoint URL into a stable dedup key.

    Thin wrapper over :func:`wily.recon.api_discovery.canonical_url` (lowercase
    host, strip ``www.``, drop default ports, drop query + fragment, strip a
    trailing slash) so Phase 4 shares the exact same canonical form the
    discovery pipeline already keys endpoints by. Returns ``None`` for a
    non-HTTP(S) or malformed URL.
    """
    return canonical_url(url)


def template_path(path: str) -> str:
    """Replace object-id path segments with ``{id}`` so routes that differ only
    by an identifier map to the same template.

    ``/api/users/42/orders/9f1c...`` -> ``/api/users/{id}/orders/{id}``. Pure
    string work; a segment that isn't clearly an id is left untouched so
    genuinely distinct routes stay distinct.
    """
    if not path:
        return path
    out_segments = []
    for seg in path.split("/"):
        if seg and (
            _NUMERIC_SEG.match(seg)
            or _UUID_SEG.match(seg)
            or _HEXBLOB_SEG.match(seg)
        ):
            out_segments.append(_ID_PLACEHOLDER)
        else:
            out_segments.append(seg)
    return "/".join(out_segments)


def _dedup_key(url: str, collapse_ids: bool) -> str | None:
    """The identity a URL collapses on: its canonical form, optionally with
    id-like path segments templated away."""
    canon = canonical_url(url)
    if canon is None:
        return None
    if not collapse_ids:
        return canon
    parts = urlparse(canon)
    templated = template_path(parts.path)
    return urlunparse(
        (parts.scheme, parts.netloc, templated, "", "", "")
    )


def dedup_urls(urls: list[str], *, collapse_ids: bool = True) -> list[str]:
    """Collapse exact and near-identical URLs, keeping the first representative.

    Pure function. The first URL seen for each dedup key is kept (in its
    original form, so it stays a usable scan target); later URLs that map to the
    same key are dropped. ``collapse_ids`` also folds routes that differ only by
    an object id into one representative; set it ``False`` to dedup on the exact
    canonical URL only.

    A URL that doesn't canonicalise (non-HTTP(S) / malformed) is kept as-is
    rather than silently dropped - the filter must never lose a target it cannot
    classify.
    """
    kept: list[str] = []
    seen: set[str] = set()
    for url in urls:
        key = _dedup_key(url, collapse_ids)
        if key is None:
            # Not classifiable - keep it, but guard against literal repeats.
            if url not in seen:
                seen.add(url)
                kept.append(url)
            continue
        if key in seen:
            continue
        seen.add(key)
        kept.append(url)
    return kept


def partition_in_scope(urls: list[str], scope) -> tuple[list[str], list[str]]:
    """Split ``urls`` into (in_scope, out_of_scope) using a ScopeManager.

    Pure w.r.t. the network (``scope.is_in_scope`` does no I/O). A ``None``
    scope passes everything through as in-scope.
    """
    if scope is None:
        return list(urls), []
    in_scope: list[str] = []
    out_scope: list[str] = []
    for url in urls:
        try:
            ok = scope.is_in_scope(url)
        except Exception:
            ok = False
        (in_scope if ok else out_scope).append(url)
    return in_scope, out_scope


@dataclass
class LiveFilterResult:
    """Outcome of filtering an endpoint list down to live, distinct targets."""

    kept: list[str] = field(default_factory=list)  # live, distinct scan targets
    collapsed: int = 0  # dropped as exact / near-identical duplicates
    out_of_scope: list[str] = field(default_factory=list)  # dropped by scope
    dead: list[str] = field(default_factory=list)  # dropped by the liveness probe

    @property
    def dropped(self) -> int:
        return self.collapsed + len(self.out_of_scope) + len(self.dead)


def is_live(http_engine, url: str) -> bool:
    """Cheap liveness check for one URL through the shared HttpEngine.

    "Live" = the server answered with *any* HTTP status (even 401/403/404 means
    something is listening). A transport failure - connection refused, DNS
    failure, timeout, or a scope/SSRF refusal - means "dead / unreachable" and
    the endpoint is dropped. HEAD is tried first (cheapest); a server that
    rejects HEAD (405/501) is re-probed with GET so a method-picky host isn't
    mistaken for a dead one.

    Every request goes through ``http_engine``, so the ScopeManager and
    rate-limiter still apply - this never routes around scope policy.
    """
    try:
        resp = http_engine.request("HEAD", url)
    except Exception:
        return False
    if getattr(resp, "status_code", None) in (405, 501):
        try:
            resp = http_engine.request("GET", url)
        except Exception:
            return False
    return getattr(resp, "status_code", None) is not None


def filter_live_assets(
    urls: list[str],
    *,
    scope=None,
    http_engine=None,
    probe: bool = False,
    collapse_ids: bool = True,
) -> LiveFilterResult:
    """Filter a discovered/imported endpoint list down to live, distinct targets.

    Steps, in order:
      1. Dedup (always, free): collapse exact + near-identical URLs.
      2. Scope (when ``scope`` given): drop out-of-scope URLs.
      3. Liveness (only when ``probe=True`` and an ``http_engine`` is given):
         drop endpoints that don't answer at all.

    Returns a :class:`LiveFilterResult` carrying the kept targets and counts for
    each drop reason, so the caller can report *why* the list shrank. Order of
    the kept list follows first appearance in ``urls``.
    """
    deduped = dedup_urls(urls, collapse_ids=collapse_ids)
    collapsed = len(urls) - len(deduped)

    in_scope, out_scope = partition_in_scope(deduped, scope)

    dead: list[str] = []
    if probe and http_engine is not None:
        alive: list[str] = []
        for url in in_scope:
            if is_live(http_engine, url):
                alive.append(url)
            else:
                dead.append(url)
        in_scope = alive

    return LiveFilterResult(
        kept=in_scope,
        collapsed=collapsed,
        out_of_scope=out_scope,
        dead=dead,
    )
