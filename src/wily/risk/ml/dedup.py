"""Near-duplicate finding clustering, plus endpoint-hash clustering.

Two complementary passes, both run after ``rules_engine.apply_deterministic_rules``
has removed exact duplicates:

  - ``deduplicate()``: findings for the same ``(asset, category)`` whose
    evidence text is near-identical (difflib ratio above a threshold) get
    collapsed, keeping the higher-confidence copy and recording
    ``duplicate_count`` on it.
  - ``cluster_by_endpoint_hash()``: a coarser, DefectDojo-style pass that
    collapses findings sharing the same (category, normalized endpoint path,
    parameter/technique) hash - the same underlying issue hit across many
    concrete object ids (``/invoices/1`` .. ``/invoices/100`` normalize to
    one ``/invoices/{id}`` root finding) even though they're on *different*
    concrete assets, which ``deduplicate()`` alone wouldn't merge.

Neither pass ever drops a genuinely distinct finding.
"""

from __future__ import annotations

import difflib
import hashlib
import re
from urllib.parse import urlsplit

# How similar two findings' evidence must be (0..1) before they are treated as
# the same underlying issue. High on purpose: this pass should only merge
# findings that are *near-identical*, never ones that merely share an asset and
# category but describe different problems.
_SIMILARITY_THRESHOLD = 0.9


def get_field(obj, name: str, default=None):
    """Attribute or dict-key access, whichever ``obj`` supports.

    Lets the hash-key helpers below work both on a ``Finding`` dataclass
    (the live scan pipeline) and on a plain dict reloaded from a JSON report
    (``cli/commands/triage_cmd.py`` and ``risk/ml/feedback.py``), without
    the live pipeline's existing ``getattr``-based helpers above having to
    change.
    """
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _cluster_key(finding) -> tuple:
    """The group a finding can near-duplicate within: same asset + category.
    Tolerant of findings that don't populate every field."""
    return (
        getattr(finding, "asset", None),
        getattr(finding, "category", None),
    )


def _evidence_fingerprint(finding) -> str:
    """A stable, comparable string summary of a finding's evidence.

    Scalar evidence values are flattened into ``key=value`` pairs sorted by
    key, so two findings with the same evidence produce the same string
    regardless of dict ordering. Non-scalar values are rendered by ``repr`` as a
    best effort. Used only for similarity comparison, never exported.
    """
    evidence = getattr(finding, "evidence", None) or {}
    if not isinstance(evidence, dict):
        return repr(evidence)
    parts = []
    for key in sorted(evidence, key=str):
        value = evidence[key]
        if isinstance(value, (str, int, float, bool)) or value is None:
            parts.append(f"{key}={value}")
        else:
            parts.append(f"{key}={value!r}")
    return "|".join(parts)


def _is_near_duplicate(a_fp: str, b_fp: str) -> bool:
    """True when two evidence fingerprints are near-identical. Two empty
    fingerprints (findings with no evidence, same asset+category) count as
    duplicates - with nothing to tell them apart they are the same issue."""
    if a_fp == b_fp:
        return True
    if not a_fp and not b_fp:
        return True
    return difflib.SequenceMatcher(None, a_fp, b_fp).ratio() >= _SIMILARITY_THRESHOLD


def deduplicate(findings: list) -> list:
    """Collapse near-identical findings, keeping the highest-confidence copy.

    Order is preserved by first appearance. For each incoming finding, if it is
    near-identical (same asset + category, evidence similarity above threshold)
    to one already kept, the two are merged: the higher-confidence finding wins
    and its ``evidence['duplicate_count']`` is incremented. Otherwise the
    finding is kept as a new, distinct result.

    A finding whose cluster key can't be resolved is always kept as-is rather
    than risk dropping a real result.
    """
    kept: list = []
    # cluster key -> list of (fingerprint, index-into-kept)
    clusters: dict[tuple, list[tuple[str, int]]] = {}

    for finding in findings:
        try:
            key = _cluster_key(finding)
            fingerprint = _evidence_fingerprint(finding)
        except Exception:
            kept.append(finding)
            continue

        match_index = None
        for member_fp, member_index in clusters.get(key, []):
            if _is_near_duplicate(fingerprint, member_fp):
                match_index = member_index
                break

        if match_index is None:
            kept.append(finding)
            clusters.setdefault(key, []).append((fingerprint, len(kept) - 1))
            continue

        # Near-duplicate of an already-kept finding: merge into it.
        existing = kept[match_index]
        prior = _duplicate_count(existing)
        incoming = _duplicate_count(finding)
        winner = (
            finding
            if getattr(finding, "confidence", 0.0) > getattr(existing, "confidence", 0.0)
            else existing
        )
        merged_count = prior + incoming
        _set_duplicate_count(winner, merged_count)
        if winner is not existing:
            kept[match_index] = winner
            # Refresh the stored fingerprint so later members compare against
            # the finding that is actually kept.
            member_list = clusters[key]
            for i, (_, idx) in enumerate(member_list):
                if idx == match_index:
                    member_list[i] = (_evidence_fingerprint(winner), match_index)
                    break

    return kept


def _duplicate_count(finding) -> int:
    evidence = getattr(finding, "evidence", None)
    if isinstance(evidence, dict):
        try:
            return int(evidence.get("duplicate_count", 1))
        except (TypeError, ValueError):
            return 1
    return 1


def _set_duplicate_count(finding, count: int) -> None:
    """Record how many raw findings collapsed into this one (only when >1, to
    keep the evidence of singletons clean)."""
    if count <= 1:
        return
    evidence = getattr(finding, "evidence", None)
    if isinstance(evidence, dict):
        evidence["duplicate_count"] = count


# ---------------------------------------------------------------------------
# Endpoint-hash clustering (DefectDojo-style hash-code)
# ---------------------------------------------------------------------------

# A version prefix (v1, v2, ...) is checked first and deliberately left
# alone even though it's all-but-numeric: collapsing /v1/orders and
# /v2/orders into the same hash would merge findings from two different API
# versions, which is a different question (or no bug at all in v2) rather
# than the same finding on two object ids.
_VERSION_SEGMENT_RE = re.compile(r"^v\d+$", re.IGNORECASE)
_UUID_SEGMENT_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_NUMERIC_SEGMENT_RE = re.compile(r"^\d+$")
# A long hex-only token (Mongo ObjectId, a hash, a non-UUID opaque id) - long
# enough that it won't accidentally match a short, meaningful path segment.
_HEX_ID_SEGMENT_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)


def _normalize_path_segment(segment: str) -> str:
    """One URL path segment -> itself, or ``"{id}"`` if it looks like an
    object identifier rather than a fixed route component."""
    if _VERSION_SEGMENT_RE.match(segment):
        return segment
    if (
        _UUID_SEGMENT_RE.match(segment)
        or _NUMERIC_SEGMENT_RE.match(segment)
        or _HEX_ID_SEGMENT_RE.match(segment)
    ):
        return "{id}"
    return segment


def normalize_endpoint_path(asset: str) -> str:
    """``asset``'s URL path with object-id-shaped segments collapsed to
    ``{id}`` - so ``/invoices/1``, ``/invoices/2``, ... ``/invoices/100``
    all normalize to ``/invoices/{id}``.

    A non-HTTP asset (e.g. ``"s3://bucket"``, a bare hostname) or one with no
    path is returned unchanged - there's nothing url-shaped to normalize, and
    guessing wrong here would risk merging unrelated findings.
    """
    asset = asset or ""
    try:
        parts = urlsplit(asset)
    except (ValueError, AttributeError):
        return asset
    if not parts.scheme or not parts.path:
        return asset
    segments = parts.path.split("/")
    return "/".join(_normalize_path_segment(s) if s else s for s in segments)


def finding_hash_key(finding) -> str:
    """A DefectDojo-style stable identity for ``finding``: a hash of
    (category, normalized endpoint path, parameter/technique).

    Two findings that are "the same underlying issue hit on a different
    object id" share this key even though they're on different concrete
    assets - deduplicate() above, which only clusters near-identical
    evidence on the *same* asset, wouldn't merge them. It is also the key
    ``risk/ml/feedback.py`` records an analyst's --valid/--fp decision
    against, so the decision survives a re-scan where the object id in the
    URL changes but the finding shape doesn't.

    Accepts a ``Finding`` dataclass or a plain dict (see ``get_field``), so
    it works both inside the live scan pipeline and on findings reloaded
    from a JSON report.
    """
    category = get_field(finding, "category", "") or ""
    asset = get_field(finding, "asset", "") or ""
    evidence = get_field(finding, "evidence", None) or {}
    if not isinstance(evidence, dict):
        evidence = {}
    param = (
        evidence.get("param")
        or evidence.get("param_name")
        or evidence.get("method")
        or evidence.get("technique")
        or ""
    )
    normalized_path = normalize_endpoint_path(asset)
    raw = f"{category}|{normalized_path}|{param}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _record_endpoint_merge(winner, existing, incoming) -> None:
    """Note, on ``winner``'s evidence, how many concrete endpoints have been
    folded into this root finding so far, plus a capped sample of them.

    The merge history lives on ``existing`` (the root kept so far, which
    accumulates across every merge for this hash-key) - never on ``winner``
    alone, since a higher-confidence ``incoming`` finding can itself become
    the new winner and would otherwise show up with a fresh, empty evidence
    dict that has never seen the earlier merges.
    """
    existing_evidence = get_field(existing, "evidence", None)
    prior_count = existing_evidence.get("merged_endpoint_count") if isinstance(existing_evidence, dict) else None
    prior_samples = existing_evidence.get("sample_merged_assets") if isinstance(existing_evidence, dict) else None

    samples = set(prior_samples or [])
    incoming_asset = get_field(incoming, "asset", None)

    if prior_count is None:
        existing_asset = get_field(existing, "asset", None)
        samples |= {existing_asset, incoming_asset}
        samples.discard(None)
        count = len(samples)
    else:
        count = prior_count
        if incoming_asset and incoming_asset not in samples:
            samples.add(incoming_asset)
            count += 1

    winner_evidence = get_field(winner, "evidence", None)
    if isinstance(winner_evidence, dict):
        winner_evidence["merged_endpoint_count"] = count
        winner_evidence["sample_merged_assets"] = sorted(s for s in samples if s)[:5]


def cluster_by_endpoint_hash(findings: list) -> list:
    """Collapse findings that share the same endpoint hash-key (see
    ``finding_hash_key``) even when they're on different concrete assets -
    e.g. the same BOLA finding repeated on ``/invoices/1`` through
    ``/invoices/100`` collapses to one root finding, keeping the highest-
    confidence copy and recording how many concrete endpoints were folded
    into it.

    Complements ``deduplicate()`` (same-asset near-duplicate clustering);
    this pass is coarser (same shape, any asset) and is meant to run after
    it in the pipeline - see ``cli/commands/scan_all.py``'s ``_finish()``.
    A finding whose hash can't be resolved is always kept as-is.
    """
    kept: list = []
    index_by_hash: dict[str, int] = {}

    for finding in findings:
        try:
            key = finding_hash_key(finding)
        except Exception:
            kept.append(finding)
            continue

        idx = index_by_hash.get(key)
        if idx is None:
            index_by_hash[key] = len(kept)
            kept.append(finding)
            continue

        existing = kept[idx]
        winner = (
            finding
            if get_field(finding, "confidence", 0.0) > get_field(existing, "confidence", 0.0)
            else existing
        )
        _record_endpoint_merge(winner, existing, finding)
        kept[idx] = winner

    return kept
