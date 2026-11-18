"""Near-duplicate finding clustering.

Runs after ``rules_engine.apply_deterministic_rules`` has removed exact
duplicates. Catches the softer case: findings for the same
``(asset, category)`` whose evidence text is near-identical (difflib
ratio above a threshold) get collapsed, keeping the higher-confidence
copy and recording ``duplicate_count`` on it. Never drops a genuinely
distinct finding.
"""

from __future__ import annotations

import difflib

# How similar two findings' evidence must be (0..1) before they are treated as
# the same underlying issue. High on purpose: this pass should only merge
# findings that are *near-identical*, never ones that merely share an asset and
# category but describe different problems.
_SIMILARITY_THRESHOLD = 0.9


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
