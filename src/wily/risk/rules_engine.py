"""Deterministic baseline rules - the correlation/dedup pass that runs
before any ML and before the final report.

Design contract: this pass must never drop a *genuinely distinct* finding.
It only collapses exact duplicates - the same vulnerability reported more
than once for the same asset (e.g. because two discovery sources routed the
same endpoint into the same scanner). When two findings collapse, the one
with the higher confidence is kept, so correlation can only ever raise the
quality of the reported set, never hide a real result.
"""

from __future__ import annotations


def _dedup_key(finding) -> tuple:
    """A finding's identity for dedup: same asset + category + technique +
    method is considered the same underlying issue. Uses getattr/.get so it
    is tolerant of findings that don't populate every evidence field."""
    evidence = getattr(finding, "evidence", None) or {}
    return (
        getattr(finding, "asset", None),
        getattr(finding, "category", None),
        evidence.get("technique"),
        evidence.get("method"),
    )


def apply_deterministic_rules(findings: list) -> list:
    """Collapse exact-duplicate findings, keeping the highest-confidence copy.

    Order is preserved by first appearance. A finding without a resolvable
    key (e.g. a non-standard object) is always kept as-is rather than risk
    dropping it.
    """
    best_by_key: dict[tuple, object] = {}
    order: list[tuple] = []
    passthrough: list = []

    for finding in findings:
        try:
            key = _dedup_key(finding)
        except Exception:
            passthrough.append(finding)
            continue

        if key not in best_by_key:
            best_by_key[key] = finding
            order.append(key)
            continue

        # Duplicate: keep whichever has the higher confidence.
        existing = best_by_key[key]
        if getattr(finding, "confidence", 0.0) > getattr(existing, "confidence", 0.0):
            best_by_key[key] = finding

    deduped = [best_by_key[k] for k in order]
    return deduped + passthrough
