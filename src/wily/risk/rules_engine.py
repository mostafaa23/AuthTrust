"""Deterministic Baseline rules - the baseline that runs before any ML.

TODO: functions to aggregate/correlate findings for the same asset, and
initial deduplication.
"""


def apply_deterministic_rules(findings: list) -> list:
    """Baseline correlation/dedup pass.

    Intentionally a non-destructive pass-through for now: it must never
    drop a real finding. Until real aggregation/dedup heuristics land,
    returning the findings unchanged is strictly safer than raising (which
    would abort a whole scan) or filtering (which would risk false
    negatives on genuine results).
    """
    return list(findings)
