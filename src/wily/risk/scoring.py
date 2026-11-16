"""Risk Score: a function of severity + confidence, as a simple
deterministic v0.1 baseline."""

from __future__ import annotations

_SEVERITY_WEIGHTS = {
    "info": 1,
    "low": 3,
    "medium": 5,
    "high": 8,
    "critical": 10,
}


def compute_risk_score(severity: str, confidence: float) -> float:
    base = _SEVERITY_WEIGHTS.get(severity, 1)
    score = base * max(0.0, min(confidence, 1.0))
    return round(score, 2)
