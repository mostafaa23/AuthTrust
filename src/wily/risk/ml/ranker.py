"""Finding prioritisation / ranking (Phase 4, the "light ML" layer).

Orders the findings for the report. Deliberately heuristic - no model, no
training. The base signal is the same ``risk_score`` the rest of Wily uses
(severity x confidence, see ``risk/scoring.py``); on top of it this pass adds a
few small, explainable boosts so that, among findings of comparable base risk,
the ones that matter most to an operator float to the top:

  - **Impact class** - credential exposure, public buckets, SSRF/IMDS, IAM
    privesc, cross-tenant access (BOLA) and resource takeover are the findings
    that chain into real compromise, so they get a small lift over, say, a
    missing-header CORS note of the same base score.
  - **Corroboration** - a finding that near-duplicate clustering merged
    (``duplicate_count`` > 1) was seen more than once, so it is slightly less
    likely to be noise.

The boosts are intentionally small (sub-severity) so they only ever break ties
and nudge ordering; they never let a low-severity finding leapfrog a genuinely
critical one. Every boost is recorded in ``evidence['rank_reasons']`` and the
final priority in ``evidence['rank_score']`` so the report can explain *why* a
finding ranks where it does - this module assists the analyst, it does not
declare anything confirmed on its own.
"""

from __future__ import annotations

from wily.risk.scoring import compute_risk_score

# Category-prefix -> impact boost. Matched by ``str.startswith`` so a family
# (e.g. every "secret-exposure-*") is covered by one entry.
_IMPACT_BOOSTS: tuple[tuple[str, float], ...] = (
    ("secret-exposure", 1.5),           # leaked credentials / private keys
    ("cloud-ssrf", 1.5),                # SSRF -> instance metadata
    ("iam-privesc", 1.5),               # privilege escalation paths
    ("s3-bucket-public", 1.0),          # publicly exposed storage
    ("bola", 1.0),                      # cross-tenant object access
    ("takeover", 1.0),                  # dangling resource / subdomain takeover
    ("authz-bypass", 0.5),              # broken authorization
)

# Lift for a finding that clustering saw more than once.
_CORROBORATION_BOOST = 0.5


def _impact_boost(category: str) -> tuple[float, str | None]:
    for prefix, boost in _IMPACT_BOOSTS:
        if category.startswith(prefix):
            return boost, f"high-impact class '{prefix}' (+{boost})"
    return 0.0, None


def _corroboration_boost(evidence: dict) -> tuple[float, str | None]:
    count = 1
    if isinstance(evidence, dict):
        try:
            count = int(evidence.get("duplicate_count", 1))
        except (TypeError, ValueError):
            count = 1
    if count > 1:
        return _CORROBORATION_BOOST, f"corroborated x{count} (+{_CORROBORATION_BOOST})"
    return 0.0, None


def priority_score(finding) -> float:
    """The heuristic priority used to order a finding: base risk + boosts.

    Pure function of the finding; computing it never mutates anything, so it is
    safe to call from a sort key or a test.
    """
    severity = getattr(finding, "severity", "info")
    confidence = getattr(finding, "confidence", 0.0) or 0.0
    base = compute_risk_score(severity, confidence)

    evidence = getattr(finding, "evidence", None) or {}
    category = getattr(finding, "category", "") or ""

    impact, _ = _impact_boost(category)
    corroboration, _ = _corroboration_boost(evidence)
    return round(base + impact + corroboration, 2)


def rank_findings(findings: list) -> list:
    """Return ``findings`` ordered highest-priority first.

    The priority of each finding (base risk + impact + corroboration boosts) is
    recorded on the finding, along with a human-readable ``rank_reasons`` list,
    so the report can explain the ordering. The sort is stable and the tie-break
    is fully deterministic (priority, then base risk, then confidence, then
    asset) so the same input always yields the same report order.
    """
    annotated: list[tuple[float, float, float, str, object]] = []
    for finding in findings:
        severity = getattr(finding, "severity", "info")
        confidence = getattr(finding, "confidence", 0.0) or 0.0
        base = compute_risk_score(severity, confidence)

        evidence = getattr(finding, "evidence", None)
        category = getattr(finding, "category", "") or ""

        impact, impact_reason = _impact_boost(category)
        corroboration, corr_reason = _corroboration_boost(evidence or {})
        priority = round(base + impact + corroboration, 2)

        reasons = [f"base risk {base}"]
        if impact_reason:
            reasons.append(impact_reason)
        if corr_reason:
            reasons.append(corr_reason)

        # Record the ranking rationale on the finding (non-destructively) so the
        # exported report can show why it placed where it did.
        if isinstance(evidence, dict):
            evidence["rank_score"] = priority
            evidence["rank_reasons"] = reasons

        annotated.append(
            (priority, base, float(confidence), str(getattr(finding, "asset", "")), finding)
        )

    annotated.sort(key=lambda t: (t[0], t[1], t[2], t[3]), reverse=True)
    return [t[4] for t in annotated]
