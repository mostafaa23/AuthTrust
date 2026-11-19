"""Finding prioritisation / ranking.

Orders findings for the report. Heuristic, not a trained model: starts
from the existing ``risk_score`` (severity x confidence) and adds small
tie-breaking boosts for high-impact classes (credential exposure, public
buckets, SSRF/IMDS, IAM privesc, BOLA, takeover) and for findings
corroborated by duplicate clustering. Boosts are sub-severity, so they
only reorder ties and never let a low-severity finding outrank a critical
one. Recorded per-finding in ``evidence['rank_reasons']``/``rank_score``.

Two impact classes (secret-exposure, bola) don't get a flat boost: their
evidence already carries a signal about how strong the underlying proof is
(a confirmed live credential vs. a generic pattern match; a directly
observed owner vs. a guessed/unowned one), so the boost is scaled by that
context instead of treating every finding in the category the same.
"""

from __future__ import annotations

from wily.risk.ml.sensitivity import score_response
from wily.risk.scoring import compute_risk_score

# Category-prefix -> impact boost. Matched by ``str.startswith`` so a family
# (e.g. every "cloud-ssrf-*") is covered by one entry. secret-exposure and
# bola are handled contextually in ``_impact_boost`` instead of here.
_IMPACT_BOOSTS: tuple[tuple[str, float], ...] = (
    ("cloud-ssrf", 1.5),                # SSRF -> instance metadata
    ("iam-privesc", 1.5),               # privilege escalation paths
    ("s3-bucket-public", 1.0),          # publicly exposed storage
    ("takeover", 1.0),                  # dangling resource / subdomain takeover
    ("authz-bypass", 0.5),              # broken authorization
)

# secret-exposure: full boost only when the evidence confirms a live,
# concretely-shaped credential (e.g. secret_scan's is_live_cloud_credential);
# a generic/weakly-matched secret kind (bearer token, bare "api_key" string,
# unverified JWT) is still worth flagging but on thinner evidence.
_SECRET_CONFIRMED_BOOST = 1.5
_SECRET_UNCONFIRMED_BOOST = 0.8

# bola: how much of the impact boost to apply, scaled by how the candidate's
# ownership was established (bola.py's BolaFinding.grounding). A directly
# observed owner is the strongest evidence a cross-tenant leak really
# happened; a JWT-seeded guess or an unowned candidate is weaker attribution.
_BOLA_GROUNDING_BOOST = {"observed": 1.0, "seeded": 0.6, "unowned": 0.3}
_BOLA_DEFAULT_GROUNDING_BOOST = _BOLA_GROUNDING_BOOST["unowned"]

# Lift for a finding that clustering saw more than once.
_CORROBORATION_BOOST = 0.5


def _impact_boost(category: str, evidence: dict) -> tuple[float, str | None]:
    if category.startswith("secret-exposure"):
        if evidence.get("is_live_cloud_credential"):
            boost = _SECRET_CONFIRMED_BOOST
            return boost, f"high-impact class 'secret-exposure' - confirmed live credential (+{boost})"
        boost = _SECRET_UNCONFIRMED_BOOST
        return boost, f"high-impact class 'secret-exposure' - unconfirmed credential kind (+{boost})"

    if category.startswith("bola"):
        grounding = evidence.get("grounding") or "unowned"
        boost = _BOLA_GROUNDING_BOOST.get(grounding, _BOLA_DEFAULT_GROUNDING_BOOST)
        return boost, f"high-impact class 'bola' - ownership grounding '{grounding}' (+{boost})"

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


# Evidence keys, in preference order, that might hold response text worth
# running the heuristic sensitivity scorer on. Different scanners name their
# captured snippet differently; this tries each until one is a usable string.
_SENSITIVITY_TEXT_KEYS = ("context", "snippet", "body_snippet", "masked_secret")


def _sensitivity_boost(evidence: dict) -> tuple[float, str | None]:
    """risk/ml/sensitivity.py's heuristic adjustment, if the finding's
    evidence happens to carry response text to score. Most findings don't
    (Wily avoids storing raw response bodies - see evidence/sanitize.py), in
    which case this is a no-op, not a penalty."""
    text = None
    for key in _SENSITIVITY_TEXT_KEYS:
        value = evidence.get(key)
        if isinstance(value, str) and value:
            text = value
            break
    if text is None:
        return 0.0, None
    boost, reason = score_response(text)
    if reason is None:
        return 0.0, None
    return boost, f"{boost:+.2f} {reason}"


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

    impact, _ = _impact_boost(category, evidence)
    corroboration, _ = _corroboration_boost(evidence)
    sensitivity, _ = _sensitivity_boost(evidence)
    return round(base + impact + corroboration + sensitivity, 2)


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

        impact, impact_reason = _impact_boost(category, evidence or {})
        corroboration, corr_reason = _corroboration_boost(evidence or {})
        sensitivity, sensitivity_reason = _sensitivity_boost(evidence or {})
        priority = round(base + impact + corroboration + sensitivity, 2)

        reasons = [f"base risk {base}"]
        if impact_reason:
            reasons.append(impact_reason)
        if corr_reason:
            reasons.append(corr_reason)
        if sensitivity_reason:
            reasons.append(sensitivity_reason)

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
