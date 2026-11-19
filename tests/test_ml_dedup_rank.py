"""Phase 4 risk/ml tests (offline, pure):
  - deduplicate() collapses near-identical findings (same asset+category,
    near-identical evidence), keeps the higher-confidence copy, records a
    duplicate_count, and never drops a genuinely distinct finding.
  - rank_findings() orders by base risk + small impact/corroboration boosts,
    records the rationale, and is deterministic.
"""

from wily.risk.ml.dedup import deduplicate
from wily.risk.ml.ranker import priority_score, rank_findings
from wily.scanners.base import Finding


def _finding(asset, category, confidence, severity="high", evidence=None):
    return Finding(
        asset=asset,
        category=category,
        severity=severity,
        confidence=confidence,
        evidence=dict(evidence or {}),
        discovery_source="scanner",
    )


# --- dedup -----------------------------------------------------------------


def test_dedup_merges_near_identical_keeping_higher_confidence():
    a = _finding("https://x/a", "secret-exposure-aws", 0.6,
                 evidence={"snippet": "AWS key AKIA...XYZ found in bundle.js line 10"})
    b = _finding("https://x/a", "secret-exposure-aws", 0.9,
                 evidence={"snippet": "AWS key AKIA...XYZ found in bundle.js line 11"})
    out = deduplicate([a, b])
    assert len(out) == 1
    assert out[0].confidence == 0.9
    assert out[0].evidence["duplicate_count"] == 2


def test_dedup_keeps_distinct_categories_on_same_asset():
    a = _finding("https://x/a", "authz-bypass-missing-authorizer", 0.8,
                 evidence={"snippet": "no auth header required"})
    b = _finding("https://x/a", "cloud-ssrf", 0.8,
                 evidence={"snippet": "fetched 169.254.169.254"})
    out = deduplicate([a, b])
    assert len(out) == 2


def test_dedup_keeps_dissimilar_evidence_same_category():
    a = _finding("https://x/a", "authz-bypass-missing-authorizer", 0.8,
                 evidence={"technique": "missing_authorizer", "detail": "GET returned 200 unauthenticated"})
    b = _finding("https://x/a", "authz-bypass-missing-authorizer", 0.8,
                 evidence={"technique": "method_override", "detail": "X-HTTP-Method-Override bypassed the gateway entirely"})
    out = deduplicate([a, b])
    assert len(out) == 2  # different evidence -> distinct, not merged


def test_dedup_no_duplicate_count_for_singletons():
    a = _finding("https://x/a", "cat", 0.8, evidence={"snippet": "only one"})
    out = deduplicate([a])
    assert "duplicate_count" in out[0].evidence or out[0].evidence == {"snippet": "only one"}
    assert "duplicate_count" not in out[0].evidence


# --- ranker ----------------------------------------------------------------


def test_priority_boosts_high_impact_class():
    base = _finding("https://x/a", "cors-weak", 0.8, severity="high")        # no boost
    impact = _finding("https://x/b", "secret-exposure-aws", 0.8, severity="high")  # +1.5
    assert priority_score(impact) > priority_score(base)


def test_rank_orders_by_priority_and_records_reasons():
    low = _finding("https://x/low", "cors-weak", 0.5, severity="low")
    cred = _finding("https://x/cred", "secret-exposure-aws", 0.9, severity="critical")
    out = rank_findings([low, cred])
    assert out[0].asset == "https://x/cred"
    assert "rank_score" in out[0].evidence
    assert out[0].evidence["rank_score"] >= out[1].evidence["rank_score"]
    assert any("high-impact" in r for r in out[0].evidence["rank_reasons"])


def test_rank_corroboration_breaks_ties():
    solo = _finding("https://x/solo", "authz-bypass-missing-authorizer", 0.8)
    corroborated = _finding(
        "https://x/corr", "authz-bypass-missing-authorizer", 0.8,
        evidence={"duplicate_count": 3},
    )
    out = rank_findings([solo, corroborated])
    # Same base risk + same impact class; corroboration boost places it first.
    assert out[0].asset == "https://x/corr"


def test_rank_is_deterministic():
    findings = [
        _finding("https://x/a", "authz-bypass-missing-authorizer", 0.7),
        _finding("https://x/b", "secret-exposure-aws", 0.7),
        _finding("https://x/c", "cloud-ssrf", 0.7),
    ]
    first = [f.asset for f in rank_findings(list(findings))]
    second = [f.asset for f in rank_findings(list(findings))]
    assert first == second


def test_rank_boost_never_overtakes_severity_gap():
    # A low-severity high-impact-class finding must not outrank a critical one.
    critical = _finding("https://x/crit", "cors-weak", 0.9, severity="critical")  # base 9.0
    low_cred = _finding("https://x/low", "secret-exposure-aws", 0.3, severity="low")  # base 0.9 +1.5
    out = rank_findings([low_cred, critical])
    assert out[0].asset == "https://x/crit"


# --- contextual risk scoring (secret-exposure / bola) -----------------------


def test_secret_exposure_confirmed_credential_outranks_unconfirmed():
    # Same category, severity and confidence; only the evidence differs.
    confirmed = _finding(
        "https://x/aws", "secret-exposure-aws-access-key-id", 0.8, severity="critical",
        evidence={"is_live_cloud_credential": True},
    )
    unconfirmed = _finding(
        "https://x/jwt", "secret-exposure-jwt", 0.8, severity="critical",
        evidence={"is_live_cloud_credential": False},
    )
    assert priority_score(confirmed) > priority_score(unconfirmed)


def test_secret_exposure_boost_present_even_without_evidence_flag():
    # No is_live_cloud_credential key at all (older finding shape) still gets
    # the weaker boost, not zero - it must not regress to "no boost at all".
    base = _finding("https://x/a", "cors-weak", 0.8, severity="high")
    secret = _finding("https://x/b", "secret-exposure-generic-api-key", 0.8, severity="high")
    assert priority_score(secret) > priority_score(base)


def test_bola_boost_scales_with_ownership_grounding():
    observed = _finding(
        "https://x/obs", "bola-cross-tenant", 0.8, severity="high",
        evidence={"grounding": "observed"},
    )
    seeded = _finding(
        "https://x/seed", "bola-cross-tenant", 0.8, severity="high",
        evidence={"grounding": "seeded"},
    )
    unowned = _finding(
        "https://x/unow", "bola-cross-tenant", 0.8, severity="high",
        evidence={"grounding": "unowned"},
    )
    assert priority_score(observed) > priority_score(seeded) > priority_score(unowned)


def test_bola_without_grounding_evidence_defaults_to_weakest_boost():
    unowned = _finding(
        "https://x/unow", "bola-cross-tenant", 0.8, severity="high",
        evidence={"grounding": "unowned"},
    )
    no_grounding = _finding("https://x/none", "bola-cross-tenant", 0.8, severity="high")
    assert priority_score(no_grounding) == priority_score(unowned)


# --- contextual risk scoring (heuristic sensitivity scorer) -----------------


def test_sensitivity_scorer_raises_priority_when_evidence_has_strong_signal():
    plain = _finding(
        "https://x/a", "cors-weak", 0.8, severity="high",
        evidence={"snippet": "nothing interesting here"},
    )
    strong = _finding(
        "https://x/b", "cors-weak", 0.8, severity="high",
        evidence={"snippet": "leaked: AKIAABCDEFGHIJKLMNOP in the response"},
    )
    assert priority_score(strong) > priority_score(plain)


def test_sensitivity_scorer_lowers_priority_for_catalog_shaped_evidence():
    plain = _finding("https://x/a", "cors-weak", 0.8, severity="high")
    catalog = _finding(
        "https://x/b", "cors-weak", 0.8, severity="high",
        evidence={"snippet": (
            '{"sku": "ABC-123", "price": 19.99, "in_stock": true, '
            '"category": "shoes", "title": "Running shoes"}'
        )},
    )
    assert priority_score(catalog) < priority_score(plain)


def test_sensitivity_reason_recorded_when_present():
    f = _finding(
        "https://x/a", "cors-weak", 0.8, severity="high",
        evidence={"snippet": "leaked: AKIAABCDEFGHIJKLMNOP in the response"},
    )
    out = rank_findings([f])
    assert any("aws" in r.lower() for r in out[0].evidence["rank_reasons"])
