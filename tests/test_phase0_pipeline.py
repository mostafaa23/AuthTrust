"""Phase 0 pipeline wiring tests:
  - apply_deterministic_rules collapses exact duplicates (keeping the
    higher-confidence copy) without dropping distinct findings.
  - export_json redacts secrets by default, keeps them only with
    redact=False, and sorts findings by risk (highest first).
"""

import json

from wily.report.json_report import export_json
from wily.risk.rules_engine import apply_deterministic_rules
from wily.scanners.base import Finding


def _finding(asset, category, confidence, technique=None, evidence=None):
    ev = dict(evidence or {})
    if technique is not None:
        ev["technique"] = technique
    return Finding(
        asset=asset,
        category=category,
        severity="critical",
        confidence=confidence,
        evidence=ev,
        discovery_source="scanner",
    )


def test_dedup_collapses_duplicates_keeping_higher_confidence():
    low = _finding("https://x/a", "authz-bypass-missing-authorizer", 0.5, "missing_authorizer")
    high = _finding("https://x/a", "authz-bypass-missing-authorizer", 0.95, "missing_authorizer")
    out = apply_deterministic_rules([low, high])
    assert len(out) == 1
    assert out[0].confidence == 0.95


def test_dedup_preserves_distinct_findings():
    a = _finding("https://x/a", "cat1", 0.9, "t1")
    b = _finding("https://x/a", "cat1", 0.9, "t2")  # different technique
    c = _finding("https://x/b", "cat1", 0.9, "t1")  # different asset
    out = apply_deterministic_rules([a, b, c])
    assert len(out) == 3


def test_export_redacts_secrets_by_default(tmp_path):
    f = _finding(
        "https://x/a", "cat", 0.9,
        evidence={"snippet": "Authorization: Bearer supersecrettoken12345"},
    )
    path = export_json([f], tmp_path / "r.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    snippet = data["findings"][0]["evidence"]["snippet"]
    assert "supersecrettoken12345" not in snippet
    assert "[REDACTED]" in snippet


def test_export_show_leak_keeps_secret_visible(tmp_path):
    f = _finding(
        "https://x/a", "cat", 0.9,
        evidence={"snippet": "Authorization: Bearer supersecrettoken12345"},
    )
    path = export_json([f], tmp_path / "r.json", redact=False)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "supersecrettoken12345" in data["findings"][0]["evidence"]["snippet"]


def test_export_sorts_by_risk_descending(tmp_path):
    low = Finding(
        asset="https://x/low", category="c", severity="low", confidence=0.4,
        evidence={}, discovery_source="scanner",
    )
    crit = Finding(
        asset="https://x/crit", category="c", severity="critical", confidence=0.9,
        evidence={}, discovery_source="scanner",
    )
    path = export_json([low, crit], tmp_path / "r.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["findings"][0]["asset"] == "https://x/crit"
    assert data["findings"][0]["risk_score"] >= data["findings"][1]["risk_score"]
