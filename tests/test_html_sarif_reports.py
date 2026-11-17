"""Phase 5 report-writer tests (offline):
  - HTML writer: renders every finding, escapes HTML, redacts evidence by
    default, keeps the ranked (preserve_order) order, honors --show-leak.
  - SARIF writer: valid 2.1.0 structure (runs/results/rules), severity->level
    mapping, deduplicated rules, redaction, location URIs.
"""

import json

import pytest

from wily.report.html_report import export_html
from wily.report.sarif_report import export_sarif
from wily.cli.commands.scan_all import parse_report_formats, _report_path
from wily.scanners.base import Finding
from pathlib import Path


def _finding(asset, category, severity, confidence, evidence=None, remediation=None):
    return Finding(
        asset=asset,
        category=category,
        severity=severity,
        confidence=confidence,
        evidence=dict(evidence or {}),
        discovery_source="scanner",
        remediation=remediation,
    )


# --------------------------------------------------------------------------- HTML


def test_html_renders_all_findings_and_counts(tmp_path):
    findings = [
        _finding("https://x/a", "authz-bypass", "critical", 0.9),
        _finding("https://x/b", "cors-misconfig", "medium", 0.5),
    ]
    path = export_html(findings, tmp_path / "r.html")
    html = path.read_text(encoding="utf-8")
    assert "authz-bypass" in html
    assert "cors-misconfig" in html
    assert "https://x/a" in html
    assert "2 findings" in html


def test_html_escapes_evidence(tmp_path):
    f = _finding(
        "https://x/a", "xss", "high", 0.8,
        evidence={"payload": "<script>alert(1)</script>"},
    )
    path = export_html([f], tmp_path / "r.html")
    html = path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_redacts_by_default(tmp_path):
    f = _finding(
        "https://x/a", "secret", "critical", 0.9,
        evidence={"snippet": "Authorization: Bearer supersecrettoken12345"},
    )
    path = export_html([f], tmp_path / "r.html")
    html = path.read_text(encoding="utf-8")
    assert "supersecrettoken12345" not in html
    assert "[REDACTED]" in html


def test_html_show_leak_keeps_secret(tmp_path):
    f = _finding(
        "https://x/a", "secret", "critical", 0.9,
        evidence={"snippet": "Authorization: Bearer supersecrettoken12345"},
    )
    path = export_html([f], tmp_path / "r.html", redact=False)
    html = path.read_text(encoding="utf-8")
    assert "supersecrettoken12345" in html


def test_html_preserve_order_kept(tmp_path):
    # A low-severity finding first; preserve_order must keep it first.
    low = _finding("https://x/low", "c", "low", 0.4)
    crit = _finding("https://x/crit", "c", "critical", 0.9)
    path = export_html([low, crit], tmp_path / "r.html", preserve_order=True)
    html = path.read_text(encoding="utf-8")
    assert html.index("https://x/low") < html.index("https://x/crit")


def test_html_empty_findings(tmp_path):
    path = export_html([], tmp_path / "r.html")
    html = path.read_text(encoding="utf-8")
    assert "No findings" in html


# --------------------------------------------------------------------------- SARIF


def test_sarif_valid_structure(tmp_path):
    findings = [
        _finding("https://x/a", "authz-bypass", "critical", 0.9),
        _finding("https://x/b", "authz-bypass", "high", 0.7),  # same category
        _finding("s3://bucket", "s3-public", "high", 0.8),
    ]
    path = export_sarif(findings, tmp_path / "r.sarif")
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Wily"
    # 3 results, but only 2 distinct rules (authz-bypass deduped).
    assert len(run["results"]) == 3
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert rule_ids.count("authz-bypass") == 1
    assert set(rule_ids) == {"authz-bypass", "s3-public"}


def test_sarif_level_mapping(tmp_path):
    findings = [
        _finding("u", "a", "critical", 0.9),
        _finding("u", "b", "medium", 0.5),
        _finding("u", "c", "low", 0.3),
    ]
    path = export_sarif(findings, tmp_path / "r.sarif", preserve_order=True)
    results = json.loads(path.read_text(encoding="utf-8"))["runs"][0]["results"]
    levels = [r["level"] for r in results]
    assert levels == ["error", "warning", "note"]


def test_sarif_location_uri(tmp_path):
    f = _finding("api.example.com/x", "c", "high", 0.8)
    path = export_sarif([f], tmp_path / "r.sarif")
    res = json.loads(path.read_text(encoding="utf-8"))["runs"][0]["results"][0]
    uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "wily://api.example.com/x"


def test_sarif_redacts_evidence(tmp_path):
    f = _finding(
        "https://x/a", "secret", "critical", 0.9,
        evidence={"snippet": "Authorization: Bearer supersecrettoken12345"},
    )
    path = export_sarif([f], tmp_path / "r.sarif")
    text = path.read_text(encoding="utf-8")
    assert "supersecrettoken12345" not in text
    assert "[REDACTED]" in text


# --------------------------------------------------------------------- CLI formats


def test_parse_formats_defaults_to_json():
    assert parse_report_formats(None) == ["json"]
    assert parse_report_formats([]) == ["json"]


def test_parse_formats_comma_and_repeatable():
    assert parse_report_formats(["html,sarif"]) == ["json", "html", "sarif"]
    assert parse_report_formats(["html", "json"]) == ["html", "json"]


def test_parse_formats_drops_unknown():
    assert parse_report_formats(["html,bogus"]) == ["json", "html"]


def test_report_path_siblings():
    base = Path("out/wily-report.json")
    assert _report_path(base, "json") == base
    assert _report_path(base, "html") == Path("out/wily-report.html")
    assert _report_path(base, "sarif") == Path("out/wily-report.sarif")
