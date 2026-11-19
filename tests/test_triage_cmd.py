"""Tests for `wily triage` (cli/commands/triage_cmd.py): records analyst
--valid/--fp decisions, keyed by row number into a prior JSON report, into
a local JSONL feedback store - and that the decisions are then readable by
risk/ml/feedback.FeedbackStore (the two share the same store format).
"""

import json

from typer.testing import CliRunner

from wily.cli.app import app
from wily.risk.ml.dedup import finding_hash_key
from wily.risk.ml.feedback import VALID, FeedbackStore

runner = CliRunner()


def _write_report(tmp_path, findings):
    path = tmp_path / "report.json"
    path.write_text(
        json.dumps({"findings": findings, "count": len(findings)}), encoding="utf-8"
    )
    return path


_SAMPLE_FINDINGS = [
    {"asset": "https://x/orders/1", "category": "authz-bypass-missing-authorizer", "severity": "critical", "confidence": 0.9, "evidence": {}},
    {"asset": "https://x/orders/2", "category": "cloud-ssrf", "severity": "high", "confidence": 0.7, "evidence": {}},
]


def test_valid_and_fp_recorded(tmp_path):
    report_path = _write_report(tmp_path, _SAMPLE_FINDINGS)
    store_path = tmp_path / "feedback.jsonl"

    result = runner.invoke(
        app,
        ["triage", str(report_path), "--valid", "1", "--fp", "2", "--store", str(store_path)],
    )
    assert result.exit_code == 0, result.output

    decisions = FeedbackStore(store_path).decisions_by_hash()
    assert len(decisions) == 2
    key1 = finding_hash_key(_SAMPLE_FINDINGS[0])
    key2 = finding_hash_key(_SAMPLE_FINDINGS[1])
    assert decisions[key1].verdict == VALID
    assert decisions[key2].verdict == "false_positive"


def test_list_shows_prior_verdicts(tmp_path):
    report_path = _write_report(tmp_path, _SAMPLE_FINDINGS)
    store_path = tmp_path / "feedback.jsonl"
    runner.invoke(app, ["triage", str(report_path), "--valid", "1", "--store", str(store_path)])

    result = runner.invoke(app, ["triage", str(report_path), "--list", "--store", str(store_path)])
    assert result.exit_code == 0, result.output
    assert "valid" in result.output


def test_out_of_range_row_errors(tmp_path):
    report_path = _write_report(tmp_path, _SAMPLE_FINDINGS)
    store_path = tmp_path / "feedback.jsonl"

    result = runner.invoke(
        app, ["triage", str(report_path), "--valid", "99", "--store", str(store_path)]
    )
    assert result.exit_code != 0


def test_nothing_to_record_without_flags(tmp_path):
    report_path = _write_report(tmp_path, _SAMPLE_FINDINGS)
    store_path = tmp_path / "feedback.jsonl"

    result = runner.invoke(app, ["triage", str(report_path), "--store", str(store_path)])
    assert result.exit_code == 0
    assert not store_path.exists()
