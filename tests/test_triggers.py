"""Phase 2: the finding-driven trigger engine (risk/triggers.py)."""

from wily.risk.triggers import FollowUp, TriggerContext, derive_followups
from wily.scanners.base import Finding


def _finding(category, asset="https://x/a", evidence=None):
    return Finding(
        asset=asset,
        category=category,
        severity="critical",
        confidence=0.9,
        evidence=evidence or {},
        discovery_source="scanner",
    )


def test_no_followups_without_context():
    findings = [_finding("authz-bypass-missing-authorizer")]
    assert derive_followups(findings, TriggerContext()) == []


def test_authz_triggers_bola_and_jwt_with_resources():
    findings = [_finding("authz-bypass-missing-authorizer", asset="https://x/orders")]
    ctx = TriggerContext(has_identities=True, has_token=True)
    out = derive_followups(findings, ctx)
    scanners = {fu.scanner for fu in out}
    assert scanners == {"bola", "jwt_tamper"}
    assert all(fu.asset == "https://x/orders" for fu in out)
    assert all(isinstance(fu, FollowUp) and fu.reason for fu in out)


def test_ssrf_triggers_blind_only_with_canary():
    findings = [_finding("cloud-ssrf-imds-v1-direct")]
    assert derive_followups(findings, TriggerContext()) == []
    out = derive_followups(findings, TriggerContext(has_canary=True))
    assert [fu.scanner for fu in out] == ["ssrf_blind"]


def test_leaked_credentials_trigger_iam_when_file_present():
    findings = [
        _finding(
            "cloud-ssrf-imds-v1-direct",
            evidence={"response_snippet": '{"AccessKeyId":"ASIA...","SecretAccessKey":"..."}'},
        )
    ]
    # category contains "imds" -> fires on has_iam_file alone.
    out = derive_followups(findings, TriggerContext(has_iam_file=True))
    assert any(fu.scanner == "iam_privesc" for fu in out)


def test_credential_marker_in_evidence_triggers_iam_even_for_other_category():
    findings = [
        _finding(
            "some-other-finding",
            evidence={"body": 'leaked AccessKeyId=ASIAEXAMPLE'},
        )
    ]
    out = derive_followups(findings, TriggerContext(has_iam_file=True))
    assert [fu.scanner for fu in out] == ["iam_privesc"]


def test_duplicate_scanner_asset_pairs_are_collapsed():
    findings = [
        _finding("authz-bypass-missing-authorizer", asset="https://x/a"),
        _finding("authz-bypass-method-inconsistency", asset="https://x/a"),
    ]
    out = derive_followups(findings, TriggerContext(has_token=True))
    # both findings map to jwt_tamper on the same asset -> one follow-up
    assert [fu.scanner for fu in out] == ["jwt_tamper"]
