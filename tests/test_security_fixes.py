"""Regression tests for the Phase 3 hardening fixes:
  - AWS secrets are actually redacted from evidence before export.
  - Destructive-method authz probes and the SSRF/IMDS check run by
    default (offensive-by-default), with an explicit opt-out still
    available for callers that pass it.
  - Parameter discovery builds a safe URL even when the base URL has a
    fragment.
"""

from wily.core.scope_manager import ScopeManager
from wily.evidence.sanitize import sanitize_evidence_dict
from wily.recon.parameter_discovery import _build_url
from wily.scanners.authz_bypass import AuthzBypassScanner, AuthzBypassTarget
from wily.scanners.ssrf_imds import SsrfImdsScanner, SsrfImdsTarget


def test_sanitize_redacts_aws_credentials():
    fake_cred_body = (
        '{"Code":"Success","AccessKeyId":"ASIAFAKEEXAMPLEKEY12",'
        '"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY",'
        '"Token":"IQoJb3JpZ2luX2VjFAKEverylongbase64liketokenvalue1234567890",'
        '"Expiration":"2024-01-01T06:00:00Z"}'
    )
    evidence = {"response_snippet": fake_cred_body}
    sanitized = sanitize_evidence_dict(evidence)

    assert "wJalrXUtnFEMI" not in sanitized["response_snippet"]
    assert "ASIAFAKEEXAMPLEKEY12" not in sanitized["response_snippet"]
    assert "[REDACTED]" in sanitized["response_snippet"]


def test_sanitize_keeps_forged_token_visible():
    """forged_token is the evidence of a vulnerability, not a secret to
    hide - it must survive sanitization untouched."""
    evidence = {"forged_token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."}
    sanitized = sanitize_evidence_dict(evidence)
    assert sanitized["forged_token"] == evidence["forged_token"]


def test_authz_bypass_probes_destructive_methods_by_default():
    """Offensive by default: a destructive target resolves to include the
    write methods without any explicit confirmation, and never raises."""
    scope = ScopeManager("example.com")
    scanner = AuthzBypassScanner(scope_manager=scope)  # confirm_destructive defaults to True
    assert scanner._confirm_destructive is True

    target = AuthzBypassTarget(url="https://example.com/orders/1")
    # include_destructive_methods now defaults to True.
    assert target.include_destructive_methods is True

    methods = scanner._resolve_methods(target)
    assert {"POST", "PUT", "DELETE", "PATCH"}.issubset(set(methods))


def test_authz_bypass_can_opt_out_of_destructive_methods():
    """The safe read-only mode is still reachable explicitly."""
    scope = ScopeManager("example.com")
    scanner = AuthzBypassScanner(scope_manager=scope, confirm_destructive=False)
    target = AuthzBypassTarget(
        url="https://example.com/orders/1", include_destructive_methods=False
    )
    methods = scanner._resolve_methods(target)
    assert set(methods) == {"GET", "HEAD"}


def test_authz_bypass_always_excludes_options():
    """OPTIONS stays excluded (CORS-preflight false positives) even in the
    default offensive configuration."""
    scope = ScopeManager("example.com")
    scanner = AuthzBypassScanner(scope_manager=scope)
    methods = scanner._resolve_methods(AuthzBypassTarget(url="https://example.com/orders/1"))
    assert "OPTIONS" not in methods


def test_ssrf_imds_runs_by_default_without_confirmation():
    """Offensive by default: the SSRF/IMDS check no longer requires an
    explicit owned-infra confirmation and runs without raising."""
    scope = ScopeManager("example.com")
    scanner = SsrfImdsScanner(scope_manager=scope)  # confirm_owned_infra defaults to True
    assert scanner._confirm_owned_infra is True

    # A stub HTTP engine keeps this a pure unit test (no real network): the
    # point is only that run() completes instead of raising a confirmation
    # error.
    class _StubResp:
        text = ""

    class _StubEngine:
        def request(self, *args, **kwargs):
            return _StubResp()

    scanner.http = _StubEngine()
    target = SsrfImdsTarget(url="https://example.com/fetch", param_name="url")
    assert scanner.run(target) == []


def test_parameter_discovery_build_url_ignores_fragment():
    url = _build_url("https://example.test/api#section", "probe", "value")
    assert "#" not in url
    assert "probe=value" in url
    assert url.startswith("https://example.test/api?")


def test_parameter_discovery_build_url_appends_to_existing_query():
    url = _build_url("https://example.test/api?a=1", "probe", "value")
    assert "a=1" in url
    assert "probe=value" in url
