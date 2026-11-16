"""Tests for the v0.2 authz_bypass additions:
  - authorizer_fail_open (Gap A): route rejects a missing header but accepts
    a malformed credential.
  - soft-200 denial suppression (Gap B/C): a 200 whose body is an auth error
    is not reported as missing_authorizer.
  - authenticated-baseline confidence grounding (Gap B): a public endpoint
    whose unauthenticated body diverges from the authenticated one is flagged
    at reduced confidence, while a confirmed leak is raised.

These inject a scripted fake HTTP engine (the scanner accepts http_engine=),
so no real network or demo server is needed.
"""

import difflib
from dataclasses import dataclass

from wily.scanners.authz_bypass import AuthzBypassScanner, AuthzBypassTarget


@dataclass
class _Resp:
    status_code: int
    text: str = ""


class _FakeHttp:
    """Scripts responses as a function of (method, headers)."""

    def __init__(self, responder):
        self._responder = responder

    def request(self, method, url, headers=None, body=None):
        return self._responder(method, headers or {})

    def similarity(self, a, b):
        return difflib.SequenceMatcher(None, a, b).ratio()


def _scanner(responder):
    # http_engine is injected, so scope_manager is unused here.
    return AuthzBypassScanner(scope_manager=None, http_engine=_FakeHttp(responder))


def test_authorizer_fail_open_detected():
    """No header -> 401, but a garbage token -> 200: authorizer fails open."""

    def responder(method, headers):
        auth = headers.get("Authorization")
        if auth is None:
            return _Resp(401, '{"error":"unauthorized"}')
        return _Resp(200, '{"order_id":123,"customer":"secret-data"}')

    target = AuthzBypassTarget(
        url="https://example.com/orders/fail-open-123",
        include_destructive_methods=False,  # keep it to GET/HEAD
    )
    findings = _scanner(responder).run(target)
    categories = {f.category for f in findings}

    assert "authz-bypass-authorizer-fail-open" in categories
    # "no header" was rejected, so this is NOT a plain missing authorizer.
    assert "authz-bypass-missing-authorizer" not in categories
    fo = next(f for f in findings if f.evidence["technique"] == "authorizer_fail_open")
    assert fo.evidence["no_auth_status"] == 401
    assert fo.evidence["invalid_auth_status"] == 200


def test_soft_200_denial_not_flagged():
    """A 200 whose body is an auth-error message is a soft denial, not a leak."""

    def responder(method, headers):
        return _Resp(200, '{"error":"unauthorized","message":"missing token"}')

    target = AuthzBypassTarget(
        url="https://example.com/api/soft-denied",
        include_destructive_methods=False,
        probe_authorizer_fail_open=False,  # isolate the missing_authorizer path
    )
    findings = _scanner(responder).run(target)
    assert findings == []


def test_missing_authorizer_still_flags_real_leak():
    """A no-auth 200 with real data (no error signature) is still reported."""

    def responder(method, headers):
        return _Resp(200, '{"order_id":123,"customer":"secret-data"}')

    target = AuthzBypassTarget(
        url="https://example.com/orders/123",
        include_destructive_methods=False,
        probe_authorizer_fail_open=False,
    )
    findings = _scanner(responder).run(target)
    cats = {f.category for f in findings}
    assert "authz-bypass-missing-authorizer" in cats


def test_confidence_raised_when_body_matches_authenticated_baseline():
    """Unauth body == authenticated body -> confirmed leak, confidence 0.95."""
    secret = '{"order_id":123,"customer":"secret-data"}'

    def responder(method, headers):
        return _Resp(200, secret)  # same body with or without a valid token

    target = AuthzBypassTarget(
        url="https://example.com/orders/123",
        include_destructive_methods=False,
        probe_authorizer_fail_open=False,
        valid_auth_header_value="Bearer valid-token",
    )
    findings = _scanner(responder).run(target)
    ma = next(f for f in findings if f.evidence["technique"] == "missing_authorizer")
    assert ma.confidence == 0.95
    assert ma.evidence["body_similarity_to_authenticated"] == 1.0
