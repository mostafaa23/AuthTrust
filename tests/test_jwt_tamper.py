import time
from types import SimpleNamespace

import jwt
import pytest

from wily.core.scope_manager import ScopeManager
from wily.scanners.jwt_tamper import (
    JwtTarget,
    JwtTamperScanner,
    analyze_expiry_claims,
)


def _token(payload: dict) -> str:
    return jwt.encode(payload, "test-secret-for-jwt-expiry-tests-32-bytes", algorithm="HS256")


def test_analyze_expiry_claims_without_exp():
    result = analyze_expiry_claims(_token({"sub": "user"}))

    assert result == {
        "has_exp": False,
        "is_expired": None,
        "lifetime_seconds": None,
    }


def test_analyze_expiry_claims_expired_token():
    result = analyze_expiry_claims(_token({"exp": time.time() - 60}))

    assert result["has_exp"] is True
    assert result["is_expired"] is True
    assert result["lifetime_seconds"] < 0


def test_analyze_expiry_claims_future_expiry():
    result = analyze_expiry_claims(_token({"exp": time.time() + 3600}))

    assert result["has_exp"] is True
    assert result["is_expired"] is False
    assert 0 < result["lifetime_seconds"] <= 3600


def test_scanner_stops_if_endpoint_accepts_request_without_auth():
    class StubHttpEngine:
        def __init__(self):
            self.requests = []

        def request(self, **kwargs):
            self.requests.append(kwargs)
            return SimpleNamespace(status_code=200)

    http = StubHttpEngine()
    scanner = JwtTamperScanner(
        scope_manager=ScopeManager("example.test"), http_engine=http
    )

    findings = scanner.run(
        JwtTarget(url="https://example.test", sample_token=_token({"sub": "user"}))
    )

    assert findings == []
    assert len(http.requests) == 2
    assert http.requests[0]["headers"] == {
        "Authorization": f"Bearer {_token({'sub': 'user'})}"
    }
    assert http.requests[1]["headers"] == {}


@pytest.mark.parametrize(
    ("payload", "expected_category"),
    [
        ({"sub": "user"}, "jwt-missing-exp-claim"),
        ({"exp": time.time() - 60}, "jwt-expired-token-accepted"),
        ({"exp": time.time() + 25 * 60 * 60}, "jwt-excessive-token-lifetime"),
    ],
)
def test_scanner_reports_expiry_claim_findings(payload, expected_category):
    class StubHttpEngine:
        def __init__(self):
            self.request_count = 0

        def request(self, **_kwargs):
            self.request_count += 1
            return SimpleNamespace(status_code=200 if self.request_count == 1 else 401)

    scanner = JwtTamperScanner(
        scope_manager=ScopeManager("example.test"),
        http_engine=StubHttpEngine(),
    )
    findings = scanner.run(JwtTarget(url="https://example.test", sample_token=_token(payload)))

    expiry_findings = [
        finding for finding in findings if finding.category == expected_category
    ]
    assert len(expiry_findings) == 1
    assert expiry_findings[0].evidence["technique"] == "expiry_claim_analysis"