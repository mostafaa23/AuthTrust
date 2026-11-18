"""Tests for the differential-baseline (soft-404) addition to
AuthzBypassScanner's missing_authorizer technique:

  - a would-be leak whose body is near-identical to a probed, known-missing
    resource is suppressed (it's a generic catch-all page, not a real leak).
  - a real leak (body is NOT similar to the soft-404 baseline) is still
    reported, and carries the similarity score in its evidence for auditing.
  - the baseline is opt-in: a target without soft_404_probe_url behaves
    exactly as before (see test_authz_fail_open.py).

Injects a scripted fake HTTP engine keyed by URL, so no real network or demo
server is needed.
"""

import difflib
from dataclasses import dataclass

from wily.scanners.authz_bypass import AuthzBypassScanner, AuthzBypassTarget


@dataclass
class _Resp:
    status_code: int
    text: str = ""


class _FakeHttp:
    """Scripts responses as a function of (method, url, headers)."""

    def __init__(self, responder):
        self._responder = responder

    def request(self, method, url, headers=None, body=None):
        return self._responder(method, url, headers or {})

    def similarity(self, a, b):
        return difflib.SequenceMatcher(None, a, b).ratio()


def _scanner(responder):
    return AuthzBypassScanner(scope_manager=None, http_engine=_FakeHttp(responder))


_GENERIC_CATCH_ALL = '{"status":"not found","message":"we could not find what you were looking for"}'


def test_soft_404_lookalike_leak_is_suppressed():
    """Body matches the known-missing-resource baseline almost exactly -
    a generic catch-all page, not a real leak of this resource's data."""

    def responder(method, url, headers):
        if url == "https://example.com/orders/does-not-exist-probe":
            return _Resp(200, _GENERIC_CATCH_ALL)
        return _Resp(200, _GENERIC_CATCH_ALL)  # the "leak" is the same generic page

    target = AuthzBypassTarget(
        url="https://example.com/orders/123",
        include_destructive_methods=False,
        probe_authorizer_fail_open=False,
        soft_404_probe_url="https://example.com/orders/does-not-exist-probe",
    )
    findings = _scanner(responder).run(target)
    assert findings == []


def test_real_leak_still_flagged_and_similarity_recorded():
    """Body is genuinely different from the soft-404 baseline - a real leak,
    still reported, with the comparison score kept for auditing."""

    def responder(method, url, headers):
        if url == "https://example.com/orders/does-not-exist-probe":
            return _Resp(200, _GENERIC_CATCH_ALL)
        return _Resp(200, '{"order_id":123,"customer":"secret-data","card":"4111..."}')

    target = AuthzBypassTarget(
        url="https://example.com/orders/123",
        include_destructive_methods=False,
        probe_authorizer_fail_open=False,
        soft_404_probe_url="https://example.com/orders/does-not-exist-probe",
    )
    findings = _scanner(responder).run(target)
    cats = {f.category for f in findings}
    assert "authz-bypass-missing-authorizer" in cats
    ma = next(f for f in findings if f.evidence["technique"] == "missing_authorizer")
    assert ma.evidence["body_similarity_to_soft_404_baseline"] is not None
    assert ma.evidence["body_similarity_to_soft_404_baseline"] < 0.85


def test_soft_404_probe_disabled_by_default_behaves_as_before():
    """No soft_404_probe_url configured -> no probe request is made, and a
    real leak is reported exactly like the pre-existing behaviour."""

    calls = []

    def responder(method, url, headers):
        calls.append(url)
        return _Resp(200, '{"order_id":123,"customer":"secret-data"}')

    target = AuthzBypassTarget(
        url="https://example.com/orders/123",
        include_destructive_methods=False,
        probe_authorizer_fail_open=False,
    )
    findings = _scanner(responder).run(target)
    assert {f.category for f in findings} == {"authz-bypass-missing-authorizer"}
    assert all(url == "https://example.com/orders/123" for url in calls)  # no extra probe request
    ma = findings[0]
    assert ma.evidence["body_similarity_to_soft_404_baseline"] is None


def test_soft_404_probe_fetch_failure_does_not_break_the_scan():
    """If the probe request itself fails, the scanner falls back to the
    pre-existing behaviour instead of erroring out."""

    def responder(method, url, headers):
        if url == "https://example.com/orders/does-not-exist-probe":
            raise ConnectionError("boom")
        return _Resp(200, '{"order_id":123,"customer":"secret-data"}')

    target = AuthzBypassTarget(
        url="https://example.com/orders/123",
        include_destructive_methods=False,
        probe_authorizer_fail_open=False,
        soft_404_probe_url="https://example.com/orders/does-not-exist-probe",
    )
    findings = _scanner(responder).run(target)
    assert {f.category for f in findings} == {"authz-bypass-missing-authorizer"}
