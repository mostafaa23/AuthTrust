"""Timing-attack account-enumeration scanner."""

from dataclasses import dataclass

import pytest

from wily.scanners.base import ScannerConfirmationError
from wily.scanners.timing_enum import (
    TimingEnumScanner,
    TimingEnumTarget,
    detect_timing_anomaly,
)


# --- pure anomaly detection ---------------------------------------------------


def test_no_anomaly_when_timings_are_close():
    baseline = [100.0, 102.0, 98.0, 101.0, 99.0]
    candidate = [100.0, 103.0, 97.0]
    assert detect_timing_anomaly(baseline, candidate) is None


def test_anomaly_detected_for_significantly_slower_candidate():
    baseline = [100.0, 101.0, 99.0, 100.0, 102.0, 98.0]
    candidate = [250.0, 260.0, 255.0, 248.0, 252.0]
    result = detect_timing_anomaly(baseline, candidate)
    assert result is not None
    assert result["slower_than_baseline"] is True
    assert result["delta_ms"] > 100


def test_anomaly_detected_for_significantly_faster_candidate():
    baseline = [200.0, 202.0, 198.0, 201.0, 199.0, 200.0]
    candidate = [10.0, 12.0, 11.0]
    result = detect_timing_anomaly(baseline, candidate)
    assert result is not None
    assert result["slower_than_baseline"] is False


def test_no_anomaly_with_insufficient_baseline():
    assert detect_timing_anomaly([100.0], [500.0]) is None
    assert detect_timing_anomaly([], [500.0]) is None


def test_no_anomaly_when_delta_below_absolute_floor_even_with_zero_variance():
    # Zero-variance baseline but a tiny (sub-threshold) absolute delta
    # shouldn't trigger just because z-score math would divide by zero.
    baseline = [100.0, 100.0, 100.0, 100.0]
    candidate = [105.0, 106.0]
    assert detect_timing_anomaly(baseline, candidate) is None


def test_anomaly_with_zero_variance_baseline_and_large_delta():
    baseline = [100.0, 100.0, 100.0, 100.0]
    candidate = [400.0, 410.0]
    result = detect_timing_anomaly(baseline, candidate)
    assert result is not None


# --- scanner-level behaviour with a fake HTTP engine -------------------------


@dataclass
class _Resp:
    elapsed_ms: float
    status_code: int = 200
    headers: dict = None
    text: str = ""


class _FakeHttp:
    def __init__(self, timing_fn):
        self._timing_fn = timing_fn
        self.calls = []

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url, body))
        return _Resp(elapsed_ms=self._timing_fn(body))


def _target(**kwargs):
    defaults = dict(
        url="https://victim.example.com/login",
        known_invalid_users=["nobody1", "nobody2", "nobody3"],
        candidate_users=["admin"],
        probes_per_item=5,
    )
    defaults.update(kwargs)
    return TimingEnumTarget(**defaults)


def test_scanner_requires_confirmation():
    http = _FakeHttp(lambda body: 100.0)
    scanner = TimingEnumScanner(http_engine=http, confirm_timing_probe=False)
    with pytest.raises(ScannerConfirmationError):
        scanner.run(_target())
    assert http.calls == []


def test_scanner_flags_slow_candidate_username():
    def timing(body):
        return 300.0 if '"admin"' in body else 100.0

    http = _FakeHttp(timing)
    scanner = TimingEnumScanner(http_engine=http, confirm_timing_probe=True)
    findings = scanner.run(_target())
    assert len(findings) == 1
    assert findings[0].category == "timing-account-enumeration"
    assert findings[0].evidence["candidate_username"] == "admin"
    # 3 baseline users * 5 probes + 1 candidate * 5 probes
    assert len(http.calls) == 20


def test_scanner_no_findings_when_timing_is_uniform():
    http = _FakeHttp(lambda body: 100.0)
    scanner = TimingEnumScanner(http_engine=http, confirm_timing_probe=True)
    findings = scanner.run(_target())
    assert findings == []


def test_scanner_returns_empty_without_baseline_or_candidates():
    http = _FakeHttp(lambda body: 100.0)
    scanner = TimingEnumScanner(http_engine=http, confirm_timing_probe=True)
    findings = scanner.run(_target(known_invalid_users=[]))
    assert findings == []
    findings = scanner.run(_target(candidate_users=[]))
    assert findings == []
