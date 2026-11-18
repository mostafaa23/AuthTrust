"""Min-entropy token/session-ID randomness scanner."""

import secrets
import string
from dataclasses import dataclass

import pytest

from wily.scanners.base import ScannerConfirmationError
from wily.scanners.token_entropy import (
    TokenEntropyScanner,
    TokenEntropyTarget,
    analyze_token_samples,
    detect_sequential_pattern,
    exact_duplicate_ratio,
    min_entropy_per_char,
    shannon_entropy_per_char,
)


# --- pure helpers ------------------------------------------------------------


def test_min_entropy_zero_for_constant_character():
    assert min_entropy_per_char(["aaaa", "aaaa", "aaaa"]) == 0.0


def test_min_entropy_high_for_strong_random_tokens():
    alphabet = string.ascii_letters + string.digits
    samples = ["".join(secrets.choice(alphabet) for _ in range(32)) for _ in range(40)]
    bits = min_entropy_per_char(samples)
    # ~6 bits/char ceiling for a 62-symbol alphabet; a strong generator
    # should land close to it, nowhere near a biased source.
    assert bits > 4.5


def test_shannon_entropy_of_empty_string_is_zero():
    assert shannon_entropy_per_char("") == 0.0


def test_exact_duplicate_ratio_detects_collision():
    samples = ["abc123", "def456", "abc123", "ghi789"]
    ratio, example = exact_duplicate_ratio(samples)
    assert ratio == pytest.approx(0.5)
    assert example == "abc123"


def test_exact_duplicate_ratio_zero_when_all_unique():
    ratio, example = exact_duplicate_ratio(["a", "b", "c"])
    assert ratio == 0.0
    assert example is None


def test_detect_sequential_pattern_constant_step():
    samples = [str(n) for n in range(1000, 1010)]
    pattern = detect_sequential_pattern(samples)
    assert pattern is not None
    assert pattern["pattern"] == "constant-step-sequence"
    assert pattern["step"] == 1


def test_detect_sequential_pattern_none_for_random_strings():
    alphabet = string.ascii_letters + string.digits
    samples = ["".join(secrets.choice(alphabet) for _ in range(16)) for _ in range(10)]
    assert detect_sequential_pattern(samples) is None


# --- analyze_token_samples (pure scoring) ------------------------------------


def test_analyze_flags_low_entropy_short_numeric_tokens():
    samples = [str(secrets.randbelow(100)).zfill(2) for _ in range(30)]
    issues = analyze_token_samples(samples, min_samples=20)
    cats = {i["category"] for i in issues}
    assert "token-low-entropy" in cats


def test_analyze_flags_sequential_tokens_as_critical():
    samples = [str(n) for n in range(5000, 5030)]
    issues = analyze_token_samples(samples, min_samples=20)
    seq = [i for i in issues if i["category"] == "token-predictable-sequential"]
    assert seq and seq[0]["severity"] == "critical"


def test_analyze_flags_duplicate_tokens():
    samples = ["sametoken1234567890abcdef"] * 2 + [
        "".join(secrets.choice(string.ascii_letters) for _ in range(24)) for _ in range(28)
    ]
    issues = analyze_token_samples(samples, min_samples=20)
    assert any(i["category"] == "token-collision" for i in issues)


def test_analyze_strong_token_yields_no_findings():
    alphabet = string.ascii_letters + string.digits
    samples = ["".join(secrets.choice(alphabet) for _ in range(40)) for _ in range(40)]
    issues = analyze_token_samples(samples, min_samples=20)
    assert issues == []


def test_analyze_skips_when_too_few_samples():
    issues = analyze_token_samples(["a", "b"], min_samples=20)
    assert issues == []


# --- scanner-level behaviour with a fake HTTP engine -------------------------


@dataclass
class _Resp:
    headers: dict
    text: str = ""


class _FakeHttp:
    def __init__(self, token_source):
        self._token_source = token_source
        self.calls = 0

    def request(self, method, url, headers=None, body=None):
        self.calls += 1
        token = self._token_source()
        return _Resp(headers={"Set-Cookie": f"session_id={token}; Path=/; HttpOnly"})


def test_scanner_requires_confirmation():
    http = _FakeHttp(lambda: "x")
    scanner = TokenEntropyScanner(http_engine=http, confirm_deep_analysis=False)
    with pytest.raises(ScannerConfirmationError):
        scanner.run(TokenEntropyTarget(url="https://victim.example.com/login", cookie_name="session_id"))
    assert http.calls == 0


def test_scanner_collects_cookie_and_flags_sequential_session_ids():
    counter = iter(range(1000, 1100))
    http = _FakeHttp(lambda: str(next(counter)))
    scanner = TokenEntropyScanner(http_engine=http, confirm_deep_analysis=True, sample_count=30, min_samples=20)
    findings = scanner.run(
        TokenEntropyTarget(url="https://victim.example.com/login", cookie_name="session_id")
    )
    cats = {f.category for f in findings}
    assert "token-predictable-sequential" in cats
    assert http.calls == 30


def test_scanner_strong_cookie_yields_no_findings():
    alphabet = string.ascii_letters + string.digits
    http = _FakeHttp(lambda: "".join(secrets.choice(alphabet) for _ in range(40)))
    scanner = TokenEntropyScanner(http_engine=http, confirm_deep_analysis=True, sample_count=30, min_samples=20)
    findings = scanner.run(
        TokenEntropyTarget(url="https://victim.example.com/login", cookie_name="session_id")
    )
    assert findings == []
