"""Token / session-ID randomness scanner, using *min-entropy* rather than
Shannon entropy.

Why min-entropy, not Shannon
----------------------------
Shannon entropy measures the *average* information content of a source -
it is a poor fit for "how guessable is this token" because it rewards a
source that is mostly random but occasionally predictable (the average
looks fine even though an attacker only needs the easy cases). Min-entropy
(as used in NIST SP 800-90B) measures the *worst case*: the probability of
the single most likely outcome, -log2(p_max). That is the right question
for a security token - "how good is an attacker's best guessing
strategy", not "what's the average token like". This mirrors the idea
behind rndSequencer (github.com/KodyMike/rndSequencer).

What this needs, and why it's opt-in
--------------------------------------
A single token tells you almost nothing about the generator behind it -
min-entropy is a property of the *distribution* the tokens are drawn from,
so this scanner needs many samples (``sample_count``, default 30) from the
same endpoint to say anything meaningful. That means sending many repeated
requests to whatever endpoint issues the token (a login, a password-reset
link, a CSRF token, a session cookie) - exactly the kind of repeated,
potentially rate-limit-tripping traffic the project's safety conventions
gate behind an explicit opt-in (see ``s3_bucket.py``'s ``confirm_writes``,
``bola.py``'s ``allow_destructive``). Here that's ``confirm_deep_analysis``
/ the CLI's ``--deep-token-analysis`` flag.

The scoring itself (``analyze_token_samples``) is a pure function over a
plain list of strings, so it is fully unit-testable with no network at
all - the collection step (``TokenEntropyScanner.run``) is the only part
that needs the opt-in and the HttpEngine.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

from wily.scanners.base import BaseScanner, Finding, ScannerConfirmationError
from wily.scanners.http_engine import HttpEngine

# OWASP Session Management Cheat Sheet: session identifiers should provide
# at least 64 bits of unpredictability, and 128 bits is the recommended
# target. These thresholds turn that guidance into severities.
_CRITICAL_BITS = 64
_HIGH_BITS = 96
_MEDIUM_BITS = 128


@dataclass
class TokenEntropyTarget:
    """What to sample, and how to pull one token out of each response.

    Exactly one of ``cookie_name`` or ``body_pattern`` should be set:
    ``cookie_name`` pulls the value out of a ``Set-Cookie`` response
    header, ``body_pattern`` is a regex with one capture group applied to
    the response body (e.g. a JSON ``"csrf_token":"([^"]+)"`` field).
    """

    url: str
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    cookie_name: str | None = None
    body_pattern: str | None = None
    token_label: str = "token"


def shannon_entropy_per_char(sample: str) -> float:
    """Average (Shannon) entropy in bits/char of a single string - kept
    only as a comparison figure in evidence, never used to score."""
    if not sample:
        return 0.0
    counts = Counter(sample)
    n = len(sample)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def min_entropy_per_char(samples: list[str]) -> float:
    """Worst-case bits/char across the whole sample population: the single
    most frequent character, over every character in every sample,
    determines the bound - -log2(p_max). This is deliberately not a
    per-position analysis (fixed-width tokens aside, alignment would be
    meaningless for variable-length tokens), so it answers "how biased is
    the character distribution", a necessary (not sufficient) condition
    for a strong token."""
    all_chars = "".join(samples)
    if not all_chars:
        return 0.0
    counts = Counter(all_chars)
    p_max = max(counts.values()) / len(all_chars)
    return -math.log2(p_max) if p_max > 0 else 0.0


def exact_duplicate_ratio(samples: list[str]) -> tuple[float, str | None]:
    """Fraction of samples that are an exact duplicate of some other
    sample, and one example of a repeated value. Any duplicate at all in a
    modest sample is a strong signal the generator's output space is far
    smaller than it looks (or is outright reused) - a single collision in
    30 samples of a supposedly-128-bit token is already far more likely
    than chance would predict."""
    if len(samples) < 2:
        return 0.0, None
    counts = Counter(samples)
    duplicated = [v for v, c in counts.items() if c > 1]
    if not duplicated:
        return 0.0, None
    duplicate_sample_count = sum(counts[v] for v in duplicated)
    return duplicate_sample_count / len(samples), duplicated[0]


def detect_sequential_pattern(samples: list[str]) -> dict | None:
    """If every sample is a bare (or near-bare) integer and the sorted
    values form a constant- or small-step arithmetic sequence, the
    generator isn't random at all - it's a counter. Mirrors the "sequential
    numeric ID" signal restless (github.com/fevra-dev/Restless) flags for
    BOLA object references; here it's applied to the token itself."""
    numeric = []
    for s in samples:
        stripped = s.strip()
        if not stripped.isdigit():
            return None
        numeric.append(int(stripped))
    if len(numeric) < 3:
        return None
    ordered = sorted(numeric)
    deltas = {b - a for a, b in zip(ordered, ordered[1:])}
    if len(deltas) == 1 and next(iter(deltas)) > 0:
        return {"pattern": "constant-step-sequence", "step": next(iter(deltas))}
    if deltas and max(deltas) <= 3 and min(ordered[1:] if len(ordered) > 1 else ordered) >= 0:
        # Small, bounded steps (not a single constant, but never a big
        # jump either) - still far too narrow a space to be random.
        return {"pattern": "small-bounded-steps", "max_step": max(deltas)}
    return None


def analyze_token_samples(
    samples: list[str], *, token_label: str = "token", min_samples: int = 20
) -> list[dict]:
    """Pure scoring step: samples in, a list of plain-dict issue
    descriptions out (category/severity/confidence/evidence/remediation) -
    the caller (``TokenEntropyScanner.run``) turns these into ``Finding``s
    with the right ``asset``. Kept as plain dicts (not ``Finding``) so this
    function has zero dependency on the scanner/base module and is trivial
    to unit test directly.
    """
    samples = [s for s in samples if s]
    issues: list[dict] = []
    if len(samples) < min_samples:
        return issues

    avg_len = sum(len(s) for s in samples) / len(samples)

    sequential = detect_sequential_pattern(samples)
    if sequential is not None:
        issues.append({
            "category": "token-predictable-sequential",
            "severity": "critical",
            "confidence": 0.9,
            "evidence": {
                "token_label": token_label,
                "sample_count": len(samples),
                **sequential,
                "note": f"every sampled {token_label} is a bare, sequentially-stepping integer.",
            },
            "remediation": (
                f"Generate {token_label}s with a cryptographically secure random "
                "generator (e.g. secrets.token_urlsafe), never a database "
                "auto-increment counter or predictable formula."
            ),
        })

    dup_ratio, dup_example = exact_duplicate_ratio(samples)
    if dup_ratio > 0:
        issues.append({
            "category": "token-collision",
            "severity": "critical",
            "confidence": 0.85,
            "evidence": {
                "token_label": token_label,
                "sample_count": len(samples),
                "duplicate_ratio": round(dup_ratio, 3),
                "example_duplicate_masked": _mask(dup_example) if dup_example else None,
            },
            "remediation": (
                f"Two or more sampled {token_label}s were identical. Re-seed the "
                "random generator per-request and ensure the output space is "
                "large enough that collisions in a small sample are astronomically "
                "unlikely."
            ),
        })

    bits_per_char = min_entropy_per_char(samples)
    total_min_entropy_bits = bits_per_char * avg_len
    shannon_avg = sum(shannon_entropy_per_char(s) for s in samples) / len(samples)

    severity = None
    if total_min_entropy_bits < _CRITICAL_BITS:
        severity = "critical"
    elif total_min_entropy_bits < _HIGH_BITS:
        severity = "high"
    elif total_min_entropy_bits < _MEDIUM_BITS:
        severity = "medium"

    if severity is not None:
        issues.append({
            "category": "token-low-entropy",
            "severity": severity,
            "confidence": 0.75,
            "evidence": {
                "token_label": token_label,
                "sample_count": len(samples),
                "average_length_chars": round(avg_len, 1),
                "min_entropy_bits_per_char": round(bits_per_char, 3),
                "estimated_total_min_entropy_bits": round(total_min_entropy_bits, 1),
                "shannon_entropy_bits_per_char": round(shannon_avg, 3),
                "note": (
                    "min-entropy (worst-case predictability) estimated across "
                    f"{len(samples)} samples, not a single-sample Shannon "
                    "entropy figure."
                ),
            },
            "remediation": (
                f"This {token_label} provides fewer than {_MEDIUM_BITS} bits of "
                "worst-case entropy. Generate it with a CSPRNG and widen the "
                "output space (longer token, full alphabet) until it reaches "
                f"at least {_MEDIUM_BITS} bits (OWASP Session Management Cheat Sheet)."
            ),
        })

    return issues


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "..." + value[-4:]


class TokenEntropyScanner(BaseScanner):
    name = "token_entropy"
    requires_tenant_pair = False
    requires_owned_infra = False

    def __init__(
        self,
        http_engine: HttpEngine | None = None,
        confirm_deep_analysis: bool = False,
        sample_count: int = 30,
        min_samples: int = 20,
    ) -> None:
        self.http = http_engine
        self._confirm = confirm_deep_analysis
        self.sample_count = sample_count
        self.min_samples = min_samples

    def _extract(self, target: TokenEntropyTarget, resp) -> str | None:
        if target.cookie_name:
            raw = (resp.headers or {}).get("Set-Cookie", "")
            match = re.search(
                re.escape(target.cookie_name) + r"=([^;,\s]+)", raw, re.IGNORECASE
            )
            return match.group(1) if match else None
        if target.body_pattern:
            match = re.search(target.body_pattern, resp.text or "")
            return match.group(1) if match else None
        return None

    def _collect(self, target: TokenEntropyTarget) -> list[str]:
        samples: list[str] = []
        for _ in range(self.sample_count):
            try:
                resp = self.http.request(
                    method=target.method, url=target.url, headers=target.headers
                )
            except Exception:
                continue
            token = self._extract(target, resp)
            if token:
                samples.append(token)
        return samples

    def run(self, target: TokenEntropyTarget) -> list[Finding]:
        if not self._confirm:
            raise ScannerConfirmationError(
                "TokenEntropyScanner requires confirm_deep_analysis=True "
                "(--deep-token-analysis): it sends many repeated requests to "
                "collect token samples for a statistically meaningful "
                "min-entropy estimate."
            )
        if self.http is None:
            return []

        samples = self._collect(target)
        issues = analyze_token_samples(
            samples, token_label=target.token_label, min_samples=self.min_samples
        )
        return [
            Finding(
                asset=target.url,
                category=issue["category"],
                severity=issue["severity"],
                confidence=issue["confidence"],
                discovery_source="scanner",
                evidence=issue["evidence"],
                remediation=issue["remediation"],
            )
            for issue in issues
        ]
