"""Timing-attack account-enumeration scanner.

Many login/forgot-password endpoints answer "invalid credentials" either
way but take measurably different time depending on whether the account
actually exists. This builds a timing baseline from known-invalid
usernames, probes each candidate the same number of times (default 5, to
average out network/scheduler noise), and flags a candidate whose mean
response time is a statistically significant outlier against that
baseline. Never attempts a correct password - only latency is measured.

Safety: sends several auth attempts per username to a live endpoint, which
can trip lockouts/WAFs, so it requires ``confirm_timing_probe=True``
(``--confirm-timing-probe``).
"""

from __future__ import annotations

import logging
import statistics
from dataclasses import dataclass, field

from wily.scanners.base import BaseScanner, Finding, ScannerConfirmationError
from wily.scanners.http_engine import HttpEngine

logger = logging.getLogger("wily.timing_enum")

# A candidate's mean must beat the baseline by at least this many standard
# deviations *and* this many absolute milliseconds to be flagged - either
# alone is too easy to trip on a quiet/noisy network (a huge z-score from a
# near-zero stdev baseline, or a large-looking ms gap that's well within
# normal jitter for a slow target).
_Z_SCORE_THRESHOLD = 3.0
_MIN_ABSOLUTE_DELTA_MS = 20.0


@dataclass
class TimingEnumTarget:
    url: str
    method: str = "POST"
    headers: dict = field(default_factory=dict)
    # ``{username}`` in the body is substituted with each probed value.
    body_template: str = '{{"username": "{username}", "password": "wrong-password-x7Q!"}}'
    # Usernames the tester already knows do not exist - the timing baseline.
    known_invalid_users: list[str] = field(default_factory=list)
    # Usernames being tested for an enumeration side-channel.
    candidate_users: list[str] = field(default_factory=list)
    probes_per_item: int = 5


def _mean_stdev(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    mean = statistics.fmean(values)
    stdev = statistics.pstdev(values) if len(values) > 1 else 0.0
    return mean, stdev


def detect_timing_anomaly(
    baseline_samples_ms: list[float], candidate_samples_ms: list[float]
) -> dict | None:
    """Pure comparison: baseline timing samples (every known-invalid user's
    probes, pooled) vs one candidate's probes. Returns an evidence dict
    when the candidate is a statistically significant outlier, else
    ``None``. Having no real network dependency, this is the part unit
    tests exercise directly.
    """
    if len(baseline_samples_ms) < 2 or not candidate_samples_ms:
        return None

    baseline_mean, baseline_stdev = _mean_stdev(baseline_samples_ms)
    candidate_mean = statistics.fmean(candidate_samples_ms)
    delta_ms = candidate_mean - baseline_mean

    if baseline_stdev <= 0:
        # No variance to divide by - fall back to the absolute-delta gate
        # alone, with a conservative floor so a perfectly flat baseline
        # can't trivially trigger on tiny noise.
        z_score = float("inf") if abs(delta_ms) >= _MIN_ABSOLUTE_DELTA_MS else 0.0
    else:
        z_score = delta_ms / baseline_stdev

    if abs(delta_ms) < _MIN_ABSOLUTE_DELTA_MS or abs(z_score) < _Z_SCORE_THRESHOLD:
        return None

    return {
        "baseline_mean_ms": round(baseline_mean, 2),
        "baseline_stdev_ms": round(baseline_stdev, 2),
        "candidate_mean_ms": round(candidate_mean, 2),
        "delta_ms": round(delta_ms, 2),
        "z_score": round(z_score, 2) if z_score != float("inf") else None,
        "slower_than_baseline": delta_ms > 0,
    }


class TimingEnumScanner(BaseScanner):
    name = "timing_enum"
    requires_tenant_pair = False
    requires_owned_infra = False

    def __init__(
        self,
        http_engine: HttpEngine | None = None,
        confirm_timing_probe: bool = False,
    ) -> None:
        self.http = http_engine
        self._confirm = confirm_timing_probe

    def _probe(self, target: TimingEnumTarget, username: str) -> list[float]:
        body = target.body_template.format(username=username)
        elapsed: list[float] = []
        for _ in range(target.probes_per_item):
            try:
                resp = self.http.request(
                    method=target.method, url=target.url, headers=target.headers, body=body
                )
            except Exception as exc:
                logger.debug("timing_enum: probe for %r failed: %s", username, exc)
                continue
            elapsed.append(resp.elapsed_ms)
        return elapsed

    def run(self, target: TimingEnumTarget) -> list[Finding]:
        if not self._confirm:
            raise ScannerConfirmationError(
                "TimingEnumScanner requires confirm_timing_probe=True "
                "(--confirm-timing-probe): it sends several authentication "
                "attempts per username to measure response timing."
            )
        if self.http is None or not target.known_invalid_users or not target.candidate_users:
            return []

        baseline_samples: list[float] = []
        for user in target.known_invalid_users:
            baseline_samples.extend(self._probe(target, user))

        findings: list[Finding] = []
        for candidate in target.candidate_users:
            candidate_samples = self._probe(target, candidate)
            anomaly = detect_timing_anomaly(baseline_samples, candidate_samples)
            if anomaly is None:
                continue
            findings.append(
                Finding(
                    asset=target.url,
                    category="timing-account-enumeration",
                    severity="medium",
                    confidence=0.7,
                    discovery_source="scanner",
                    evidence={
                        "candidate_username": candidate,
                        "baseline_usernames": list(target.known_invalid_users),
                        "probes_per_item": target.probes_per_item,
                        **anomaly,
                        "note": (
                            "Response timing for this username differs "
                            "significantly from known-invalid usernames, "
                            "even though the status/body may be identical - "
                            "this can let an attacker enumerate valid "
                            "accounts without ever seeing a different "
                            "response."
                        ),
                    },
                    remediation=(
                        "Make the authentication code path take the same "
                        "time regardless of whether the account exists "
                        "(e.g. always perform a constant-time password hash "
                        "comparison, or pad short-circuited paths to match), "
                        "and return an identical generic error/response for "
                        "both cases."
                    ),
                )
            )
        return findings
