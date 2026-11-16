"""Adaptive Rate Limiting - a real implementation (sync, compatible with
HttpEngine).

- Per-host rate limiting: each host has its own minimum interval between
  consecutive requests.
- Adaptive: 429 -> halve the RPS for that host; repeated success ->
  gradually increase it again.
- Thread-safe (a simple lock), in case more than one scanner ever shares
  this limiter concurrently.

TODO (v0.2): a global request budget across all hosts combined, real
max-concurrent if/when this moves to async.
"""

from __future__ import annotations

import threading
import time


class AdaptiveRateLimiter:
    def __init__(
        self,
        initial_rps: float = 10.0,
        min_rps: float = 0.5,
        max_rps: float = 50.0,
        max_retries: int = 3,
    ) -> None:
        self.initial_rps = initial_rps
        self.min_rps = min_rps
        self.max_rps = max_rps
        self.max_retries = max_retries

        self._lock = threading.Lock()
        self._rps_per_host: dict[str, float] = {}
        self._last_request_time: dict[str, float] = {}

    def _rps_for(self, host: str) -> float:
        return self._rps_per_host.setdefault(host, self.initial_rps)

    def wait_for_host(self, host: str) -> None:
        """Sleep if needed, to respect this host's minimum interval."""
        with self._lock:
            rps = self._rps_for(host)
            min_interval = 1.0 / rps if rps > 0 else 0.0
            last = self._last_request_time.get(host, 0.0)
            now = time.monotonic()
            wait_time = min_interval - (now - last)

        if wait_time > 0:
            time.sleep(wait_time)

        with self._lock:
            self._last_request_time[host] = time.monotonic()

    def on_response(self, host: str, status_code: int) -> None:
        """Called after every response - adjusts this host's future RPS."""
        with self._lock:
            rps = self._rps_for(host)
            if status_code == 429:
                self._rps_per_host[host] = max(self.min_rps, rps / 2)
            elif status_code < 400:
                self._rps_per_host[host] = min(self.max_rps, rps * 1.05)

    def backoff_delay(self, attempt: int, retry_after: str | None) -> float:
        """Compute the wait time before retrying a 429: prefers
        Retry-After when present and valid, otherwise exponential backoff
        with jitter."""
        import random

        if retry_after:
            try:
                return max(0.0, float(retry_after))
            except ValueError:
                pass
        base = min(30.0, (2**attempt))
        return base + random.uniform(0, 0.3)
