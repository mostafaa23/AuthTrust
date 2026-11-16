"""Shared base for every scanner module (bola, authz_bypass, ssrf_imds,
iam_privesc, jwt_tamper, ...).

Architectural note: not every scanner is concurrent in the same way. Most
of them (JWT, Authz, SSRF, IAM) are synchronous (requests + the shared
HttpEngine). BOLA alone is async (aiohttp + real concurrency across
multiple identities) - a deliberate decision, not an architectural
mistake; it is documented in bola.py itself. BaseScanner therefore has no
strict abstractmethod on run(), so both styles can subclass it without
breaking either one.

If you need to drive scanners uniformly (e.g. from an orchestrator), use
run_scanner() below - it detects the run() style and dispatches correctly.
Note that the current orchestrator (cli/commands/scan_all.py) calls each
scanner's run() directly rather than through this adapter; keep that in
mind if you add a gating check here and expect it to apply everywhere.
"""

import datetime as _dt
import inspect
from abc import ABC
from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    asset: str
    category: str
    severity: str
    confidence: float
    evidence: dict
    discovery_source: str
    remediation: str | None = None
    scanned_at: str = field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat()
    )
    risk_score: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class ScannerConfirmationError(RuntimeError):
    """Raised when a scanner requires explicit confirmation before running
    a check that is either destructive (can mutate target state) or that
    requires owned infrastructure (requires_owned_infra = True), and that
    confirmation was not given.
    """


class BaseScanner(ABC):
    name: str = "base"
    requires_tenant_pair: bool = False
    requires_owned_infra: bool = False

    def run(self, target) -> list[Finding]:
        raise NotImplementedError(f"{type(self).__name__} must implement run()")


def is_async_scanner(scanner: BaseScanner) -> bool:
    """True when this scanner's run() is an async def."""
    return inspect.iscoroutinefunction(scanner.run)


async def run_scanner(scanner: BaseScanner, target) -> list[Finding]:
    """Uniform adapter that runs run() whether it is sync or async."""
    if is_async_scanner(scanner):
        return await scanner.run(target)
    return scanner.run(target)
