"""Parameter Discovery & Classification - phases 2 and 3 of the pipeline:

    1. Endpoint Discovery       -> api_discovery.py (already implemented)
    2. Parameter Discovery      -> discover_parameters() here
    3. Parameter Classification -> classify_url_likely() here
    4. SSRF Assessment          -> scanners/ssrf_imds.py (already implemented)
    5. Result Analysis          -> risk/scoring.py + evidence/sanitize.py (already implemented)

Philosophy: Wily does not automatically test every discovered parameter
as SSRF. It discovers them first (brute-force via the Arjun wordlist),
then classifies the names by how likely they are to be a "fetch a URL"
feature, and only names that pass that filter reach the actual SSRF
Assessment stage.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from wily.core.scope_manager import ScopeManager
from wily.scanners.http_engine import HttpEngine

logger = logging.getLogger("wily.parameter_discovery")

WORDLISTS_DIR = Path(__file__).resolve().parent / "wordlists"

_STRONG_URL_PARAM_NAMES = {
    "url", "uri", "link", "href", "src", "source", "dest", "destination",
    "redirect", "redirect_to", "redirect_uri", "redirect_url", "redirecturl",
    "returnurl", "return_url", "returnto", "return_to",
    "callback", "callback_url", "webhook", "webhook_url",
    "continue", "forward", "goto", "next", "proxy", "fetch",
    "target_url", "file_url", "img_url", "image_url", "load_url",
    "from_url", "checkout_url", "doneurl", "backurl", "out", "feed",
    "avatar_url", "picture_url", "logo_url", "profile_url", "site_url",
}

_URL_SUFFIX_RE = re.compile(r"(_url|url$|_uri|uri$|_link|link$|_href|href$)", re.IGNORECASE)
_URL_KEYWORD_RE = re.compile(
    r"(redirect|callback|webhook|continue|forward|goto|navigate|proxy|fetch)",
    re.IGNORECASE,
)


def classify_url_likely(param_name: str) -> bool:
    """Return True when a parameter's name suggests it takes an external
    URL (a URL/webhook/redirect feature), based on its name alone."""
    name_lower = param_name.strip().lower()
    if name_lower in _STRONG_URL_PARAM_NAMES:
        return True
    if _URL_SUFFIX_RE.search(name_lower):
        return True
    if _URL_KEYWORD_RE.search(name_lower):
        return True
    return False


def load_wordlist(name: str = "arjun_small") -> list[str]:
    path = WORDLISTS_DIR / f"{name}.txt"
    words = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        words.append(line)
    return words


@dataclass
class DiscoveredParameter:
    name: str
    url_likely: bool
    baseline_similarity: float
    status_changed: bool


@dataclass
class ParameterDiscoveryConfig:
    url: str
    method: str = "GET"
    wordlist: str = "arjun_small"
    marker_value: str = "wily-param-probe-1"
    similarity_threshold: float = 0.95
    max_params: int = 2000


@dataclass
class ParameterDiscoveryResult:
    """discover_parameters()'s full result: the discovered parameters plus
    how many probe requests failed outright, so a caller can tell "no
    active parameters" apart from "the target stopped responding partway
    through"."""

    discovered: list[DiscoveredParameter] = field(default_factory=list)
    probe_errors: int = 0
    probes_sent: int = 0

    def __iter__(self):
        # Keeps `for p in result` working for existing call sites that
        # expect an iterable of DiscoveredParameter.
        return iter(self.discovered)

    def __len__(self) -> int:
        return len(self.discovered)


def _build_url(base_url: str, param: str, value: str) -> str:
    """Append ``param=value`` to ``base_url``'s query string.

    Uses urlsplit/urlunsplit rather than naive string concatenation so a
    base URL containing a fragment (``...#section``) still gets the new
    parameter placed in the query string, where the server actually
    receives it - a trailing "?param=value" after a "#..." fragment is
    never sent to the server at all.
    """
    parts = urlsplit(base_url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.append((param, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def discover_parameters(
    config: ParameterDiscoveryConfig,
    scope_manager: ScopeManager,
    http_engine: HttpEngine | None = None,
) -> ParameterDiscoveryResult:
    """Phase 2: Parameter Discovery via differential fuzzing.

    Every probe failure is counted and logged rather than silently
    dropped, so a run that failed on most probes (e.g. the target is
    rate-limiting or unreachable) does not look identical to a clean run
    that genuinely found no active parameters.
    """
    http = http_engine or HttpEngine(scope_manager=scope_manager)
    words = load_wordlist(config.wordlist)[: config.max_params]

    try:
        baseline = http.request(method=config.method, url=config.url, headers={})
    except Exception as exc:
        logger.warning("Parameter discovery baseline request failed for %s: %s", config.url, exc)
        return ParameterDiscoveryResult(discovered=[], probe_errors=len(words), probes_sent=0)

    discovered: list[DiscoveredParameter] = []
    probe_errors = 0
    probes_sent = 0

    for name in words:
        probe_url = _build_url(config.url, name, config.marker_value)
        probes_sent += 1
        try:
            resp = http.request(method=config.method, url=probe_url, headers={})
        except Exception as exc:
            probe_errors += 1
            logger.debug("Parameter probe failed for %r on %s: %s", name, config.url, exc)
            continue

        similarity = http.similarity(baseline.text, resp.text)
        status_changed = resp.status_code != baseline.status_code

        if status_changed or similarity < config.similarity_threshold:
            discovered.append(
                DiscoveredParameter(
                    name=name,
                    url_likely=classify_url_likely(name),
                    baseline_similarity=round(similarity, 3),
                    status_changed=status_changed,
                )
            )

    if probe_errors:
        logger.info(
            "Parameter discovery on %s: %d/%d probes failed",
            config.url, probe_errors, probes_sent,
        )

    return ParameterDiscoveryResult(
        discovered=discovered, probe_errors=probe_errors, probes_sent=probes_sent
    )


def select_ssrf_candidates(result: ParameterDiscoveryResult | list[DiscoveredParameter]) -> list[str]:
    """From the active parameters, return only the names classified as
    url_likely=True."""
    discovered = result.discovered if isinstance(result, ParameterDiscoveryResult) else result
    return [p.name for p in discovered if p.url_likely]
