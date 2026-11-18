"""Subdomain / cloud-resource takeover scanner.

Detects dangling DNS records: a subdomain whose CNAME still points at a
de-provisioned cloud service (S3 website, GitHub Pages, Heroku, ...),
which lets an attacker re-register that resource and serve content from
the victim's subdomain. Correlates the CNAME (against known provider
suffixes) with the HTTP body served at the host (against that provider's
"unclaimed" fingerprint).

Detection only - never registers, claims, or provisions anything. A match
is a takeover indicator for an analyst to confirm and claim defensively.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from wily.core.scope_manager import ScopeManager
from wily.scanners.base import BaseScanner, Finding
from wily.scanners.http_engine import HttpEngine


@dataclass(frozen=True)
class _Service:
    name: str
    cname_suffixes: tuple[str, ...]
    fingerprints: tuple[str, ...]
    # Some services are confirmed by the fingerprint alone even without a known
    # CNAME (e.g. the S3 NoSuchBucket XML is unambiguous); others need the CNAME
    # to avoid flagging an ordinary 404.
    fingerprint_is_sufficient: bool = False


# A pragmatic subset of the community "can-i-take-over-xyz" fingerprint set -
# the high-signal, widely-exploited providers. Each fingerprint is a substring
# searched case-insensitively in the response body.
_SERVICES: tuple[_Service, ...] = (
    _Service(
        name="aws-s3",
        cname_suffixes=("amazonaws.com", "s3-website"),
        fingerprints=("NoSuchBucket", "The specified bucket does not exist"),
        fingerprint_is_sufficient=True,
    ),
    _Service(
        name="github-pages",
        cname_suffixes=("github.io",),
        fingerprints=(
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ),
    ),
    _Service(
        name="heroku",
        cname_suffixes=("herokuapp.com", "herokudns.com"),
        fingerprints=("No such app", "herokucdn.com/error-pages/no-such-app.html"),
    ),
    _Service(
        name="fastly",
        cname_suffixes=("fastly.net",),
        fingerprints=("Fastly error: unknown domain",),
    ),
    _Service(
        name="azure",
        cname_suffixes=(
            "azurewebsites.net",
            "cloudapp.net",
            "trafficmanager.net",
            "blob.core.windows.net",
            "azureedge.net",
        ),
        fingerprints=("404 Web Site not found", "The resource you are looking for has been removed"),
    ),
    _Service(
        name="cloudfront",
        cname_suffixes=("cloudfront.net",),
        fingerprints=("The request could not be satisfied", "ERROR: The request could not be satisfied"),
    ),
    _Service(
        name="shopify",
        cname_suffixes=("myshopify.com",),
        fingerprints=("Sorry, this shop is currently unavailable",),
    ),
    _Service(
        name="bitbucket",
        cname_suffixes=("bitbucket.io",),
        fingerprints=("Repository not found",),
    ),
    _Service(
        name="pantheon",
        cname_suffixes=("pantheonsite.io",),
        fingerprints=("The gods are wise, but do not know of the site which you seek",),
    ),
)


@dataclass
class TakeoverTarget:
    """``host`` is the subdomain under test. ``cname`` is its CNAME target when
    already known (from DNS enumeration / discovery); when omitted and a
    ``resolver`` is supplied to the scanner, it is resolved. ``url`` overrides
    the URL fetched for the body check (defaults to ``https://{host}/``)."""

    host: str
    cname: str | None = None
    url: str | None = None
    schemes: list[str] = field(default_factory=lambda: ["https", "http"])


class TakeoverScanner(BaseScanner):
    name = "takeover"
    requires_tenant_pair = False
    requires_owned_infra = False

    def __init__(
        self,
        scope_manager: ScopeManager | None = None,
        http_engine: HttpEngine | None = None,
        resolver=None,
    ) -> None:
        self.scope = scope_manager
        self.http = http_engine
        # resolver(host) -> cname str | None. Optional; CNAME can also be passed
        # in on the target. Kept injectable so tests never touch real DNS.
        self._resolver = resolver

    def _resolve_cname(self, target: TakeoverTarget) -> str | None:
        if target.cname:
            return target.cname
        if self._resolver is None:
            return None
        try:
            return self._resolver(target.host)
        except Exception:
            return None

    def _fetch_body(self, target: TakeoverTarget) -> str | None:
        if self.http is None:
            return None
        urls = [target.url] if target.url else [
            f"{scheme}://{target.host}/" for scheme in target.schemes
        ]
        for url in urls:
            if self.scope is not None and not self.scope.is_in_scope(url):
                continue
            try:
                resp = self.http.request(method="GET", url=url, headers={})
            except Exception:
                continue
            if resp is not None and resp.text:
                return resp.text
        return None

    @staticmethod
    def _cname_matches(cname: str | None, service: _Service) -> bool:
        if not cname:
            return False
        low = cname.lower()
        return any(suffix in low for suffix in service.cname_suffixes)

    @staticmethod
    def _fingerprint_match(body: str | None, service: _Service) -> str | None:
        if not body:
            return None
        low = body.lower()
        for fp in service.fingerprints:
            if fp.lower() in low:
                return fp
        return None

    def run(self, target: TakeoverTarget) -> list[Finding]:
        findings: list[Finding] = []

        cname = self._resolve_cname(target)
        body = self._fetch_body(target)

        for service in _SERVICES:
            cname_hit = self._cname_matches(cname, service)
            fp_hit = self._fingerprint_match(body, service)

            if not fp_hit:
                continue  # no "unclaimed" fingerprint -> not a takeover indicator
            # A fingerprint alone is enough only for unambiguous services (S3's
            # NoSuchBucket); otherwise require the CNAME to point at the service
            # so an ordinary 404 is not misread as a dangling record.
            if not cname_hit and not service.fingerprint_is_sufficient:
                continue

            confidence = 0.9 if (cname_hit and fp_hit) else 0.7
            findings.append(
                Finding(
                    asset=target.host,
                    category=f"subdomain-takeover-{service.name}",
                    severity="high",
                    confidence=confidence,
                    discovery_source="scanner",
                    evidence={
                        "host": target.host,
                        "service": service.name,
                        "cname": cname,
                        "cname_matched_service": cname_hit,
                        "fingerprint_matched": fp_hit,
                        "note": (
                            "Dangling-resource indicator only - detection and "
                            "fingerprinting. The resource was NOT claimed or "
                            "registered. Confirm and claim it defensively, or "
                            "remove the dangling DNS record."
                        ),
                    },
                    remediation=(
                        "Remove the dangling DNS record pointing at the "
                        "de-provisioned resource, or re-create/claim the resource "
                        "under your own account. Prefer alias records tied to a "
                        "resource you control and audit DNS for pointers to "
                        "services you no longer own."
                    ),
                )
            )
            # One indicator per host is enough; stop at the first match.
            break

        return findings
