"""API-keys / secrets exposure scanner.

Frontend bundles, HTTP response bodies and already-captured traffic routinely
leak long-lived credentials - a hardcoded AWS access key in a minified JS
bundle, a bearer token in a HAR export, a PEM private key echoed in an error
page. This scanner searches *text the scan already has* for those secrets.

Detection only, never use
-------------------------
The scanner matches secret *shapes* (see ``evidence/sanitize.detect_secrets``)
and reports them. It never authenticates to any third-party service with a
found key - a live-looking AWS key is reported, not exercised. The report keeps
only a short masked indicator of each secret (``mask_secret``), never the raw
value, so the finding is actionable without re-leaking the credential.

Input shape
-----------
The scanner is pure/offline over whatever text it is handed:
  * ``sources``    - pre-fetched text blobs (imported Burp/HAR traffic, response
                     bodies the orchestrator already read, observed tokens).
  * ``fetch_urls`` - in-scope URLs (typically discovered ``*.js`` bundles) whose
                     body the scanner fetches through the shared HttpEngine and
                     then scans. Out-of-scope / unreachable URLs are skipped.
So unit tests can drive it entirely through ``sources`` with no network, exactly
like the other scanners' fake-HTTP tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from wily.core.scope_manager import ScopeManager
from wily.evidence.sanitize import (
    AWS_CREDENTIAL_KINDS,
    SecretMatch,
    detect_secrets,
    sanitize_text,
)
from wily.scanners.base import BaseScanner, Finding
from wily.scanners.http_engine import HttpEngine

# How much context around a match is kept (after redaction) for the analyst to
# locate the secret in the source, without dumping the whole file.
_CONTEXT_WINDOW = 48

# Per-kind risk. A live cloud credential outranks a generic app key.
_KIND_SEVERITY: dict[str, str] = {
    "aws_access_key_id": "critical",
    "aws_secret_access_key": "critical",
    "aws_session_token": "critical",
    "private_key": "critical",
    "github_token": "high",
    "slack_token": "high",
    "google_api_key": "high",
    "jwt": "medium",
    "bearer_token": "medium",
    "generic_api_key": "medium",
}
_KIND_CONFIDENCE: dict[str, float] = {
    "aws_access_key_id": 0.9,
    "aws_secret_access_key": 0.85,
    "aws_session_token": 0.85,
    "private_key": 0.95,
    "github_token": 0.9,
    "slack_token": 0.9,
    "google_api_key": 0.85,
    "jwt": 0.5,
    "bearer_token": 0.5,
    "generic_api_key": 0.45,
}


@dataclass
class SecretSource:
    """One named text blob to scan. ``location`` is where it came from (a URL,
    a file name, "imported-traffic") - recorded in evidence so a finding points
    the analyst back at the source."""

    label: str
    content: str
    location: str = ""


@dataclass
class SecretScanTarget:
    sources: list[SecretSource] = field(default_factory=list)
    # In-scope URLs whose body should be fetched and scanned (e.g. JS bundles).
    fetch_urls: list[str] = field(default_factory=list)


class SecretScanScanner(BaseScanner):
    name = "secret_scan"
    requires_tenant_pair = False
    # Reading already-available text / fetching an in-scope JS file is passive.
    requires_owned_infra = False

    def __init__(
        self,
        scope_manager: ScopeManager | None = None,
        http_engine: HttpEngine | None = None,
    ) -> None:
        self.scope = scope_manager
        # http_engine is only needed when fetch_urls is used; scanning provided
        # sources works with neither (offline).
        self.http = http_engine

    def _context(self, text: str, match: SecretMatch) -> str:
        start = max(0, match.start - _CONTEXT_WINDOW)
        end = min(len(text), match.end + _CONTEXT_WINDOW)
        snippet = text[start:end]
        # Redact the secret (and anything else sensitive) out of the context so
        # the surrounding snippet is safe to store even before json_report's
        # own redaction pass.
        return sanitize_text(snippet).replace("\n", " ").strip()

    def _fetch(self, url: str) -> SecretSource | None:
        """Fetch one in-scope URL's body as a source. Returns None when there
        is no engine, the URL is out of scope, or the request fails."""
        if self.http is None:
            return None
        if self.scope is not None and not self.scope.is_in_scope(url):
            return None
        try:
            resp = self.http.request(method="GET", url=url, headers={})
        except Exception:
            return None
        return SecretSource(label=url, content=resp.text or "", location=url)

    def run(self, target: SecretScanTarget) -> list[Finding]:
        sources: list[SecretSource] = list(target.sources)
        for url in target.fetch_urls:
            fetched = self._fetch(url)
            if fetched is not None:
                sources.append(fetched)

        findings: list[Finding] = []
        # Dedup identical secrets seen across many sources (a key hardcoded in
        # several bundles is one problem), keyed on (kind, masked).
        seen: set[tuple[str, str]] = set()

        for source in sources:
            text = source.content or ""
            for match in detect_secrets(text):
                key = (match.kind, match.masked)
                if key in seen:
                    continue
                seen.add(key)

                is_aws = match.kind in AWS_CREDENTIAL_KINDS
                findings.append(
                    Finding(
                        asset=source.location or source.label,
                        category=f"secret-exposure-{match.kind.replace('_', '-')}",
                        severity=_KIND_SEVERITY.get(match.kind, "medium"),
                        confidence=_KIND_CONFIDENCE.get(match.kind, 0.5),
                        discovery_source="scanner",
                        evidence={
                            "secret_kind": match.kind,
                            "masked_secret": match.masked,
                            "source_label": source.label,
                            "source_location": source.location,
                            "is_live_cloud_credential": is_aws,
                            "context": self._context(text, match),
                            "note": (
                                "Detection only - the credential was NOT used to "
                                "authenticate to any service. Treat it as "
                                "compromised and rotate it."
                            ),
                        },
                        remediation=(
                            "Remove the secret from the shipped code/response and "
                            "rotate it immediately (assume it is compromised). "
                            "Load secrets at runtime from a secrets manager "
                            "(AWS Secrets Manager / SSM Parameter Store), never "
                            "bake them into frontend bundles or API responses, "
                            "and add a pre-commit/CI secret scanner to catch "
                            "regressions."
                        ),
                    )
                )

        return findings
