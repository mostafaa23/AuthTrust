"""TLS/SSL configuration scanner.

Negotiates a handshake under a handful of fixed protocol-version ceilings
(SSLv3..TLS 1.3), inspects the leaf certificate, and scores the result
against Mozilla's TLS guidelines (ssl-config.mozilla.org): Modern,
Intermediate, or Old. Uses stdlib ``ssl`` + ``cryptography`` rather than
the ``sslyze`` package, to avoid its compiled ``nassl`` dependency.

Safety: read-only (handshake + certificate read, no HTTP body, no write).
Applies the same private/loopback/metadata IP-safety check as
``HttpEngine`` before opening any socket. No confirmation flag required.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import logging
import socket
import ssl
from dataclasses import dataclass
from typing import Callable

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from wily.core.scope_manager import ScopeError, ScopeManager
from wily.scanners.base import BaseScanner, Finding

logger = logging.getLogger("wily.tls_config")

# Protocol versions to probe, oldest first. SSLv2 is not probed: it was
# removed from OpenSSL/Python's ssl module entirely decades ago, so a
# wily host can never even attempt that handshake - there is nothing to
# detect it with, and claiming to check for it would be dishonest.
_PROTOCOL_PROBES: tuple[tuple[str, int], ...] = (
    ("SSLv3", ssl.TLSVersion.SSLv3),
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
)

# Mozilla "Old"/"Intermediate"/"Modern" tiers, simplified to "the oldest
# protocol version a conforming server must refuse to offer" -
# https://ssl-config.mozilla.org/ - the detail each profile also prescribes
# (cipher suites, curve choices, HSTS, ...) is out of scope for a single
# protocol-version probe; this module answers the version question only.
_MODERN_FLOOR = "TLSv1.3"
_INTERMEDIATE_FLOOR = "TLSv1.2"

_WEAK_PROTOCOL_SEVERITY = {
    "SSLv3": "critical",
    "TLSv1.0": "high",
    "TLSv1.1": "medium",
}

# How soon "expiring soon" triggers a (low-severity, heads-up) finding.
_EXPIRY_WARNING_DAYS = 30


@dataclass
class CertificateFacts:
    """What this scanner needs to know about the leaf certificate - kept
    separate from the raw ``cryptography`` object so the scoring logic
    below is a pure function over plain data and is unit-testable without
    ever generating a real certificate."""

    subject_common_name: str | None
    subject_alt_names: tuple[str, ...]
    not_valid_after: _dt.datetime
    is_self_signed: bool


@dataclass
class TlsConfigTarget:
    host: str
    port: int = 443
    # The hostname the certificate is expected to cover - usually the same
    # as ``host``, but kept distinct for the (rare) case of an IP target
    # with a SNI override.
    expected_hostname: str | None = None

    @property
    def hostname(self) -> str:
        return self.expected_hostname or self.host


# A "connector" is injected so tests never open a real socket: given
# (host, port, protocol_version) it returns the negotiated protocol name on
# success, or None if the handshake was rejected/unsupported. The default
# implementation (``_default_protocol_probe``) is the only part of this
# module that actually touches the network.
ProtocolProber = Callable[[str, int, "ssl.TLSVersion"], str | None]
CertificateFetcher = Callable[[str, int], CertificateFacts | None]


def _host_is_safe(hostname: str) -> bool:
    """Mirrors ``HttpEngine``'s IP-safety guard: refuse to connect to a
    hostname that resolves to a private/loopback/link-local/metadata
    address, even if it passed ScopeManager's domain-scope check."""
    try:
        ip = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        try:
            infos = socket.getaddrinfo(hostname, None)
        except (socket.gaierror, UnicodeError, OSError):
            return False
        try:
            return all(
                not _ip_is_blocked(ipaddress.ip_address(info[4][0].split("%")[0]))
                for info in infos
            )
        except ValueError:
            return False
    return not _ip_is_blocked(ip)


def _ip_is_blocked(ip: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _default_protocol_probe(host: str, port: int, version: "ssl.TLSVersion") -> str | None:
    """Attempt a handshake capped at exactly ``version`` (min == max) and
    return the negotiated protocol name, or None if the server refused it
    (handshake failure, protocol mismatch, connection refused/timeout)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except ValueError:
        # This Python/OpenSSL build doesn't support the version at all -
        # that is itself "not offered", not an error worth surfacing.
        return None
    try:
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                return tls_sock.version()
    except (ssl.SSLError, OSError, socket.timeout):
        return None


def _default_certificate_fetch(host: str, port: int) -> CertificateFacts | None:
    """Fetch the leaf certificate using the highest protocol version the
    server will negotiate, and parse it with ``cryptography`` (never
    trusting the chain - ``CERT_NONE`` - since the point here is to read
    and score the certificate's own facts, not to validate it the way a
    browser would)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
    except (ssl.SSLError, OSError, socket.timeout):
        return None
    if not der:
        return None
    return parse_certificate_der(der)


def parse_certificate_der(der: bytes) -> CertificateFacts | None:
    """Pure parsing step, split out from ``_default_certificate_fetch`` so
    tests can hand it a real DER-encoded certificate without a network
    call."""
    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
    except ValueError:
        return None

    cn = None
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn = cn_attrs[0].value if cn_attrs else None
    except Exception:
        cn = None

    sans: tuple[str, ...] = ()
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = tuple(ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        sans = ()

    is_self_signed = cert.issuer == cert.subject

    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=_dt.timezone.utc)

    return CertificateFacts(
        subject_common_name=cn,
        subject_alt_names=sans,
        not_valid_after=not_after,
        is_self_signed=is_self_signed,
    )


def mozilla_tier(supported_protocols: set[str]) -> str:
    """Classify the set of accepted protocol names against Mozilla's
    tiers, keyed on the *oldest* protocol still accepted - any one weak
    protocol accepted drags the whole configuration down to that tier,
    same as a real Mozilla config-generator scan would flag it."""
    if not supported_protocols:
        return "unknown"
    weakest = min(
        supported_protocols,
        key=lambda p: [name for name, _ in _PROTOCOL_PROBES].index(p),
    )
    if weakest in _WEAK_PROTOCOL_SEVERITY:
        return "old"
    if weakest == _INTERMEDIATE_FLOOR:
        return "intermediate"
    if weakest == _MODERN_FLOOR:
        return "modern"
    return "unknown"


def hostname_matches_certificate(hostname: str, cert: CertificateFacts) -> bool:
    """RFC 6125-ish match (exact or a single leading-wildcard label) against
    the certificate's SANs, falling back to the CN only when there are no
    SANs at all (a CN-only cert is itself a separate, older-practice
    finding - see ``evaluate_certificate``)."""
    candidates = cert.subject_alt_names or (
        (cert.subject_common_name,) if cert.subject_common_name else ()
    )
    host = hostname.lower().rstrip(".")
    for candidate in candidates:
        candidate = (candidate or "").lower().rstrip(".")
        if not candidate:
            continue
        if candidate == host:
            return True
        if candidate.startswith("*."):
            suffix = candidate[2:]
            if host.endswith("." + suffix) and host.count(".") == suffix.count(".") + 1:
                return True
    return False


class TlsConfigScanner(BaseScanner):
    name = "tls_config"
    requires_tenant_pair = False
    # A TLS handshake is as safe as a GET request; no owned-infra gate needed.
    requires_owned_infra = False

    def __init__(
        self,
        scope_manager: ScopeManager | None = None,
        protocol_prober: ProtocolProber | None = None,
        certificate_fetcher: CertificateFetcher | None = None,
    ) -> None:
        self.scope = scope_manager
        self._probe = protocol_prober or _default_protocol_probe
        self._fetch_cert = certificate_fetcher or _default_certificate_fetch

    def run(self, target: TlsConfigTarget) -> list[Finding]:
        findings: list[Finding] = []

        if self.scope is not None:
            try:
                self.scope.require_in_scope(target.host)
            except ScopeError as exc:
                logger.info("tls_config: %s out of scope (%s)", target.host, exc)
                return findings

        if not _host_is_safe(target.host):
            logger.warning(
                "tls_config: refusing %s - resolves to a private/loopback/"
                "link-local/metadata address", target.host,
            )
            return findings

        supported: set[str] = set()
        for name, version in _PROTOCOL_PROBES:
            negotiated = self._probe(target.host, target.port, version)
            if negotiated:
                supported.add(name)

        for name in sorted(supported):
            if name in _WEAK_PROTOCOL_SEVERITY:
                findings.append(
                    Finding(
                        asset=f"{target.host}:{target.port}",
                        category="tls-weak-protocol",
                        severity=_WEAK_PROTOCOL_SEVERITY[name],
                        confidence=0.95,
                        discovery_source="scanner",
                        evidence={
                            "protocol": name,
                            "supported_protocols": sorted(supported),
                        },
                        remediation=(
                            f"Disable {name} on this host's TLS configuration. "
                            "Follow Mozilla's Intermediate (or Modern) TLS "
                            "configuration guidelines (ssl-config.mozilla.org): "
                            "require TLS 1.2 or newer."
                        ),
                    )
                )

        if supported:
            tier = mozilla_tier(supported)
            if tier in ("old", "unknown"):
                findings.append(
                    Finding(
                        asset=f"{target.host}:{target.port}",
                        category="tls-mozilla-config-level",
                        severity="medium" if tier == "old" else "low",
                        confidence=0.8,
                        discovery_source="scanner",
                        evidence={
                            "mozilla_tier": tier,
                            "supported_protocols": sorted(supported),
                        },
                        remediation=(
                            "This TLS configuration does not meet Mozilla's "
                            "Intermediate profile. Reconfigure the server to "
                            "accept TLS 1.2+ only and retest against "
                            "ssl-config.mozilla.org."
                        ),
                    )
                )

        cert = self._fetch_cert(target.host, target.port)
        if cert is not None:
            findings.extend(self._evaluate_certificate(target, cert))

        return findings

    def _evaluate_certificate(
        self, target: TlsConfigTarget, cert: CertificateFacts
    ) -> list[Finding]:
        findings: list[Finding] = []
        asset = f"{target.host}:{target.port}"
        now = _dt.datetime.now(_dt.timezone.utc)

        if cert.not_valid_after < now:
            findings.append(
                Finding(
                    asset=asset,
                    category="tls-cert-expired",
                    severity="high",
                    confidence=0.95,
                    discovery_source="scanner",
                    evidence={"not_valid_after": cert.not_valid_after.isoformat()},
                    remediation="Renew the TLS certificate immediately - clients will refuse or warn on every connection.",
                )
            )
        elif (cert.not_valid_after - now).days <= _EXPIRY_WARNING_DAYS:
            findings.append(
                Finding(
                    asset=asset,
                    category="tls-cert-expiring-soon",
                    severity="low",
                    confidence=0.9,
                    discovery_source="scanner",
                    evidence={
                        "not_valid_after": cert.not_valid_after.isoformat(),
                        "days_remaining": (cert.not_valid_after - now).days,
                    },
                    remediation="Renew the TLS certificate before it expires; automate renewal (e.g. ACME/Let's Encrypt) to avoid a repeat.",
                )
            )

        if cert.is_self_signed:
            findings.append(
                Finding(
                    asset=asset,
                    category="tls-cert-self-signed",
                    severity="medium",
                    confidence=0.85,
                    discovery_source="scanner",
                    evidence={"subject_common_name": cert.subject_common_name},
                    remediation="Replace the self-signed certificate with one issued by a trusted CA for any publicly reachable service.",
                )
            )

        if not hostname_matches_certificate(target.hostname, cert):
            findings.append(
                Finding(
                    asset=asset,
                    category="tls-cert-hostname-mismatch",
                    severity="high",
                    confidence=0.85,
                    discovery_source="scanner",
                    evidence={
                        "expected_hostname": target.hostname,
                        "subject_common_name": cert.subject_common_name,
                        "subject_alt_names": list(cert.subject_alt_names),
                    },
                    remediation="Issue a certificate whose SAN list covers this hostname; clients that correctly validate SAN (not CN) will reject every connection.",
                )
            )

        return findings
