"""TLS/SSL configuration scanner.

Protocol probing and certificate fetching are both injected (``protocol_prober``
/ ``certificate_fetcher``), so these tests never open a real socket - the same
fake-I/O pattern the other scanners' tests use.
"""

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from wily.scanners.tls_config import (
    CertificateFacts,
    TlsConfigScanner,
    TlsConfigTarget,
    hostname_matches_certificate,
    mozilla_tier,
    parse_certificate_der,
)


def _build_cert(
    common_name: str = "victim.example.com",
    sans: list[str] | None = None,
    not_valid_after: dt.datetime | None = None,
    self_signed: bool = True,
) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = subject if self_signed else x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Some Trusted CA")]
    )
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(not_valid_after or (now + dt.timedelta(days=90)))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    cert = builder.sign(key, hashes.SHA256(), default_backend())
    from cryptography.hazmat.primitives.serialization import Encoding

    return cert.public_bytes(Encoding.DER)


# --- pure scoring helpers ---------------------------------------------------


def test_mozilla_tier_classification():
    assert mozilla_tier({"TLSv1.3"}) == "modern"
    assert mozilla_tier({"TLSv1.2", "TLSv1.3"}) == "intermediate"
    assert mozilla_tier({"TLSv1.0", "TLSv1.2"}) == "old"
    assert mozilla_tier({"SSLv3"}) == "old"
    assert mozilla_tier(set()) == "unknown"


def test_hostname_matches_certificate_exact_and_wildcard():
    cert = CertificateFacts(
        subject_common_name="victim.example.com",
        subject_alt_names=("*.example.com",),
        not_valid_after=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30),
        is_self_signed=False,
    )
    assert hostname_matches_certificate("api.example.com", cert)
    assert not hostname_matches_certificate("api.sub.example.com", cert)
    assert not hostname_matches_certificate("evil.com", cert)


def test_parse_certificate_der_roundtrip():
    der = _build_cert(common_name="victim.example.com", sans=["victim.example.com", "www.victim.example.com"])
    facts = parse_certificate_der(der)
    assert facts is not None
    assert facts.subject_common_name == "victim.example.com"
    assert "www.victim.example.com" in facts.subject_alt_names
    assert facts.is_self_signed


def test_parse_certificate_der_rejects_garbage():
    assert parse_certificate_der(b"not a certificate") is None


# --- scanner-level behaviour, with injected network --------------------------


def _scanner(probe_results: dict[str, str | None] = None, cert=None):
    probe_results = probe_results or {}

    def prober(host, port, version):
        name = version.name.replace("_", ".")
        return probe_results.get(name)

    def fetcher(host, port):
        return cert

    return TlsConfigScanner(protocol_prober=prober, certificate_fetcher=fetcher)


def test_weak_protocol_flagged():
    scanner = _scanner(probe_results={"TLSv1": "TLSv1.0", "TLSv1.2": "TLSv1.2"})
    findings = scanner.run(TlsConfigTarget(host="8.8.8.8"))
    cats = {f.category for f in findings}
    assert "tls-weak-protocol" in cats
    weak = [f for f in findings if f.category == "tls-weak-protocol"][0]
    assert weak.severity == "high"


def test_modern_only_host_yields_no_protocol_finding():
    scanner = _scanner(probe_results={"TLSv1.3": "TLSv1.3"})
    findings = scanner.run(TlsConfigTarget(host="8.8.8.8"))
    assert not any(f.category in ("tls-weak-protocol", "tls-mozilla-config-level") for f in findings)


def test_expired_certificate_flagged():
    expired = CertificateFacts(
        subject_common_name="victim.example.com",
        subject_alt_names=("victim.example.com",),
        not_valid_after=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1),
        is_self_signed=False,
    )
    scanner = _scanner(probe_results={"TLSv1.3": "TLSv1.3"}, cert=expired)
    findings = scanner.run(TlsConfigTarget(host="8.8.8.8"))
    assert any(f.category == "tls-cert-expired" for f in findings)


def test_self_signed_and_hostname_mismatch_flagged():
    bad_cert = CertificateFacts(
        subject_common_name="someone-else.com",
        subject_alt_names=("someone-else.com",),
        not_valid_after=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=90),
        is_self_signed=True,
    )
    scanner = _scanner(probe_results={"TLSv1.3": "TLSv1.3"}, cert=bad_cert)
    findings = scanner.run(TlsConfigTarget(host="8.8.8.8"))
    cats = {f.category for f in findings}
    assert "tls-cert-self-signed" in cats
    assert "tls-cert-hostname-mismatch" in cats


def test_no_scanner_crashes_when_nothing_negotiates():
    scanner = _scanner(probe_results={}, cert=None)
    findings = scanner.run(TlsConfigTarget(host="victim.example.com"))
    assert findings == []


def test_out_of_scope_host_is_refused():
    from wily.core.scope_manager import ScopeManager

    scope = ScopeManager("victim.example.com")
    scanner = TlsConfigScanner(
        scope_manager=scope,
        protocol_prober=lambda h, p, v: "TLSv1.0",
        certificate_fetcher=lambda h, p: None,
    )
    findings = scanner.run(TlsConfigTarget(host="other-site.com"))
    assert findings == []
