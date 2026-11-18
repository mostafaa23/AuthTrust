"""Redaction of secrets, tokens, cookies and API keys before evidence is
logged or written to a report.

``sanitize_evidence_dict`` is the one safe to call on a Finding's evidence
before it leaves the process; report writers rely on this.

``jwt_tamper.py``'s ``forged_token`` field is exempted by name: it is the
proof of the vulnerability itself, not a leaked secret.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_REDACTED = "[REDACTED]"

# Fields whose value *is* the evidence of the vulnerability and must stay
# readable in the report. Exempting by exact key name only - never by a
# substring match - so nothing else can be excluded from redaction by
# accident just because "token" or "forged" appears in its key.
_ALWAYS_VISIBLE_KEYS = frozenset({"forged_token"})

_SENSITIVE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9\-_.]+", re.IGNORECASE)),
    # AWS access key IDs: AKIA (long-term), ASIA (temporary/STS - what IMDS
    # actually returns), plus the other official 4-letter prefixes. All are
    # the same fixed length (16 chars after the prefix).
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    # AWS secret access key, as returned by IMDS/STS JSON responses
    # (`"SecretAccessKey":"..."`) or as an env-var-style assignment.
    (
        "aws_secret_access_key",
        re.compile(
            r'(?i)"?secret[_-]?access[_-]?key"?\s*[:=]\s*"?([A-Za-z0-9/+=]{30,})"?'
        ),
    ),
    # AWS session/security token - typically 100+ base64-like characters.
    (
        "aws_session_token",
        re.compile(
            r'(?i)"?(?:session|security)?[_-]?token"?\s*[:=]\s*"?([A-Za-z0-9/+=]{80,})"?'
        ),
    ),
    (
        "generic_api_key",
        re.compile(r"(?i)(api[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{16,}"),
    ),
    # Google API key (AIza...), 39 chars total.
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    # GitHub personal/OAuth/app/refresh tokens (ghp_, gho_, ghu_, ghs_, ghr_).
    ("github_token", re.compile(r"\bgh[posru]_[A-Za-z0-9]{36,255}\b")),
    # Slack tokens (bot/user/app/refresh/legacy).
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    # PEM private key blocks (RSA/EC/DSA/OPENSSH/PGP or plain).
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
            r".*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
]

_SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "set-cookie", "x-api-key"}


# ---------------------------------------------------------------------------
# Secret detection (used by scanners/secret_scan.py)
# ---------------------------------------------------------------------------
#
# Redaction (above) answers "make this evidence safe to write out". Detection
# answers "is there a secret in this text, and what kind" - the same patterns,
# read the other way round. secret_scan reuses these instead of maintaining a
# second, drifting copy of the regexes.

# A JWT: three base64url segments, the first starting with the base64 of ``{"``
# (``eyJ``). The length floors keep random dotted tokens from matching.
_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"
)

# Detectors map a pattern to the capture group that holds the secret *value*
# (0 = the whole match). Order matters only for which kind is reported when two
# patterns overlap on the same span; the most specific come first.
_SECRET_DETECTORS: list[tuple[str, re.Pattern, int]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"), 0),
    (
        "aws_secret_access_key",
        re.compile(
            r'(?i)"?secret[_-]?access[_-]?key"?\s*[:=]\s*"?([A-Za-z0-9/+=]{30,})"?'
        ),
        1,
    ),
    (
        "aws_session_token",
        re.compile(
            r'(?i)"?(?:session|security)[_-]?token"?\s*[:=]\s*"?([A-Za-z0-9/+=]{80,})"?'
        ),
        1,
    ),
    ("private_key", _SENSITIVE_PATTERNS[-1][1], 0),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), 0),
    ("github_token", re.compile(r"\bgh[posru]_[A-Za-z0-9]{36,255}\b"), 0),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0),
    ("jwt", _JWT_RE, 0),
    ("bearer_token", re.compile(r"\bBearer\s+([A-Za-z0-9\-_.]{12,})", re.IGNORECASE), 1),
    (
        "generic_api_key",
        re.compile(
            r"(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token)"
            r"['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,})"
        ),
        1,
    ),
]

# Kinds that represent live cloud credentials (vs. a generic app secret). These
# are what the trigger layer escalates into IAM-privilege analysis.
AWS_CREDENTIAL_KINDS = frozenset(
    {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"}
)


@dataclass(frozen=True)
class SecretMatch:
    """One detected secret. ``secret`` is the raw value (never written to a
    report); ``masked`` is the short, safe indicator that is."""

    kind: str
    secret: str
    masked: str
    start: int
    end: int


def mask_secret(secret: str) -> str:
    """Return a short, non-reversible indicator of a secret: enough to
    correlate it (prefix + last two chars + length) without disclosing it."""
    s = secret.strip()
    if "PRIVATE KEY" in s:
        return f"PEM private key block (len={len(s)})"
    if len(s) <= 6:
        return "*" * len(s)
    prefix = s[:4]
    suffix = s[-2:]
    return f"{prefix}{'*' * 6}{suffix} (len={len(s)})"


def detect_secrets(text: str) -> list[SecretMatch]:
    """Find secrets in ``text``. Overlapping matches are resolved by keeping
    the first (most specific) detector that claims a span, so one secret is
    not double-reported as two kinds."""
    if not text:
        return []
    out: list[SecretMatch] = []
    claimed: list[tuple[int, int]] = []

    def _overlaps(start: int, end: int) -> bool:
        return any(not (end <= s or start >= e) for s, e in claimed)

    for kind, pattern, group in _SECRET_DETECTORS:
        for m in pattern.finditer(text):
            try:
                value = m.group(group)
            except IndexError:  # pragma: no cover - defensive
                continue
            if not value:
                continue
            vstart = m.start(group)
            vend = m.end(group)
            if _overlaps(vstart, vend):
                continue
            claimed.append((vstart, vend))
            out.append(
                SecretMatch(
                    kind=kind,
                    secret=value,
                    masked=mask_secret(value),
                    start=vstart,
                    end=vend,
                )
            )
    out.sort(key=lambda sm: sm.start)
    return out


def sanitize_text(text: str) -> str:
    """Redact every sensitive pattern found in ``text``.

    When a pattern has a capture group (the secret *value* only, not the
    surrounding key/label), only that captured substring is replaced so the
    evidence stays readable (e.g. ``"SecretAccessKey":"[REDACTED]"`` instead
    of the whole key:value pair disappearing). Patterns without a capture
    group redact the entire match.
    """
    result = text
    for _name, pattern in _SENSITIVE_PATTERNS:
        if pattern.groups:
            result = pattern.sub(
                lambda m: m.group(0).replace(m.group(1), _REDACTED), result
            )
        else:
            result = pattern.sub(_REDACTED, result)
    return result


def sanitize_headers(headers: dict) -> dict:
    """Redact well-known sensitive header values (case-insensitive names)."""
    sanitized = {}
    for key, value in headers.items():
        if key.lower() in _SENSITIVE_HEADER_NAMES:
            sanitized[key] = _REDACTED
        else:
            sanitized[key] = value
    return sanitized


def sanitize_evidence_dict(evidence: dict) -> dict:
    """Redact a Finding's evidence dict before it is persisted or reported.

    Strings are passed through ``sanitize_text``. Nested dicts whose key
    name contains "header" are passed through ``sanitize_headers``. Keys in
    ``_ALWAYS_VISIBLE_KEYS`` are preserved verbatim because the key itself
    *is* the proof of the finding.
    """
    sanitized = {}
    for key, value in evidence.items():
        if key in _ALWAYS_VISIBLE_KEYS:
            sanitized[key] = value
        elif isinstance(value, str):
            sanitized[key] = sanitize_text(value)
        elif isinstance(value, dict):
            sanitized[key] = sanitize_headers(value) if "header" in key else value
        else:
            sanitized[key] = value
    return sanitized
