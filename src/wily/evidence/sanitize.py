"""Redaction of secrets, tokens, cookies and API keys before evidence is
logged or written to a report.

Only ``sanitize_evidence_dict`` is safe to call on a Finding's evidence
before it leaves the process (report writers rely on this - see
``report/json_report.py``). Scanners should still prefer calling
``sanitize_text``/``sanitize_headers`` directly on anything they capture
and plan to keep around in memory for longer than one Finding.

Note: in scanners/jwt_tamper.py, the evidence *is* the forged token
(``forged_token``) - that is intentional and not a leaked secret, it is
the proof of the vulnerability itself. It is exempted by name, not by any
looser rule, so an unrelated field that happens to contain the substring
"token" is never silently skipped.
"""

from __future__ import annotations

import re

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
]

_SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "set-cookie", "x-api-key"}


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
