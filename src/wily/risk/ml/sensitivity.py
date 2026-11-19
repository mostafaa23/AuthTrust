"""Heuristic response-sensitivity scorer.

Distinguishes a response that plausibly carries real sensitive data (a
credential-shaped value, a plausible account/billing-looking JSON shape)
from one that reads like an intentionally public catalog/listing response -
the "Test Oracle Problem" DAST-AI and similar research names as a leading
false-positive source for authz/BOLA-style findings.

This is deliberately NOT a trained classifier - there is no labeled dataset
yet (that is exactly what ``risk/ml/feedback.py`` exists to start
collecting). It is a regex/feature scorer, in the same spirit as
``evidence/sanitize.py``'s secret patterns, that produces a signed
adjustment plus a human-readable reason, consumed by ``risk/ml/ranker.py``.
Once ``risk/ml/feedback.py`` has accumulated enough decisions, this is the
first module worth replacing with a trained model - the interface
(``score_response() -> (float, str | None)``) is deliberately small so that
swap doesn't ripple elsewhere.
"""

from __future__ import annotations

import json
import re

# Strong, concrete sensitive-value shapes - same spirit as
# evidence/sanitize.py's secret patterns, but scoring plausible sensitive
# data IN A RESPONSE BODY, not credentials hardcoded in source.
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_CARD_LIKE_RE = re.compile(r"\b(?:\d[ -]*){13,16}\b")

# JSON key-paths (matched by last segment, case-insensitive) whose presence
# suggests a specific account/credential record rather than a shared
# catalog entry.
_ACCOUNT_SHAPED_KEYS = frozenset({
    "ssn", "social_security", "password", "password_hash", "credit_card",
    "card_number", "cvv", "iban", "account_number", "routing_number",
    "api_key", "secret", "token", "access_token", "refresh_token",
})

# Keys that suggest a shared/public catalog entry (product listing, docs)
# rather than one specific account's data. None of these alone means much;
# several together, with no account-shaped key alongside them, is the signal.
_CATALOG_SHAPED_KEYS = frozenset({
    "price", "sku", "in_stock", "category", "description", "title",
    "public", "name", "slug", "tags",
})

_STRONG_BOOST = 0.5
_WEAK_PENALTY = -0.3


def _flatten_key_names(obj, depth: int = 0) -> set[str]:
    """Every JSON key name (not full paths - just the leaf names, lower-
    cased) in a decoded structure, capped in breadth and depth so a
    pathological body can't make this expensive."""
    if depth > 6:
        return set()
    keys: set[str] = set()
    if isinstance(obj, dict):
        for k, v in list(obj.items())[:50]:
            keys.add(str(k).lower())
            keys |= _flatten_key_names(v, depth + 1)
    elif isinstance(obj, list):
        for item in obj[:5]:
            keys |= _flatten_key_names(item, depth + 1)
    return keys


def score_response(text: str | None) -> tuple[float, str | None]:
    """A signed adjustment (and the reason for it) based on whether ``text``
    plausibly carries real sensitive data vs. reads like an intentionally
    public catalog/listing response.

    Positive means the text is more likely to be a genuine leak (raises a
    finding's priority); negative means it looks like a public-catalog
    shape with no concrete sensitive value (lowers it). Returns
    ``(0.0, None)`` - no adjustment - whenever the text is empty/unreadable
    or neither signal is present; "no evidence either way" never nudges the
    score in either direction.
    """
    if not text or not isinstance(text, str):
        return 0.0, None

    if _AWS_KEY_RE.search(text):
        return _STRONG_BOOST, "response contains an AWS-key-shaped value"
    if _JWT_RE.search(text):
        return _STRONG_BOOST, "response contains a JWT-shaped value"
    if _EMAIL_RE.search(text) and _CARD_LIKE_RE.search(text):
        # Either alone is common noise (phone numbers, generic ids); both
        # together in the same response is a much stronger signal of real
        # account data than either pattern on its own.
        return _STRONG_BOOST, "response contains both an email and a card-number-shaped value"

    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return 0.0, None

    keys = _flatten_key_names(parsed)
    if keys & _ACCOUNT_SHAPED_KEYS:
        return _STRONG_BOOST, "response JSON has an account/credential-shaped field"

    if len(keys & _CATALOG_SHAPED_KEYS) >= 3:
        return _WEAK_PENALTY, "response JSON reads like a public catalog/listing shape"

    return 0.0, None
