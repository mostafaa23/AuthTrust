"""Session-fixation scanner (OWASP A07).

Captures the session cookie from an anonymous GET of the login page, logs
in while still sending that pre-login cookie, then checks whether the
cookie's value is unchanged afterward - if so, the server never rotates
the session ID on login, so an attacker who fixes a victim's cookie before
they authenticate inherits their session.

Only cookies that look like session identifiers (name pattern, or
HttpOnly - minus a small tracking-cookie denylist) are compared, to avoid
noise from analytics/preference cookies.

Safety: one anonymous GET and one login POST with tester-supplied
credentials, no different from a normal login. No confirmation flag needed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from wily.scanners.base import BaseScanner, Finding
from wily.scanners.http_engine import HttpEngine

# Cookie *names* that unambiguously mean "this is the session/auth cookie",
# collected from the most common frameworks (PHP, Java/JSP, Express,
# Rails, Django, generic "session"/"sid"/"auth" conventions).
_SESSION_NAME_RE = re.compile(
    r"(?:^|[_.\-])(session(?:id)?|sess|jsessionid|phpsessid|connect\.sid|"
    r"auth(?:token)?|sid)(?:$|[_\-])",
    re.IGNORECASE,
)

# Cookie names known to be tracking/preference, not session state - excluded
# even if they happen to be HttpOnly on some site.
_TRACKING_NAMES = {
    "_ga", "_gid", "_gat", "_fbp", "_fbc", "language", "lang", "locale",
    "theme", "consent", "cookieconsent", "cookie_consent", "_hjid",
}


@dataclass
class CookieFacts:
    name: str
    value: str
    http_only: bool
    secure: bool


_COOKIE_ATTR_RE = re.compile(r"^\s*([^=;\s]+)\s*=\s*([^;]*)")


def parse_set_cookie(header_value: str) -> CookieFacts | None:
    """Parse one ``Set-Cookie`` header value into its name/value/flags.

    Only a single cookie per header value is handled - this matches
    ``HttpEngine``'s ``HttpResponse.headers``, which (like the underlying
    ``requests`` library) folds multiple ``Set-Cookie`` response headers
    down to whichever one a dict keeps. A server that sets more than one
    cookie in one response will only have its last one visible here; that
    is an existing limitation of the shared HTTP layer, not something this
    scanner can work around on its own.
    """
    if not header_value:
        return None
    match = _COOKIE_ATTR_RE.match(header_value)
    if not match:
        return None
    name, value = match.group(1), match.group(2)
    return CookieFacts(
        name=name,
        value=value,
        http_only=bool(re.search(r";\s*httponly\b", header_value, re.IGNORECASE)),
        secure=bool(re.search(r";\s*secure\b", header_value, re.IGNORECASE)),
    )


def is_sensitive_session_cookie(cookie: CookieFacts) -> bool:
    """True when ``cookie`` is worth comparing pre/post login - see the
    module docstring's "Telling a session cookie from a tracking cookie"
    section."""
    if cookie.name.lower() in _TRACKING_NAMES:
        return False
    return bool(_SESSION_NAME_RE.search(cookie.name)) or cookie.http_only


@dataclass
class SessionFixationTarget:
    login_page_url: str
    login_submit_url: str
    submit_method: str = "POST"
    credentials_body: str = ""
    credentials_headers: dict = field(default_factory=dict)


class SessionFixationScanner(BaseScanner):
    name = "session_fixation"
    requires_tenant_pair = False
    requires_owned_infra = False

    def __init__(self, http_engine: HttpEngine | None = None) -> None:
        self.http = http_engine

    def _session_cookie(self, headers: dict) -> CookieFacts | None:
        raw = (headers or {}).get("Set-Cookie", "")
        cookie = parse_set_cookie(raw)
        if cookie is None or not is_sensitive_session_cookie(cookie):
            return None
        return cookie

    def run(self, target: SessionFixationTarget) -> list[Finding]:
        if self.http is None:
            return []

        try:
            pre_resp = self.http.request(method="GET", url=target.login_page_url, headers={})
        except Exception:
            return []
        pre_cookie = self._session_cookie(pre_resp.headers)
        if pre_cookie is None:
            return []

        post_headers = dict(target.credentials_headers)
        post_headers["Cookie"] = f"{pre_cookie.name}={pre_cookie.value}"
        try:
            post_resp = self.http.request(
                method=target.submit_method,
                url=target.login_submit_url,
                headers=post_headers,
                body=target.credentials_body,
            )
        except Exception:
            return []

        post_cookie = self._session_cookie(post_resp.headers)
        # No new Set-Cookie at all on the login response means the server
        # never issued a fresh session identifier either - just as much a
        # fixation failure as reissuing the identical value.
        post_value = post_cookie.value if post_cookie is not None else pre_cookie.value

        if post_value != pre_cookie.value:
            return []

        return [
            Finding(
                asset=target.login_submit_url,
                category="session-fixation",
                severity="high",
                confidence=0.8,
                discovery_source="scanner",
                evidence={
                    "cookie_name": pre_cookie.name,
                    "pre_login_value_masked": _mask(pre_cookie.value),
                    "session_rotated_on_login": post_cookie is not None
                    and post_cookie.value != pre_cookie.value,
                    "note": (
                        "The session identifier captured before authentication "
                        "is still valid after a successful login - the server "
                        "does not rotate the session ID on privilege change "
                        "(OWASP A07: Identification and Authentication "
                        "Failures)."
                    ),
                },
                remediation=(
                    "Issue a brand-new session identifier (invalidate the old "
                    "one server-side) immediately after a successful "
                    "authentication, so a session ID obtained before login "
                    "can never be reused to inherit a victim's post-login "
                    "session."
                ),
            )
        ]


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "..." + value[-4:]
