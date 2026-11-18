"""Session-fixation scanner (OWASP A07)."""

from dataclasses import dataclass

from wily.scanners.session_fixation import (
    SessionFixationScanner,
    SessionFixationTarget,
    is_sensitive_session_cookie,
    parse_set_cookie,
)


# --- pure cookie parsing / classification ------------------------------------


def test_parse_set_cookie_basic():
    cookie = parse_set_cookie("session_id=abc123; Path=/; HttpOnly; Secure")
    assert cookie.name == "session_id"
    assert cookie.value == "abc123"
    assert cookie.http_only
    assert cookie.secure


def test_parse_set_cookie_without_flags():
    cookie = parse_set_cookie("language=ar; Path=/")
    assert cookie.name == "language"
    assert cookie.value == "ar"
    assert not cookie.http_only
    assert not cookie.secure


def test_parse_set_cookie_empty_returns_none():
    assert parse_set_cookie("") is None


def test_session_named_cookie_is_sensitive():
    cookie = parse_set_cookie("JSESSIONID=XYZ; Path=/")
    assert is_sensitive_session_cookie(cookie)


def test_httponly_cookie_is_sensitive_even_with_generic_name():
    cookie = parse_set_cookie("auth_state=XYZ; HttpOnly")
    assert is_sensitive_session_cookie(cookie)


def test_tracking_cookie_is_not_sensitive():
    cookie = parse_set_cookie("_ga=GA1.2.123; Path=/")
    assert not is_sensitive_session_cookie(cookie)


def test_language_cookie_is_not_sensitive():
    cookie = parse_set_cookie("language=ar; Path=/")
    assert not is_sensitive_session_cookie(cookie)


# --- scanner-level behaviour with a fake HTTP engine -------------------------


@dataclass
class _Resp:
    headers: dict
    text: str = ""


class _FakeHttp:
    def __init__(self, pre_cookie: str, post_cookie: str | None):
        self.pre_cookie = pre_cookie
        self.post_cookie = post_cookie
        self.calls = []

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url, headers, body))
        if method == "GET":
            return _Resp(headers={"Set-Cookie": self.pre_cookie})
        resp_headers = {}
        if self.post_cookie is not None:
            resp_headers["Set-Cookie"] = self.post_cookie
        return _Resp(headers=resp_headers)


def _target():
    return SessionFixationTarget(
        login_page_url="https://victim.example.com/login",
        login_submit_url="https://victim.example.com/login",
        credentials_body="username=alice&password=correct-horse",
    )


def test_fixation_detected_when_cookie_unchanged_after_login():
    http = _FakeHttp(
        pre_cookie="session_id=FIXED123; Path=/; HttpOnly",
        post_cookie="session_id=FIXED123; Path=/; HttpOnly",
    )
    findings = SessionFixationScanner(http_engine=http).run(_target())
    assert len(findings) == 1
    assert findings[0].category == "session-fixation"
    assert findings[0].severity == "high"
    # The pre-login cookie must be sent on the login POST.
    post_call = http.calls[1]
    assert post_call[2]["Cookie"] == "session_id=FIXED123"


def test_fixation_detected_when_no_new_cookie_issued_on_login():
    http = _FakeHttp(pre_cookie="session_id=FIXED123; Path=/; HttpOnly", post_cookie=None)
    findings = SessionFixationScanner(http_engine=http).run(_target())
    assert len(findings) == 1


def test_no_fixation_when_session_rotates():
    http = _FakeHttp(
        pre_cookie="session_id=PRELOGIN; Path=/; HttpOnly",
        post_cookie="session_id=ROTATED456; Path=/; HttpOnly",
    )
    findings = SessionFixationScanner(http_engine=http).run(_target())
    assert findings == []


def test_no_finding_when_no_sensitive_cookie_set_pre_login():
    http = _FakeHttp(pre_cookie="language=ar; Path=/", post_cookie="language=ar; Path=/")
    findings = SessionFixationScanner(http_engine=http).run(_target())
    assert findings == []


def test_no_http_engine_yields_no_findings():
    findings = SessionFixationScanner(http_engine=None).run(_target())
    assert findings == []
