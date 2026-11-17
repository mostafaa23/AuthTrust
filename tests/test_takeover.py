"""Phase 3: subdomain / cloud-resource takeover scanner.

CNAME is injected (via a fake resolver or the target field) and the HTTP body
is scripted, so no real DNS or network is touched. The scanner only reads - it
never claims or registers a resource, which these tests assert by construction
(there is no write path to exercise).
"""

from dataclasses import dataclass

from wily.scanners.takeover import TakeoverScanner, TakeoverTarget

_S3_NOSUCHBUCKET = "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"
_GH_PAGES_404 = "<h1>404</h1><p>There isn't a GitHub Pages site here.</p>"
_NORMAL_404 = "<html><body>404 Not Found</body></html>"


@dataclass
class _Resp:
    status_code: int
    text: str = ""


class _FakeHttp:
    def __init__(self, body):
        self.body = body
        self.calls = []

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url))
        return _Resp(404, self.body)


def test_s3_takeover_fingerprint_sufficient_without_cname():
    http = _FakeHttp(_S3_NOSUCHBUCKET)
    findings = TakeoverScanner(scope_manager=None, http_engine=http).run(
        TakeoverTarget(host="assets.victim.com", url="https://assets.victim.com/")
    )
    assert len(findings) == 1
    assert findings[0].category == "subdomain-takeover-aws-s3"
    assert all(method == "GET" for method, _ in http.calls)


def test_github_pages_requires_cname_match():
    http = _FakeHttp(_GH_PAGES_404)
    # Fingerprint present but no CNAME -> not flagged (ordinary 404 guard).
    no_cname = TakeoverScanner(scope_manager=None, http_engine=http).run(
        TakeoverTarget(host="blog.victim.com", url="https://blog.victim.com/")
    )
    assert no_cname == []
    # With the CNAME pointing at github.io, it is a takeover indicator.
    with_cname = TakeoverScanner(scope_manager=None, http_engine=http).run(
        TakeoverTarget(host="blog.victim.com", cname="victim.github.io", url="https://blog.victim.com/")
    )
    assert any(f.category == "subdomain-takeover-github-pages" for f in with_cname)
    assert with_cname[0].confidence == 0.9  # cname + fingerprint both matched


def test_resolver_is_used_when_cname_absent():
    http = _FakeHttp(_GH_PAGES_404)
    scanner = TakeoverScanner(
        scope_manager=None,
        http_engine=http,
        resolver=lambda host: "victim.github.io",
    )
    findings = scanner.run(TakeoverTarget(host="blog.victim.com", url="https://blog.victim.com/"))
    assert any(f.category == "subdomain-takeover-github-pages" for f in findings)


def test_normal_404_is_not_a_takeover():
    http = _FakeHttp(_NORMAL_404)
    findings = TakeoverScanner(scope_manager=None, http_engine=http).run(
        TakeoverTarget(host="www.victim.com", cname="victim.github.io", url="https://www.victim.com/")
    )
    assert findings == []


def test_no_body_no_finding():
    findings = TakeoverScanner(scope_manager=None, http_engine=None).run(
        TakeoverTarget(host="x.victim.com", cname="victim.github.io")
    )
    assert findings == []
