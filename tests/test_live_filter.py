"""Phase 4 live-asset filter tests (offline, no real network):
  - URL normalisation + exact/near-identical dedup are pure and deterministic.
  - id-like path segments collapse so /users/1 and /users/42 are one target.
  - scope partitioning drops out-of-scope URLs.
  - the optional liveness probe runs through an injected (fake) HttpEngine and
    drops only endpoints that don't answer.
"""

from wily.recon.live_filter import (
    dedup_urls,
    filter_live_assets,
    is_live,
    normalize_url,
    partition_in_scope,
    template_path,
)


def test_normalize_url_canonicalises():
    assert normalize_url("HTTPS://WWW.Example.com:443/a/") == "https://example.com/a"
    assert normalize_url("https://example.com/a?x=1#frag") == "https://example.com/a"
    assert normalize_url("ftp://example.com/a") is None
    assert normalize_url("not a url") is None


def test_template_path_collapses_ids():
    assert template_path("/users/42/orders/7") == "/users/{id}/orders/{id}"
    uuid = "9f1c2b3a-4d5e-6f70-8a9b-0c1d2e3f4a5b"
    assert template_path(f"/u/{uuid}") == "/u/{id}"
    assert template_path("/a/deadbeefcafe0001") == "/a/{id}"  # long hex blob
    # Non-id segments are left intact.
    assert template_path("/api/v1/users") == "/api/v1/users"


def test_dedup_collapses_exact_and_scheme_host_variants():
    urls = [
        "https://example.com/api/users",
        "https://www.example.com/api/users/",   # www + trailing slash
        "https://example.com/api/users?page=2",  # query only
    ]
    out = dedup_urls(urls)
    assert out == ["https://example.com/api/users"]


def test_dedup_collapses_id_variants_but_keeps_distinct_routes():
    urls = [
        "https://example.com/users/1",
        "https://example.com/users/2",
        "https://example.com/users/3",
        "https://example.com/orders/5",
    ]
    out = dedup_urls(urls)
    assert out == [
        "https://example.com/users/1",   # first id-variant representative
        "https://example.com/orders/5",  # distinct route kept
    ]


def test_dedup_can_disable_id_collapsing():
    urls = ["https://example.com/users/1", "https://example.com/users/2"]
    out = dedup_urls(urls, collapse_ids=False)
    assert out == urls  # only exact-canonical dedup -> both kept


def test_dedup_keeps_unclassifiable_urls():
    urls = ["s3://bucket/key", "s3://bucket/key", "https://example.com/a"]
    out = dedup_urls(urls)
    # The s3:// URL can't canonicalise but is kept (once), not dropped.
    assert "s3://bucket/key" in out
    assert out.count("s3://bucket/key") == 1
    assert "https://example.com/a" in out


class _FakeScope:
    def __init__(self, allowed_substr):
        self._allowed = allowed_substr

    def is_in_scope(self, url):
        return self._allowed in url


def test_partition_in_scope_splits():
    scope = _FakeScope("example.com")
    in_scope, out_scope = partition_in_scope(
        ["https://example.com/a", "https://evil.com/b"], scope
    )
    assert in_scope == ["https://example.com/a"]
    assert out_scope == ["https://evil.com/b"]


def test_partition_none_scope_passes_through():
    urls = ["https://example.com/a", "https://evil.com/b"]
    in_scope, out_scope = partition_in_scope(urls, None)
    assert in_scope == urls
    assert out_scope == []


class _FakeResp:
    def __init__(self, status_code):
        self.status_code = status_code


class _FakeEngine:
    """Records requests and returns scripted statuses; raises for 'dead' hosts."""

    def __init__(self, dead=(), head_blocked=()):
        self.dead = set(dead)
        self.head_blocked = set(head_blocked)
        self.calls = []

    def request(self, method, url):
        self.calls.append((method, url))
        if url in self.dead:
            raise ConnectionError("refused")
        if method == "HEAD" and url in self.head_blocked:
            return _FakeResp(405)
        return _FakeResp(200)


def test_is_live_true_on_any_response():
    engine = _FakeEngine()
    assert is_live(engine, "https://example.com/a") is True


def test_is_live_false_on_transport_error():
    engine = _FakeEngine(dead={"https://example.com/dead"})
    assert is_live(engine, "https://example.com/dead") is False


def test_is_live_falls_back_to_get_when_head_blocked():
    engine = _FakeEngine(head_blocked={"https://example.com/a"})
    assert is_live(engine, "https://example.com/a") is True
    assert ("HEAD", "https://example.com/a") in engine.calls
    assert ("GET", "https://example.com/a") in engine.calls


def test_filter_live_assets_dedups_without_probe():
    urls = [
        "https://example.com/users/1",
        "https://example.com/users/2",
        "https://example.com/orders/9",
    ]
    result = filter_live_assets(urls)  # no scope, no probe
    assert result.kept == [
        "https://example.com/users/1",
        "https://example.com/orders/9",
    ]
    assert result.collapsed == 1
    assert result.dead == []
    assert result.out_of_scope == []


def test_filter_live_assets_applies_scope_and_probe():
    urls = [
        "https://example.com/a",
        "https://example.com/dead",
        "https://evil.com/b",
    ]
    scope = _FakeScope("example.com")
    engine = _FakeEngine(dead={"https://example.com/dead"})
    result = filter_live_assets(urls, scope=scope, http_engine=engine, probe=True)
    assert result.kept == ["https://example.com/a"]
    assert result.out_of_scope == ["https://evil.com/b"]
    assert result.dead == ["https://example.com/dead"]
    # The out-of-scope URL must never have been probed.
    assert all("evil.com" not in url for _, url in engine.calls)
