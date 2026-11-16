"""Formal tests proving: "out-of-scope requests are blocked" (Phase 1,
requirement 2). Uses a real local Flask server, not mocks - exercises
HttpEngine making real HTTP requests and confirms they're blocked correctly.
"""

import threading
import time

import pytest
from flask import Flask, jsonify, redirect

from wily.core.http_policy import resolve_redirect
from wily.core.rate_limiter import AdaptiveRateLimiter
from wily.core.scope_manager import ScopeError, ScopeManager
from wily.scanners.http_engine import HttpEngine, TooManyRedirectsError, UnsafeAddressError


@pytest.fixture(scope="module")
def demo_server():
    """A local server with a plain endpoint, two redirects (internal and
    external), and a multi-redirect chain for testing max_redirects."""
    app = Flask("scope_enforcement_demo")

    @app.route("/safe")
    def safe():
        return jsonify({"status": "ok"}), 200

    @app.route("/redirect-internal")
    def redirect_internal():
        return redirect("/safe", code=302)

    @app.route("/redirect-to-evil")
    def redirect_evil():
        return redirect("http://evil-outside-scope.invalid/steal", code=302)

    @app.route("/redirect-loop/<int:n>")
    def redirect_loop(n):
        return redirect(f"/redirect-loop/{n + 1}", code=302)

    port = 5099
    thread = threading.Thread(target=lambda: app.run(port=port, use_reloader=False), daemon=True)
    thread.start()
    time.sleep(1.0)
    yield f"http://127.0.0.1:{port}"


@pytest.fixture
def scope():
    return ScopeManager("127.0.0.1", allow_local_targets=True)


@pytest.fixture
def engine(scope):
    return HttpEngine(scope_manager=scope, rate_limiter=AdaptiveRateLimiter(initial_rps=50))


def test_direct_request_outside_scope_is_blocked(engine):
    """A direct request to a domain outside scope - must be rejected
    immediately, before it ever reaches the network."""
    with pytest.raises(ScopeError):
        engine.request("GET", "http://example.com/")


def test_request_inside_scope_succeeds(engine, demo_server):
    """The reverse case - an in-scope endpoint must work normally."""
    resp = engine.request("GET", f"{demo_server}/safe")
    assert resp.status_code == 200


def test_scope_manager_rejects_evil_subdomain_spoofing():
    """example.com.attacker.net is not a real subdomain of example.com -
    must be rejected, not wrongly accepted as 'ends with example.com'."""
    scope = ScopeManager("example.com")
    assert scope.is_in_scope("https://example.com") is True
    assert scope.is_in_scope("https://api.example.com") is True
    assert scope.is_in_scope("https://example.com.attacker.net") is False
    assert scope.is_in_scope("https://attacker-example.com") is False


def test_redirect_to_in_scope_target_is_followed(engine, demo_server):
    """A redirect to a path within the same scope - must be followed
    normally, returning the final result."""
    resp = engine.request("GET", f"{demo_server}/redirect-internal")
    assert resp.status_code == 200
    assert resp.url.endswith("/safe")


def test_redirect_to_out_of_scope_target_is_blocked(engine, demo_server):
    """The critical protection: an in-scope endpoint tries to redirect
    you outside scope - HttpEngine must refuse to follow the redirect,
    not just trust the first URL."""
    with pytest.raises(ScopeError):
        engine.request("GET", f"{demo_server}/redirect-to-evil")


def test_redirect_chain_respects_max_redirects(engine, demo_server):
    """A chain of in-scope redirects, but longer than max_redirects -
    must stop with a clear error (TooManyRedirectsError), not an
    infinite loop."""
    short_engine = HttpEngine(
        scope_manager=engine.scope_manager,
        rate_limiter=AdaptiveRateLimiter(initial_rps=50),
        max_redirects=3,
    )
    with pytest.raises(TooManyRedirectsError):
        short_engine.request("GET", f"{demo_server}/redirect-loop/0")


def test_http_engine_requires_scope_manager():
    """No exceptions - HttpEngine() with no scope_manager must refuse to
    even construct, so no scanner can accidentally route around the
    check."""
    with pytest.raises(ValueError):
        HttpEngine(scope_manager=None)


def test_resolve_redirect_enforces_scope_guard():
    """If a redirect leads outside scope, the policy must reject it
    immediately."""
    scope = ScopeManager("127.0.0.1", allow_local_targets=True)
    assert resolve_redirect(scope, "http://127.0.0.1/one", "/two") == "http://127.0.0.1/two"
    with pytest.raises(ScopeError):
        resolve_redirect(scope, "http://127.0.0.1/one", "http://example.com/")


def test_host_is_safe_blocks_loopback_without_allow_local():
    """The IP-safety guard is a separate check from the hostname-scope
    check: even a hostname that legitimately matches the authorized scope
    (by name) must still be refused if it resolves to a private/loopback/
    link-local/metadata address and the ScopeManager was not given
    allow_local_targets=True. Tested directly against _host_is_safe
    rather than through a full request, since a ScopeManager whose own
    *target* is a bare IP already refuses to construct at all when
    allow_local_targets=False (a separate, stricter rule in
    normalize_domain/_parse_hostname) - this guard exists for the case
    where the target is an ordinary domain name but a *request* URL's
    host resolves to an internal address."""
    scope_for_domain_target = ScopeManager("example.com", allow_local_targets=False)
    engine_no_local = HttpEngine(
        scope_manager=scope_for_domain_target,
        rate_limiter=AdaptiveRateLimiter(initial_rps=50),
    )
    assert engine_no_local._host_is_safe("127.0.0.1") is False
    assert engine_no_local._host_is_safe("169.254.169.254") is False


def test_host_is_safe_allows_loopback_with_allow_local():
    """The positive case: once allow_local_targets=True, a loopback
    address is considered safe to connect to."""
    scope_allow_local = ScopeManager("example.com", allow_local_targets=True)
    engine_allow_local = HttpEngine(
        scope_manager=scope_allow_local,
        rate_limiter=AdaptiveRateLimiter(initial_rps=50),
    )
    assert engine_allow_local._host_is_safe("127.0.0.1") is True


def test_http_engine_allows_loopback_with_allow_local(engine, demo_server):
    """The positive case end-to-end: with allow_local_targets=True, a
    loopback target is reachable through a real request (already covered
    by test_request_inside_scope_succeeds, repeated here to make the
    IP-safety guard's behavior explicit alongside the unit tests above)."""
    resp = engine.request("GET", f"{demo_server}/safe")
    assert resp.status_code == 200
