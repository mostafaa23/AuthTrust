"""Scope + Redirect + 429 tests for BolaTester._replay() - uses aiohttp
for real against a local Flask server, not mocks."""

import asyncio
import threading
import time

import pytest
from flask import Flask, jsonify, redirect, request

from wily.core.scope_manager import ScopeManager
from wily.scanners.bola import BolaTester, Identity


@pytest.fixture(scope="module")
def demo_server():
    app = Flask("bola_policy_demo")
    _attempt_counter = {"n": 0}

    @app.route("/resource/<int:rid>")
    def resource(rid):
        return jsonify({"id": rid, "owner": "tenant_a"}), 200

    @app.route("/redirect-internal/<int:rid>")
    def redirect_internal(rid):
        return redirect(f"/resource/{rid}", code=302)

    @app.route("/redirect-to-evil")
    def redirect_evil():
        return redirect("http://evil-outside-scope.invalid/steal", code=302)

    @app.route("/flaky")
    def flaky():
        _attempt_counter["n"] += 1
        if _attempt_counter["n"] < 2:
            return jsonify({"error": "slow down"}), 429
        return jsonify({"status": "ok"}), 200

    port = 5098
    thread = threading.Thread(target=lambda: app.run(port=port, use_reloader=False), daemon=True)
    thread.start()
    time.sleep(1.0)
    yield f"http://127.0.0.1:{port}"


@pytest.fixture
def scope():
    return ScopeManager("127.0.0.1", allow_local_targets=True)


@pytest.fixture
def identities():
    return [
        Identity("tenant_a", {"Authorization": "Bearer token-a"}),
        Identity("tenant_b", {"Authorization": "Bearer token-b"}),
    ]


def test_replay_outside_scope_fails_closed(scope, identities):
    tester = BolaTester(identities, scope_manager=scope, min_confidence="LOW")

    async def _run():
        return await tester._replay("http://example.com/resource/1", "GET", identities[0])

    sample = asyncio.run(_run())
    assert sample.status is None
    assert sample.error is not None
    assert "scope" in sample.error.lower()


def test_replay_follows_in_scope_redirect(demo_server, scope, identities):
    tester = BolaTester(identities, scope_manager=scope, min_confidence="LOW")

    async def _run():
        connector = __import__("aiohttp").TCPConnector(limit=5)
        async with __import__("aiohttp").ClientSession(connector=connector) as session:
            tester._session = session
            return await tester._replay(f"{demo_server}/redirect-internal/42", "GET", identities[0])

    sample = asyncio.run(_run())
    assert sample.status == 200
    assert sample.error is None


def test_replay_blocks_redirect_outside_scope(demo_server, scope, identities):
    tester = BolaTester(identities, scope_manager=scope, min_confidence="LOW")

    async def _run():
        import aiohttp
        async with aiohttp.ClientSession() as session:
            tester._session = session
            return await tester._replay(f"{demo_server}/redirect-to-evil", "GET", identities[0])

    sample = asyncio.run(_run())
    assert sample.status is None
    assert sample.error is not None
    assert "scope" in sample.error.lower()


def test_replay_retries_on_429_then_succeeds(demo_server, scope, identities):
    tester = BolaTester(identities, scope_manager=scope, min_confidence="LOW")

    async def _run():
        import aiohttp
        async with aiohttp.ClientSession() as session:
            tester._session = session
            return await tester._replay(f"{demo_server}/flaky", "GET", identities[0])

    sample = asyncio.run(_run())
    assert sample.status == 200
    assert sample.error is None
