#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wily :: wily/traffic_monitor.py
================================
Stage 4 of the discovery pipeline: passive, authenticated traffic capture.

Where Stage 0-3 (api_discovery.py) are static/black-box (user spec, docs
probing, JS scraping, wordlist fuzzing), this stage is dynamic: it drives a
real Chromium session through Playwright, lets a signed-in tester click
through the target app normally, and listens to every XHR/fetch response
that goes by. It is the only stage that can find endpoints that are never
referenced in a public spec or a JS bundle - calls assembled at runtime,
calls gated behind a login, GraphQL operations dispatched from a compiled
chunk, etc.

Design notes
------------
* Pairing request <-> response needs no manual bookkeeping: Playwright hands
  you the originating ``Request`` on every ``Response`` event
  (``response.request``), unlike a mitmproxy addon which has to correlate
  requests and responses itself.
* This module never guesses a login flow. It accepts one of:
    - ``storage_state``: a Playwright storage-state JSON saved from a
      session the tester already authenticated by hand (recommended -
      repeatable, no credentials handled by this code at all).
    - ``login``: an async callback you write for this one target, given the
      Page, that fills the form / clicks the SSO button.
    - Neither: the browser opens headful (``headless=False``, the default)
      and waits for the tester to log in and explore, then press ENTER in
      the terminal when done.
* Capture is passive and read-only: it listens, it never issues a request of
  its own and never submits a form itself - the tester (a real browser, a
  real human, an authorised test account) drives the navigation. Only point
  this at targets you are authorised to assess.
* Every captured endpoint is folded into api_discovery's ``DiscoveryReport``
  via ``add_endpoint()`` - the same dedupe-by-canonical-URL map Stage 1-3
  write into - so an endpoint found both in a JS bundle and in live traffic
  shows up once, tagged with both sources.
* Endpoints whose path carries what looks like an object id (numeric,
  UUID, Mongo ObjectId) are flagged ``bola_candidate`` in their details.
  That list (``bola_candidates()``) is the hand-off point for a later
  two-account BOLA/cross-tenant stage; this module does not attempt that
  testing itself - a single 200 OK here is evidence of "endpoint exists
  and responded", not of a vulnerability.

Requirements
------------
    pip install playwright
    playwright install chromium

Usage
-----
    import asyncio
    from wily.api_discovery import ApiDiscoveryPipeline, DiscoveryConfig
    from wily.traffic_monitor import TrafficMonitor, TrafficConfig

    async def main():
        # Stage 0-3, exactly as before.
        report = await ApiDiscoveryPipeline(
            DiscoveryConfig(target="https://tester.example.com")
        ).run()

        # Stage 4: open a real session, capture while the tester explores.
        monitor = TrafficMonitor(TrafficConfig(
            target_url="https://tester.example.com/login",
            save_storage_state_to="tester_session.json",  # reusable next run
        ))
        await monitor.run()
        monitor.merge_into(report)  # dedupes into the same report as Stage 1-3

        print(report.to_json())
        for ep in monitor.bola_candidates():
            print("BOLA candidate:", ep.method, ep.path)

    asyncio.run(main())

Next run, skip the manual login entirely:
    TrafficConfig(target_url="...", storage_state="tester_session.json")
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse

try:
    from playwright.async_api import Page, Request, Response, async_playwright
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "Wily traffic monitoring requires Playwright. Install it with:\n"
        "  pip install playwright && playwright install chromium\n"
    )
    raise SystemExit(2)

from .api_discovery import DiscoveryReport, canonical_url, id_like_names, same_site

logger = logging.getLogger("wily.traffic_monitor")

__all__ = ["TrafficMonitor", "TrafficConfig", "CapturedEndpoint"]

# ---------------------------------------------------------------------------
# Heuristics (deliberately close cousins of api_discovery.py's own, so the
# two stages agree on what "looks like an API call" means)
# ---------------------------------------------------------------------------

# Playwright's own classification - the two types that actually carry API
# traffic. Images/fonts/css/documents are never considered here.
API_RESOURCE_TYPES = frozenset({"xhr", "fetch"})

API_PATH_MARKERS = re.compile(
    r"/(?:api|rest|graphql|gql|rpc|webhooks?|internal|v\d+)(?:/|$)", re.IGNORECASE
)
API_CONTENT_TYPE_MARKERS = ("json", "graphql", "x-www-form-urlencoded")

AUTH_HEADER_NAMES = frozenset(
    {"authorization", "x-api-key", "x-auth-token", "x-csrf-token"}
)

# Path segments that look like an identifier rather than a fixed route
# segment - exactly the endpoints worth handing to a later two-account
# BOLA/cross-tenant testing stage.
_NUMERIC_ID = re.compile(r"^\d+$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_MONGO_OBJECT_ID = re.compile(r"^[0-9a-f]{24}$", re.IGNORECASE)


def _primary_status(codes: Set[int]) -> Optional[int]:
    """Pick one representative status to surface: the lowest 2xx, else the max seen."""
    if not codes:
        return None
    ok = sorted(c for c in codes if 200 <= c < 300)
    return ok[0] if ok else max(codes)


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass
class CapturedEndpoint:
    """One endpoint as observed live - everything Stage 0-3 structurally can't see."""

    method: str
    url: str  # canonical
    path: str
    content_type: Optional[str] = None
    status_codes: Set[int] = field(default_factory=set)
    auth_present: bool = False
    auth_type: Optional[str] = None
    # Index (0-based, path-segment position) of segments that look like IDs.
    path_param_positions: List[int] = field(default_factory=list)
    query_params: Set[str] = field(default_factory=set)
    body_params: Set[str] = field(default_factory=set)
    request_count: int = 0
    first_seen: str = ""
    last_seen: str = ""
    sample_request_body: Optional[str] = None
    sample_response_body: Optional[str] = None
    # Concrete requests are kept in memory for Stage 5, not in the JSON report.
    request_samples: List[Dict[str, Any]] = field(default_factory=list, repr=False)
    # Which identity's session observed this request. This is an ownership
    # hint for Stage 5, not proof that the resource is exclusive to that tenant.
    owner_identity: Optional[str] = None

    @property
    def bola_candidate(self) -> bool:
        """True when a path segment, or a query/body parameter *name*, looks
        like an object or tenant reference.

        Path segments are checked by shape (``_NUMERIC_ID``/``_UUID``/
        ``_MONGO_OBJECT_ID`` below, against the live value). Query and body
        parameters are checked by *name* instead (``id_like_names``, shared
        with ``api_discovery.py``), because a cross-tenant parameter is very
        often carried as ``?tenant_id=123`` rather than a path segment - a
        shape-only check over the path would miss that case completely.
        """
        if self.path_param_positions:
            return True
        return bool(id_like_names(self.query_params) or id_like_names(self.body_params))

    def to_details(self) -> Dict[str, Any]:
        """Shape this record for ``DiscoveryReport.add_endpoint(details=...)``."""
        return {
            "auth_present": self.auth_present,
            "auth_type": self.auth_type,
            "query_params": sorted(self.query_params),
            "body_params": sorted(self.body_params),
            "path_param_positions": self.path_param_positions,
            "id_like_query_params": id_like_names(self.query_params),
            "id_like_body_params": id_like_names(self.body_params),
            "bola_candidate": self.bola_candidate,
            "owner_identity": self.owner_identity,
            "request_count": self.request_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "status_codes_seen": sorted(self.status_codes),
        }


@dataclass
class TrafficConfig:
    """Everything one traffic-capture session needs."""

    target_url: str
    # Name of the test account driving this session (e.g. "accountA"). Run
    # this module once per identity you want BOLA-tested and give each run a
    # different identity_name; bola_tester.py uses the stamp this leaves on
    # every CapturedEndpoint to know *whose* resource a candidate is, instead
    # of guessing ownership from traffic alone.
    identity_name: Optional[str] = None
    # A saved Playwright storage_state.json from a prior authenticated
    # session. When set, no login step runs - the context opens already
    # signed in.
    storage_state: Optional[str] = None
    # App-specific login steps, given the Page. Write this per target;
    # this module deliberately never guesses selectors or submits creds.
    login: Optional[Callable[[Page], Awaitable[None]]] = None
    # Persist the authenticated session here so the next run can skip login
    # entirely via `storage_state=`.
    save_storage_state_to: Optional[str] = None
    # Headful by default: a human drives the exploration. Flip to True only
    # when paired with `storage_state` + scripted navigation of your own.
    headless: bool = False
    same_site_only: bool = True  # ignore third-party analytics/CDN noise
    capture_bodies: bool = True
    max_body_bytes: int = 20_000
    # Hard ceiling for headless/unattended runs; the headful/manual path
    # ends as soon as the tester presses ENTER, regardless of this value.
    idle_timeout: float = 600.0


# ---------------------------------------------------------------------------
# The monitor
# ---------------------------------------------------------------------------


class TrafficMonitor:
    """Drives one authenticated Chromium session and listens to its traffic."""

    def __init__(self, config: TrafficConfig) -> None:
        self.cfg = config
        self.origin_host = urlparse(config.target_url).hostname or ""
        self.endpoints: Dict[str, CapturedEndpoint] = {}
        self._lock = asyncio.Lock()
        # Each "response" event spawns its own task (see run()) so one slow
        # body read never blocks the next event. Tracked here so run() can
        # drain them before browser.close() - otherwise the last few
        # responses captured right before the tester hits ENTER are either
        # silently lost (task killed mid-await) or raise an unhandled
        # "Task was destroyed but it is pending" warning once the loop
        # notices the orphaned task.
        self._pending_tasks: Set[asyncio.Task] = set()

    # -- filtering ------------------------------------------------------

    def _in_scope(self, url: str) -> bool:
        if not self.cfg.same_site_only:
            return True
        return same_site(self.origin_host, urlparse(url).hostname or "")

    def _looks_like_api(self, request: Request, response: Response) -> bool:
        if request.resource_type in API_RESOURCE_TYPES:
            return True
        if API_PATH_MARKERS.search(urlparse(request.url).path):
            return True
        ctype = (response.headers.get("content-type") or "").lower()
        if any(marker in ctype for marker in API_CONTENT_TYPE_MARKERS):
            return True
        header_names = {k.lower() for k in request.headers.keys()}
        return bool(header_names & AUTH_HEADER_NAMES)

    # -- capture ----------------------------------------------------------

    def _spawn_tracked(self, coro: Awaitable[None]) -> None:
        """Schedule ``coro`` as a task and remember it until it finishes."""
        task = asyncio.create_task(coro)
        self._pending_tasks.add(task)
        task.add_done_callback(self._pending_tasks.discard)

    async def _on_response(self, response: Response) -> None:
        try:
            request = response.request
            if not self._in_scope(request.url):
                return
            if not self._looks_like_api(request, response):
                return

            key = canonical_url(request.url)
            if not key:
                return
            method = request.method.upper()
            record_key = f"{method}:{key}"
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            lower_headers = {k.lower(): v for k, v in request.headers.items()}
            auth_header = lower_headers.get("authorization", "")
            auth_type: Optional[str] = None
            if auth_header.lower().startswith("bearer"):
                auth_type = "bearer"
            elif auth_header.lower().startswith("basic"):
                auth_type = "basic"
            elif "x-api-key" in lower_headers:
                auth_type = "api_key"
            auth_present = bool(set(lower_headers) & AUTH_HEADER_NAMES)

            parsed = urlparse(request.url)
            query_params = set(parse_qs(parsed.query).keys())

            body_params: Set[str] = set()
            sample_request_body: Optional[str] = None
            if self.cfg.capture_bodies:
                post_data = request.post_data
                if post_data:
                    sample_request_body = post_data[: self.cfg.max_body_bytes]
                    if "json" in lower_headers.get("content-type", ""):
                        try:
                            parsed_body = json.loads(post_data)
                            if isinstance(parsed_body, dict):
                                body_params = set(parsed_body.keys())
                        except (json.JSONDecodeError, TypeError):
                            pass

            sample_response_body: Optional[str] = None
            if self.cfg.capture_bodies:
                try:
                    resp_ctype = (response.headers.get("content-type") or "").lower()
                    if "json" in resp_ctype or "text" in resp_ctype:
                        body_text = await response.text()
                        sample_response_body = body_text[: self.cfg.max_body_bytes]
                except Exception:  # noqa: BLE001 - body may be gone (redirect/binary/closed)
                    pass

            segments = [s for s in parsed.path.split("/") if s]
            id_positions = [
                i
                for i, seg in enumerate(segments)
                if _NUMERIC_ID.match(seg) or _UUID.match(seg) or _MONGO_OBJECT_ID.match(seg)
            ]

            async with self._lock:
                record = self.endpoints.get(record_key)
                if record is None:
                    record = CapturedEndpoint(
                        method=method,
                        url=key,
                        path=parsed.path or "/",
                        content_type=response.headers.get("content-type"),
                        first_seen=now,
                        owner_identity=self.cfg.identity_name,
                    )
                    self.endpoints[record_key] = record
                record.status_codes.add(response.status)
                record.auth_present = record.auth_present or auth_present
                record.auth_type = record.auth_type or auth_type
                record.query_params |= query_params
                record.body_params |= body_params
                if not record.path_param_positions:
                    record.path_param_positions = id_positions
                record.request_count += 1
                record.last_seen = now
                replay_sample = {
                    "method": method,
                    "url": request.url,
                    "body": sample_request_body,
                    "content_type": lower_headers.get("content-type"),
                }
                signature = (method, request.url, sample_request_body or "")
                if not any(
                    (s.get("method"), s.get("url"), s.get("body") or "") == signature
                    for s in record.request_samples
                ) and len(record.request_samples) < 10:
                    record.request_samples.append(replay_sample)
                if sample_request_body and not record.sample_request_body:
                    record.sample_request_body = sample_request_body
                if sample_response_body and not record.sample_response_body:
                    record.sample_response_body = sample_response_body

            logger.info("Traffic: %s %s -> %s", method, parsed.path, response.status)
        except Exception as exc:  # noqa: BLE001 - one bad event must never kill the session
            logger.debug("Traffic capture skipped one event: %s", exc)

    # -- session orchestration -------------------------------------------

    async def run(self) -> Dict[str, CapturedEndpoint]:
        """Open the session, capture traffic, return the captured endpoints."""
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=self.cfg.headless)
            context = await browser.new_context(
                storage_state=self.cfg.storage_state if self.cfg.storage_state else None
            )
            page = await context.new_page()
            page.on("response", lambda r: self._spawn_tracked(self._on_response(r)))

            await page.goto(self.cfg.target_url)

            if self.cfg.login is not None:
                logger.info("Running the provided login() callback...")
                await self.cfg.login(page)

            if self.cfg.storage_state is None and not self.cfg.headless:
                # No saved session and a human is at the wheel: let them log
                # in (manually or via the login callback above having placed
                # them post-login) and explore, then hand control back here.
                await self._wait_for_tester()
            elif self.cfg.headless:
                await asyncio.sleep(self.cfg.idle_timeout)

            if self.cfg.save_storage_state_to:
                await context.storage_state(path=self.cfg.save_storage_state_to)
                logger.info(
                    "Session saved to %s - pass storage_state=... next run to skip login",
                    self.cfg.save_storage_state_to,
                )

            if self._pending_tasks:
                logger.debug(
                    "Draining %d in-flight response handler(s) before closing...",
                    len(self._pending_tasks),
                )
                await asyncio.wait(self._pending_tasks, timeout=5.0)

            await browser.close()

        logger.info("Traffic monitoring finished: %d endpoint(s) captured", len(self.endpoints))
        return self.endpoints

    @staticmethod
    async def _wait_for_tester() -> None:
        """Block until the tester (a human, in the terminal) says they're done exploring."""
        print(
            "\n[Wily] Browser is open and traffic capture is running.\n"
            "       Log in with the authorised test account and click through the\n"
            "       flows you want covered, then press ENTER here when done...\n",
            file=sys.stderr,
        )
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, sys.stdin.readline)

    # -- integration with Stage 0-3 ----------------------------------------

    def merge_into(self, report: DiscoveryReport) -> None:
        """Fold captured endpoints into the report, keeping replay material private."""
        for record in self.endpoints.values():
            samples = record.request_samples or [None]
            for index, sample in enumerate(samples):
                report.add_endpoint(
                    record.url,
                    source="traffic_monitoring",
                    methods={record.method},
                    status=_primary_status(record.status_codes),
                    content_type=record.content_type,
                    details=record.to_details() if index == 0 else None,
                    replay_sample=sample,
                )

    def bola_candidates(self) -> List[CapturedEndpoint]:
        """Endpoints worth handing to the (future) two-account BOLA/cross-tenant stage."""
        return [r for r in self.endpoints.values() if r.bola_candidate]
