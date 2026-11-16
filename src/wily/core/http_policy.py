"""Logic shared between HttpEngine (sync) and BolaTester (async) -
transport-agnostic so both use exactly the same policy instead of two
copies that could drift apart.
"""

from __future__ import annotations

from urllib.parse import urljoin

from wily.core.scope_manager import ScopeManager

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def resolve_redirect(scope_manager: ScopeManager, current_url: str, location: str) -> str:
    """Build the full URL from a Location header and verify it is inside
    scope before returning it. Raises ScopeError (from scope_manager) if
    the redirect target is out of scope - the exact same policy whether
    called from HttpEngine or BolaTester."""
    next_url = urljoin(current_url, location)
    scope_manager.require_in_scope(next_url)
    return next_url
