from urllib.parse import urljoin, urlsplit

from .scope_manager import ScopeError, ScopeManager


class ScopeGuard:
    """Validate URLs and redirects against Wily's authorized scope."""

    def __init__(self, scope: ScopeManager) -> None:
        self.scope = scope

    def validate_url(self, url: str) -> str:
        """Return the URL if it is valid and inside the authorized scope."""

        if not isinstance(url, str) or not url:
            raise ScopeError("URL cannot be empty.")

        if url != url.strip():
            raise ScopeError("URL must not have leading or trailing whitespace.")

        if "\\" in url or any(
            char.isspace() or ord(char) < 32 or ord(char) == 127
            for char in url
        ):
            raise ScopeError("URL contains whitespace or invalid characters.")

        try:
            parsed = urlsplit(url)
            hostname = parsed.hostname
            _ = parsed.port
        except ValueError as exc:
            raise ScopeError("Malformed URL or port.") from exc

        if parsed.scheme.lower() not in ("http", "https"):
            raise ScopeError("Only HTTP and HTTPS URLs are allowed.")

        if not parsed.netloc or not hostname:
            raise ScopeError("URL must include a hostname.")

        if parsed.username is not None or parsed.password is not None:
            raise ScopeError("URLs containing credentials are not allowed.")

        self.scope.require_in_scope(url)
        return url

    def validate_redirect(self, current_url: str, location: str) -> str:
        """Resolve and validate a redirect before following it."""

        self.validate_url(current_url)

        if not isinstance(location, str) or not location.strip():
            raise ScopeError("Redirect location cannot be empty.")

        if any(ord(char) < 32 or ord(char) == 127 for char in location):
            raise ScopeError("Redirect location contains control characters.")

        destination = urljoin(current_url, location.strip())
        return self.validate_url(destination)