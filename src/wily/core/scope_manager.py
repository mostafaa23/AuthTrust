from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


_LOCAL_HOSTNAMES = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost"}
)


class ScopeError(ValueError):
    """Raised when a target or URL is invalid."""


def _parse_hostname(
    value: str, *, target: bool = False, allow_local_targets: bool = False
) -> str:
    """Validate an input and return its normalized hostname."""

    if not isinstance(value, str) or not value.strip():
        raise ScopeError("Target/URL cannot be empty.")

    value = value.strip()

    # Accept either a bare hostname or an HTTP(S) URL.
    if "://" in value:
        parsed = urlsplit(value)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ScopeError("Only HTTP and HTTPS URLs are supported.")
    else:
        parsed = urlsplit("//" + value)

    if not parsed.hostname:
        raise ScopeError("Invalid hostname or URL.")

    if parsed.username is not None or parsed.password is not None:
        raise ScopeError("URLs containing credentials are not allowed.")

    try:
        _ = parsed.port
    except ValueError as exc:
        raise ScopeError("Invalid port.") from exc

    if target and (
        parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ScopeError(
            "Enter a domain or a base URL only, without a path or query."
        )

    hostname = parsed.hostname.rstrip(".").lower()

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None
    if ip is not None:
        if allow_local_targets and ip.is_loopback:
            return hostname
        raise ScopeError("IP addresses are not accepted as domain targets.")

    if hostname in _LOCAL_HOSTNAMES:
        if allow_local_targets:
            return hostname
        raise ScopeError("Localhost is not accepted as a domain target.")
    if hostname.endswith(".localhost"):
        raise ScopeError("Localhost is not accepted as a domain target.")

    # Convert internationalized domain names to their ASCII form.
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError("Invalid internationalized domain name.") from exc

    if len(hostname) > 253 or "." not in hostname:
        raise ScopeError("Enter a valid fully qualified domain name.")

    labels = hostname.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            # Underscore allowed: real DNS labels like _dmarc, _acme-challenge,
            # _sip._tcp (TXT/SRV-style records) are legal and common - a recon
            # tool that drops these as "invalid" silently loses real subdomains.
            or not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?", label)
        ):
            raise ScopeError(f"Invalid domain label: {label!r}")

    return hostname


def normalize_domain(value: str) -> str:
    """Validate a target domain and return its normalized hostname."""
    return _parse_hostname(value, target=True)


class ScopeManager:
    """Checks whether a hostname belongs to the authorized target scope."""

    def __init__(
        self,
        target: str,
        *,
        allow_subdomains: bool = True,
        excluded_hosts: tuple[str, ...] = (),
        allow_local_targets: bool = False,
    ) -> None:
        self.allow_local_targets = allow_local_targets
        self.target = _parse_hostname(
            target, target=True, allow_local_targets=allow_local_targets
        )
        self._is_local_target = self.target in _LOCAL_HOSTNAMES or (
            _is_loopback_address(self.target)
        )
        self.allow_subdomains = allow_subdomains
        self.excluded_hosts = tuple(
            normalize_domain(host) for host in excluded_hosts
        )

    @staticmethod
    def _matches(hostname: str, base: str) -> bool:
        # The dot prevents evil-example.com matching example.com.
        return hostname == base or hostname.endswith("." + base)

    def is_in_scope(self, url_or_host: str) -> bool:
        """Return True only when the URL/hostname is inside the allowed scope."""

        try:
            hostname = _parse_hostname(
                url_or_host, allow_local_targets=self.allow_local_targets
            )
        except ScopeError:
            return False

        # Exclusions take precedence over inclusions.
        for excluded in self.excluded_hosts:
            if self._matches(hostname, excluded):
                return False

        if hostname == self.target:
            return True

        if self._is_local_target:
            return False

        return (
            self.allow_subdomains
            and hostname.endswith("." + self.target)
        )

    def require_in_scope(self, url_or_host: str) -> None:
        """Raise ScopeError if a URL/hostname is outside the allowed scope."""

        if not self.is_in_scope(url_or_host):
            raise ScopeError(
                f"Out-of-scope URL or hostname: {url_or_host}"
            )


def _is_loopback_address(hostname: str) -> bool:
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False