from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

try:  # Optional: YAML scope-config files work only when PyYAML is installed.
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - JSON config always works regardless
    yaml = None


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


# ---------------------------------------------------------------------------
# S3 bucket scope
# ---------------------------------------------------------------------------
#
# A second scope dimension beside domains/CIDRs: a list of S3 bucket names or
# glob patterns (e.g. "target-*", "company-assets"). Discovery/parsers that
# surface an ``s3://bucket/key`` URI or a ``*.s3*.amazonaws.com`` URL can ask
# whether that bucket is one we are authorized to look at, instead of treating
# every AWS bucket on the internet as in scope.


def extract_bucket_name(value: str) -> str | None:
    """Pull the bucket name out of an ``s3://`` URI or an S3 HTTP(S) URL.

    Handles both addressing styles AWS uses:
      * virtual-hosted  - ``bucket.s3.amazonaws.com`` /
                          ``bucket.s3.<region>.amazonaws.com`` /
                          ``bucket.s3-<region>.amazonaws.com`` (incl.
                          dualstack and ``s3-website`` hosts)
      * path-style      - ``s3.amazonaws.com/bucket/key`` /
                          ``s3.<region>.amazonaws.com/bucket``
      * ``s3://bucket/key`` URIs

    Returns ``None`` for anything that is not recognisably an S3 reference
    (a bare bucket *name* with no scheme/host is intentionally not treated as
    an S3 URL here - callers decide whether to accept a raw name).
    """
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v:
        return None

    if v.lower().startswith("s3://"):
        rest = v[5:].lstrip("/")
        bucket = rest.split("/", 1)[0].split("?", 1)[0].strip().lower()
        return bucket or None

    if "://" in v:
        parsed = urlsplit(v)
    elif "amazonaws.com" in v.lower():
        # Bare host like "bucket.s3.amazonaws.com/..." with no scheme.
        parsed = urlsplit("//" + v)
    else:
        return None

    host = (parsed.hostname or "").lower()
    if not host.endswith("amazonaws.com"):
        return None

    labels = host.split(".")
    for i, label in enumerate(labels):
        if label == "s3" or label.startswith("s3-"):
            if i > 0:
                # Virtual-hosted: everything before the s3 label is the bucket.
                return ".".join(labels[:i]) or None
            # Path-style: the first path segment is the bucket.
            segment = (parsed.path or "").lstrip("/").split("/", 1)[0]
            return segment.strip().lower() or None
    return None


def _looks_like_bare_bucket_name(value: str) -> bool:
    """True when ``value`` is plausibly a raw bucket name (not a URL/host)."""
    v = value.strip().lower()
    if not v or "://" in v or "/" in v or "amazonaws.com" in v:
        return False
    # S3 bucket naming: 3-63 chars, lowercase letters/digits/dots/hyphens.
    return bool(re.fullmatch(r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]", v))


def bucket_in_scope(value: str, patterns: tuple[str, ...]) -> bool:
    """Return True when ``value``'s bucket matches any configured pattern.

    ``value`` may be a bucket name, an ``s3://`` URI or an S3 URL. With no
    patterns configured there is no bucket scope, so nothing matches.
    """
    if not patterns:
        return False
    bucket = extract_bucket_name(value)
    if bucket is None:
        if _looks_like_bare_bucket_name(value):
            bucket = value.strip().lower()
        else:
            return False
    return any(fnmatch.fnmatchcase(bucket, pattern) for pattern in patterns)


# ---------------------------------------------------------------------------
# AWS account / ARN scope
# ---------------------------------------------------------------------------
#
# A restriction (not an inclusion) list: keep the IAM analyzer from reasoning
# about principals that live in a third-party account that happened to end up
# in an exported authorization-details file. With no account scope configured
# there is no restriction (the common case - the user exported their own
# account), so everything passes.

_ACCOUNT_ID_RE = re.compile(r"\b(\d{12})\b")


def extract_account_id(value: str) -> str | None:
    """Extract the 12-digit AWS account id from an account id or an ARN."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if re.fullmatch(r"\d{12}", v):
        return v
    if v.lower().startswith("arn:"):
        # arn:partition:service:region:account-id:resource
        parts = v.split(":")
        if len(parts) >= 5 and re.fullmatch(r"\d{12}", parts[4]):
            return parts[4]
    match = _ACCOUNT_ID_RE.search(v)
    return match.group(1) if match else None


def account_in_scope(value: str, accounts: tuple[str, ...]) -> bool:
    """Return True when ``value`` (an ARN or account id) is in account scope.

    Each configured entry may be a bare 12-digit account id (e.g.
    ``123456789012``) or an ARN / ARN glob prefix (e.g.
    ``arn:aws:iam::123456789012:*``). With no entries configured the account
    scope imposes no restriction and every value passes.
    """
    if not accounts:
        return True
    if not isinstance(value, str):
        return False
    candidate = value.strip()
    candidate_account = extract_account_id(candidate)
    for raw in accounts:
        entry = raw.strip()
        if not entry:
            continue
        if re.fullmatch(r"\d{12}", entry):
            if candidate_account == entry:
                return True
            continue
        if ("*" in entry or "?" in entry) and fnmatch.fnmatchcase(candidate, entry):
            return True
        if candidate == entry:
            return True
        entry_account = extract_account_id(entry)
        if candidate_account and entry_account and candidate_account == entry_account:
            return True
    return False


# ---------------------------------------------------------------------------
# Scope config file
# ---------------------------------------------------------------------------


def load_scope_config(path: str | Path) -> dict[str, tuple[str, ...]]:
    """Load a JSON (or YAML, if PyYAML is installed) scope-config file.

    Recognised keys (aliases accepted): ``buckets``/``s3_buckets``,
    ``accounts``/``aws_accounts``, ``exclude``/``excluded_hosts``. Returns a
    dict of ``{"buckets": (...), "accounts": (...), "exclude": (...)}`` with
    every list normalised to a tuple of non-empty strings.
    """
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except ValueError:
        if yaml is None:
            raise ScopeError(
                f"Scope config {path} is not valid JSON "
                "(install PyYAML to use a YAML config)."
            )
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ScopeError(f"Scope config {path} is not valid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ScopeError(f"Scope config {path} must be a mapping/object.")

    def _list(*keys: str) -> tuple[str, ...]:
        for key in keys:
            raw = data.get(key)
            if isinstance(raw, list):
                return tuple(str(x).strip() for x in raw if str(x).strip())
            if isinstance(raw, str) and raw.strip():
                return (raw.strip(),)
        return ()

    return {
        "buckets": _list("buckets", "s3_buckets"),
        "accounts": _list("accounts", "aws_accounts"),
        "exclude": _list("exclude", "excluded_hosts", "excluded"),
    }


class ScopeManager:
    """Checks whether a hostname belongs to the authorized target scope."""

    def __init__(
        self,
        target: str,
        *,
        allow_subdomains: bool = True,
        excluded_hosts: tuple[str, ...] = (),
        allow_local_targets: bool = False,
        s3_buckets: tuple[str, ...] = (),
        aws_accounts: tuple[str, ...] = (),
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
        # Second/third scope dimensions (opt-in, additive - the domain scope
        # above is unaffected when these are left empty).
        self.s3_buckets = tuple(
            b.strip().lower() for b in s3_buckets if isinstance(b, str) and b.strip()
        )
        self.aws_accounts = tuple(
            a.strip() for a in aws_accounts if isinstance(a, str) and a.strip()
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

    # -- S3 bucket scope ----------------------------------------------------

    @property
    def has_bucket_scope(self) -> bool:
        """True when at least one S3 bucket name/pattern was configured."""
        return bool(self.s3_buckets)

    def is_bucket_in_scope(self, bucket_or_url: str) -> bool:
        """Return True when a bucket name / ``s3://`` URI / S3 URL is in scope.

        With no bucket scope configured this returns False (there is no bucket
        scope to be inside of); callers that want "report every S3 link I find"
        behaviour should check :attr:`has_bucket_scope` first.
        """
        return bucket_in_scope(bucket_or_url, self.s3_buckets)

    # -- AWS account / ARN scope -------------------------------------------

    @property
    def has_account_scope(self) -> bool:
        """True when at least one account id / ARN prefix was configured."""
        return bool(self.aws_accounts)

    def is_account_in_scope(self, arn_or_account: str) -> bool:
        """Return True when an ARN or account id is within the account scope.

        This is the helper the IAM path calls to avoid analysing principals
        that belong to a third-party account. With no account scope configured
        it imposes no restriction and returns True for everything.
        """
        return account_in_scope(arn_or_account, self.aws_accounts)


def _is_loopback_address(hostname: str) -> bool:
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False