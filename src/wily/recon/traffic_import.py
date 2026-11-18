"""Import captured HTTP traffic (Burp Suite XML / HAR) as scan input.

Opt-in alternative to ``api_discovery.py`` for when the tester already has
a traffic capture and wants Wily to scan exactly those endpoints, seeded
with the auth tokens already observed. Strictly offline: only parses the
bytes/text handed to it, and feeds the extracted endpoints/tokens into the
same scan queue the orchestrator already loops over.

Extracts: deduplicated endpoint URLs; ``Authorization``/bearer tokens
(JWTs surfaced separately for the JWT module's ``--token`` path); and any
S3 URIs/URLs seen in the captured data.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET

__all__ = [
    "ImportedTraffic",
    "extract_bearer_token",
    "import_traffic",
    "looks_like_jwt",
    "parse_burp_xml",
    "parse_har",
]


# s3://bucket/key  OR  any http(s) URL whose host is an S3 endpoint.
_S3_LINK_RE = re.compile(
    r"""(?xi)
    (?:
        s3://[a-z0-9.\-]+(?:/[^\s"'<>]*)?        # s3://bucket/key
        |
        https?://[^\s"'<>]*?s3[.\-][^\s"'<>]*?amazonaws\.com[^\s"'<>]*  # virtual-host/path style
    )
    """
)

# Bearer token after an "Authorization:" header value (case-insensitive).
_BEARER_RE = re.compile(r"\bbearer\s+([^\s,;]+)", re.IGNORECASE)

# A JWT is three base64url segments separated by dots.
_JWT_RE = re.compile(r"^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$")

# First line of a raw HTTP request: "GET /path HTTP/1.1".
_REQUEST_LINE_RE = re.compile(
    r"^([A-Z]+)\s+(\S+)\s+HTTP/\d(?:\.\d)?\s*$", re.IGNORECASE
)


def looks_like_jwt(token: str) -> bool:
    """True when ``token`` has the three-segment shape of a JWT."""
    return bool(isinstance(token, str) and token.count(".") == 2 and _JWT_RE.match(token))


def extract_bearer_token(auth_header_value: str) -> str | None:
    """Return the token from an ``Authorization`` header value.

    Strips a leading ``Bearer `` scheme when present; otherwise returns the
    raw value (some APIs send a bare token). ``Basic``/``Digest`` and other
    non-token schemes are ignored (return ``None``).
    """
    if not isinstance(auth_header_value, str):
        return None
    value = auth_header_value.strip()
    if not value:
        return None
    match = _BEARER_RE.search(value)
    if match:
        return match.group(1).strip() or None
    lowered = value.lower()
    if lowered.startswith(("basic ", "digest ", "negotiate ", "ntlm ")):
        return None
    # A bare token (no recognised scheme, no spaces) - accept as-is.
    if " " not in value:
        return value
    return None


@dataclass
class ImportedTraffic:
    """Everything parsed out of an imported capture (all offline)."""

    endpoints: list[str] = field(default_factory=list)
    tokens: list[str] = field(default_factory=list)
    s3_links: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    source: str | None = None

    @property
    def jwt_tokens(self) -> list[str]:
        """The subset of tokens that look like JWTs (for the JWT module)."""
        return [t for t in self.tokens if looks_like_jwt(t)]

    def extend(self, other: ImportedTraffic) -> None:
        """Merge another result in, de-duplicating while preserving order."""
        self.endpoints = _dedup(self.endpoints + other.endpoints)
        self.tokens = _dedup(self.tokens + other.tokens)
        self.s3_links = _dedup(self.s3_links + other.s3_links)
        self.errors += other.errors


def _dedup(items: list[str]) -> list[str]:
    """Order-preserving de-duplication."""
    return list(dict.fromkeys(i for i in items if i))


def _read_text(source: str | bytes | Path) -> str:
    """Accept raw text, bytes, or a path and return decoded text.

    A ``str`` that names an existing file is read from disk; otherwise the
    ``str`` is treated as the capture content itself (handy for inline test
    fixtures). ``bytes``/``Path`` are read/decoded directly.
    """
    if isinstance(source, Path):
        return source.read_text(encoding="utf-8", errors="replace")
    if isinstance(source, bytes):
        return source.decode("utf-8", errors="replace")
    if isinstance(source, str):
        try:
            path = Path(source)
            if len(source) < 4096 and path.is_file():
                return path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass
        return source
    raise TypeError(f"Unsupported source type: {type(source)!r}")


def _collect_s3_links(*texts: str) -> list[str]:
    links: list[str] = []
    for text in texts:
        if not text:
            continue
        links.extend(m.group(0).rstrip(".,;)\"'") for m in _S3_LINK_RE.finditer(text))
    return links


def _parse_raw_http_request(raw: str) -> tuple[str | None, str | None, dict[str, str]]:
    """Parse a raw HTTP request into (method, request_target, headers)."""
    method: str | None = None
    target: str | None = None
    headers: dict[str, str] = {}
    lines = raw.replace("\r\n", "\n").split("\n")
    if lines:
        first = _REQUEST_LINE_RE.match(lines[0].strip())
        if first:
            method = first.group(1).upper()
            target = first.group(2)
    for line in lines[1:]:
        if not line.strip():
            break  # blank line -> headers end, body begins
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
    return method, target, headers


def _request_url(target: str | None, headers: dict[str, str], host_hint: str | None) -> str | None:
    """Reconstruct an absolute URL from a raw request target + Host header."""
    if not target:
        return None
    if target.lower().startswith(("http://", "https://")):
        return target
    host = headers.get("host") or host_hint
    if not host:
        return None
    # No wire-level TLS signal in a raw request; assume https (the common case
    # for anything carrying an Authorization header). The scope guard downstream
    # keys on hostname, not scheme.
    scheme = "https"
    if not target.startswith("/"):
        target = "/" + target
    return f"{scheme}://{host}{target}"


def parse_burp_xml(source: str | bytes | Path) -> ImportedTraffic:
    """Parse a Burp Suite "Save items" XML export.

    Shape: ``<items><item><url>..</url><host>..</host>
    <request base64="true">BASE64</request>..</item></items>``. The request is
    usually base64-encoded raw HTTP; we decode it to recover the method/path
    and the ``Authorization`` header, and fall back to the ``<url>`` element
    for the endpoint when present.
    """
    result = ImportedTraffic(source="burp")
    text = _read_text(source)
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        result.errors.append(f"Burp XML parse error: {exc}")
        return result

    items = root.findall(".//item") or ([root] if root.tag == "item" else [])
    for item in items:
        url_el = item.find("url")
        host_el = item.find("host")
        req_el = item.find("request")

        url = url_el.text.strip() if (url_el is not None and url_el.text) else None
        host_hint = host_el.text.strip() if (host_el is not None and host_el.text) else None

        raw_request = ""
        if req_el is not None and req_el.text:
            raw_request = _decode_maybe_base64(req_el.text, req_el.get("base64"))

        headers: dict[str, str] = {}
        if raw_request:
            _method, target, headers = _parse_raw_http_request(raw_request)
            if url is None:
                url = _request_url(target, headers, host_hint)

        if url:
            result.endpoints.append(url)

        auth = headers.get("authorization")
        if auth:
            token = extract_bearer_token(auth)
            if token:
                result.tokens.append(token)

        result.s3_links.extend(_collect_s3_links(url or "", raw_request))

    result.endpoints = _dedup(result.endpoints)
    result.tokens = _dedup(result.tokens)
    result.s3_links = _dedup(result.s3_links)
    return result


def _decode_maybe_base64(text: str, base64_attr: str | None) -> str:
    """Decode a Burp ``<request>`` body, honouring ``base64="true"``.

    Burp marks encoded elements with ``base64="true"``. When the attribute is
    missing we still try base64 and fall back to the literal text, so a
    hand-written or already-decoded fixture also works.
    """
    stripped = text.strip()
    wants_b64 = (base64_attr or "").lower() == "true"
    if wants_b64 or _REQUEST_LINE_RE.match(stripped.split("\n", 1)[0]) is None:
        try:
            return base64.b64decode(stripped, validate=False).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            if wants_b64:
                return ""
    return text


def parse_har(source: str | bytes | Path) -> ImportedTraffic:
    """Parse a HAR (HTTP Archive) capture.

    Shape: ``{"log": {"entries": [{"request": {"method","url","headers":
    [{"name","value"}], "postData": {"text": ...}}}]}}``.
    """
    result = ImportedTraffic(source="har")
    text = _read_text(source)
    try:
        data = json.loads(text)
    except (ValueError, TypeError) as exc:
        result.errors.append(f"HAR parse error: {exc}")
        return result

    log = data.get("log") if isinstance(data, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        result.errors.append("HAR has no log.entries array.")
        return result

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request")
        if not isinstance(request, dict):
            continue

        url = request.get("url")
        if isinstance(url, str) and url.strip():
            result.endpoints.append(url.strip())

        header_blob_parts: list[str] = []
        for header in request.get("headers", []) or []:
            if not isinstance(header, dict):
                continue
            name = str(header.get("name", "")).strip().lower()
            value = str(header.get("value", "")).strip()
            header_blob_parts.append(f"{name}: {value}")
            if name == "authorization" and value:
                token = extract_bearer_token(value)
                if token:
                    result.tokens.append(token)

        post_text = ""
        post_data = request.get("postData")
        if isinstance(post_data, dict) and isinstance(post_data.get("text"), str):
            post_text = post_data["text"]

        result.s3_links.extend(
            _collect_s3_links(url or "", "\n".join(header_blob_parts), post_text)
        )

    result.endpoints = _dedup(result.endpoints)
    result.tokens = _dedup(result.tokens)
    result.s3_links = _dedup(result.s3_links)
    return result


def import_traffic(
    burp_xml: str | bytes | Path | None = None,
    har: str | bytes | Path | None = None,
) -> ImportedTraffic:
    """Parse any combination of Burp XML and HAR inputs into one result."""
    combined = ImportedTraffic(
        source="+".join(s for s in (("burp" if burp_xml else None), ("har" if har else None)) if s)
        or None
    )
    if burp_xml is not None:
        combined.extend(parse_burp_xml(burp_xml))
    if har is not None:
        combined.extend(parse_har(har))
    return combined
