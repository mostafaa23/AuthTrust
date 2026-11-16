"""Phase 1 (part 2): offline parsing of imported traffic (Burp XML / HAR).

Everything here is a small inline fixture - nothing is fetched or replayed.
"""

import base64
import json

from wily.recon.traffic_import import (
    ImportedTraffic,
    extract_bearer_token,
    import_traffic,
    looks_like_jwt,
    parse_burp_xml,
    parse_har,
)

# A realistic-looking (but fake) JWT: header.payload.signature, all base64url.
FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0IiwibmFtZSI6IkFsaWNlIn0"
    ".c2lnbmF0dXJlX2hlcmU"
)


def _burp_item(method: str, path: str, host: str, *, auth: str | None = None) -> str:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    if auth:
        lines.append(f"Authorization: {auth}")
    lines.append("")  # end of headers
    raw = "\r\n".join(lines)
    b64 = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return (
        "<item>"
        f"<url>https://{host}{path}</url>"
        f"<host>{host}</host>"
        f'<request base64="true">{b64}</request>'
        "</item>"
    )


def _burp_doc(*items: str) -> str:
    return "<items>" + "".join(items) + "</items>"


# --- Burp XML --------------------------------------------------------------


def test_parse_burp_xml_endpoints_and_token():
    doc = _burp_doc(
        _burp_item("GET", "/api/v1/users", "api.target.com"),
        _burp_item("POST", "/api/v1/login", "api.target.com", auth=f"Bearer {FAKE_JWT}"),
    )
    result = parse_burp_xml(doc)
    assert "https://api.target.com/api/v1/users" in result.endpoints
    assert "https://api.target.com/api/v1/login" in result.endpoints
    assert FAKE_JWT in result.tokens
    assert result.jwt_tokens == [FAKE_JWT]
    assert result.errors == []


def test_parse_burp_xml_reconstructs_url_from_request_when_url_missing():
    # No <url> element - the URL must come from the request line + Host header.
    raw = "GET /only/in/request HTTP/1.1\r\nHost: recon.target.com\r\n\r\n"
    b64 = base64.b64encode(raw.encode()).decode()
    doc = f'<items><item><request base64="true">{b64}</request></item></items>'
    result = parse_burp_xml(doc)
    assert result.endpoints == ["https://recon.target.com/only/in/request"]


def test_parse_burp_xml_extracts_s3_links():
    raw = (
        "GET /x HTTP/1.1\r\nHost: target.com\r\n"
        "Referer: https://target-assets.s3.amazonaws.com/logo.png\r\n\r\n"
    )
    b64 = base64.b64encode(raw.encode()).decode()
    doc = f'<items><item><url>https://target.com/x</url><request base64="true">{b64}</request></item></items>'
    result = parse_burp_xml(doc)
    assert "https://target-assets.s3.amazonaws.com/logo.png" in result.s3_links


def test_parse_burp_xml_malformed_is_reported_not_raised():
    result = parse_burp_xml("<items><item><url>oops")  # truncated XML
    assert result.endpoints == []
    assert result.errors and "parse error" in result.errors[0].lower()


# --- HAR -------------------------------------------------------------------


def _har(*entries: dict) -> str:
    return json.dumps({"log": {"version": "1.2", "entries": list(entries)}})


def test_parse_har_endpoints_tokens_and_s3():
    doc = _har(
        {
            "request": {
                "method": "GET",
                "url": "https://api.target.com/api/orders",
                "headers": [
                    {"name": "Authorization", "value": f"Bearer {FAKE_JWT}"},
                    {"name": "Accept", "value": "application/json"},
                ],
            }
        },
        {
            "request": {
                "method": "POST",
                "url": "https://api.target.com/api/upload",
                "headers": [
                    {"name": "X-Amz-Source", "value": "s3://target-uploads/incoming"},
                ],
                "postData": {"text": "{\"dest\": \"s3://target-uploads/dest\"}"},
            }
        },
    )
    result = parse_har(doc)
    assert "https://api.target.com/api/orders" in result.endpoints
    assert "https://api.target.com/api/upload" in result.endpoints
    assert FAKE_JWT in result.tokens
    assert "s3://target-uploads/incoming" in result.s3_links
    assert "s3://target-uploads/dest" in result.s3_links


def test_parse_har_missing_entries_is_reported():
    result = parse_har(json.dumps({"log": {}}))
    assert result.endpoints == []
    assert result.errors


def test_parse_har_bad_json_is_reported_not_raised():
    result = parse_har("{not json")
    assert result.endpoints == []
    assert result.errors and "parse error" in result.errors[0].lower()


# --- Combined / helpers ----------------------------------------------------


def test_import_traffic_merges_and_dedups():
    burp = _burp_doc(_burp_item("GET", "/shared", "target.com", auth=f"Bearer {FAKE_JWT}"))
    har = _har({"request": {"method": "GET", "url": "https://target.com/shared", "headers": []}})
    result = import_traffic(burp_xml=burp, har=har)
    # Same endpoint from both sources appears once.
    assert result.endpoints.count("https://target.com/shared") == 1
    assert result.jwt_tokens == [FAKE_JWT]


def test_extract_bearer_token():
    assert extract_bearer_token(f"Bearer {FAKE_JWT}") == FAKE_JWT
    assert extract_bearer_token("bearer abc123") == "abc123"
    assert extract_bearer_token("rawtokenvalue") == "rawtokenvalue"
    assert extract_bearer_token("Basic dXNlcjpwYXNz") is None
    assert extract_bearer_token("") is None


def test_looks_like_jwt():
    assert looks_like_jwt(FAKE_JWT) is True
    assert looks_like_jwt("not.a.jwt.extra") is False
    assert looks_like_jwt("single") is False


def test_empty_import_is_harmless():
    result = ImportedTraffic()
    assert result.endpoints == []
    assert result.jwt_tokens == []
