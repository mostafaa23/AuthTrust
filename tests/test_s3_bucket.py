"""Phase 3: S3 bucket misconfiguration scanner.

A scripted fake HTTP engine (keyed on the request URL) drives every case, so
there is no real network or AWS call. The scanner only ever sends GETs, which
these tests assert.
"""

from dataclasses import dataclass

from wily.scanners.s3_bucket import S3BucketScanner, S3BucketTarget, s3_base_url, s3_host_for

_ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"

_LIST_XML = (
    '<?xml version="1.0"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    "<Name>victim</Name><Contents><Key>secret.txt</Key></Contents></ListBucketResult>"
)

_ACL_READ_ONLY = (
    "<AccessControlPolicy><AccessControlList><Grant>"
    f"<Grantee><URI>{_ALL_USERS}</URI></Grantee><Permission>READ</Permission>"
    "</Grant></AccessControlList></AccessControlPolicy>"
)

_ACL_WRITABLE = (
    "<AccessControlPolicy><AccessControlList><Grant>"
    f"<Grantee><URI>{_ALL_USERS}</URI></Grantee><Permission>WRITE</Permission>"
    "</Grant></AccessControlList></AccessControlPolicy>"
)


@dataclass
class _Resp:
    status_code: int
    text: str = ""


class _FakeHttp:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url))
        for pattern, resp in self.routes.items():
            if pattern in url:
                return resp
        return _Resp(404, "<Error><Code>NoSuchKey</Code></Error>")


def test_host_and_url_helpers():
    assert s3_host_for("victim") == "victim.s3.amazonaws.com"
    # A dotted bucket name falls back to path-style.
    assert s3_host_for("my.victim") == "s3.amazonaws.com"
    assert s3_base_url("victim") == "https://victim.s3.amazonaws.com"
    assert s3_base_url("my.victim") == "https://s3.amazonaws.com/my.victim"


def test_public_listing_detected():
    http = _FakeHttp({"victim.s3.amazonaws.com/": _Resp(200, _LIST_XML)})
    findings = S3BucketScanner(http_engine=http).run(S3BucketTarget(bucket="victim"))
    cats = {f.category for f in findings}
    assert "s3-bucket-public-listing" in cats
    # Read-only: the scanner must never send a mutating method.
    assert all(method == "GET" for method, _ in http.calls)


def test_public_object_read_detected():
    http = _FakeHttp({
        "victim.s3.amazonaws.com/secret.txt": _Resp(200, "topsecret"),
    })
    findings = S3BucketScanner(http_engine=http).run(
        S3BucketTarget(bucket="victim", sample_object_key="secret.txt")
    )
    assert any(f.category == "s3-bucket-public-object" for f in findings)


def test_public_acl_detected_but_write_not_reported_without_confirm():
    http = _FakeHttp({"?acl": _Resp(200, _ACL_WRITABLE)})
    findings = S3BucketScanner(http_engine=http, confirm_writes=False).run(
        S3BucketTarget(bucket="victim")
    )
    cats = {f.category for f in findings}
    assert "s3-bucket-public-acl" in cats
    # Write exposure must NOT be concluded unless explicitly confirmed.
    assert "s3-bucket-public-writable" not in cats


def test_writable_inferred_from_acl_only_with_confirm():
    http = _FakeHttp({"?acl": _Resp(200, _ACL_WRITABLE)})
    findings = S3BucketScanner(http_engine=http, confirm_writes=True).run(
        S3BucketTarget(bucket="victim")
    )
    writable = [f for f in findings if f.category == "s3-bucket-public-writable"]
    assert writable
    ev = writable[0].evidence
    assert ev["check"] == "write_permission_inferred_from_acl"
    assert ev["inferred_write_grant"]  # non-empty list of granted perms
    # Still only GETs - the "writable" conclusion came from reading the ACL.
    assert all(method == "GET" for method, _ in http.calls)


def test_read_only_acl_is_not_writable_even_with_confirm():
    http = _FakeHttp({"?acl": _Resp(200, _ACL_READ_ONLY)})
    findings = S3BucketScanner(http_engine=http, confirm_writes=True).run(
        S3BucketTarget(bucket="victim")
    )
    cats = {f.category for f in findings}
    assert "s3-bucket-public-acl" in cats
    assert "s3-bucket-public-writable" not in cats


def test_private_bucket_yields_nothing():
    http = _FakeHttp({
        "victim": _Resp(403, "<Error><Code>AccessDenied</Code></Error>"),
    })
    findings = S3BucketScanner(http_engine=http).run(S3BucketTarget(bucket="victim"))
    assert findings == []
