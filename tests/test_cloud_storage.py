"""Phase: multi-cloud storage enumeration scanner (scanners/cloud_storage.py).

A scripted fake HTTP engine (keyed on request URL) drives AWS / Azure / GCP
cases offline. Asserts detection-only (GET only) and correct open/protected
classification per provider.
"""

from dataclasses import dataclass, field

from wily.scanners.cloud_storage import CloudStorageScanner, CloudStorageTarget

_AZURE_LIST = '<?xml version="1.0"?><EnumerationResults><Blobs><Blob><Name>x</Name></Blob></Blobs></EnumerationResults>'


@dataclass
class _Resp:
    status_code: int
    text: str = ""
    headers: dict = field(default_factory=dict)


class _FakeHttp:
    def __init__(self, routes, default=None):
        self.routes = routes
        self.default = default or _Resp(404, "<Error><Code>NoSuchKey</Code></Error>")
        self.calls = []

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url))
        for pattern, resp in self.routes.items():
            if pattern in url:
                return resp
        return self.default


def _scanner(http):
    return CloudStorageScanner(http_engine=http)


def test_open_s3_bucket_detected():
    http = _FakeHttp({"victim.s3.amazonaws.com/": _Resp(200, "<ListBucketResult/>")})
    findings = _scanner(http).run(CloudStorageTarget(name="victim", providers=("aws",)))
    assert any(f.category == "cloud-storage-s3-open" for f in findings)
    assert all(m == "GET" for m, _ in http.calls)


def test_protected_s3_bucket_detected_as_low():
    http = _FakeHttp({"victim.s3.amazonaws.com/": _Resp(403, "<Error><Code>AccessDenied</Code></Error>")})
    findings = _scanner(http).run(CloudStorageTarget(name="victim", providers=("aws",)))
    f = next(f for f in findings if f.category == "cloud-storage-s3-protected")
    assert f.severity == "low"
    assert f.evidence["access"] == "protected"


def test_nonexistent_s3_bucket_yields_nothing():
    http = _FakeHttp({}, default=_Resp(404, "<Error><Code>NoSuchBucket</Code></Error>"))
    findings = _scanner(http).run(CloudStorageTarget(name="victim", providers=("aws",)))
    assert findings == []


def test_open_gcp_bucket_detected():
    http = _FakeHttp({"storage.googleapis.com/victim": _Resp(200, "<ListBucketResult/>")})
    findings = _scanner(http).run(CloudStorageTarget(name="victim", providers=("gcp",)))
    assert any(f.category == "cloud-storage-gcp-bucket-open" for f in findings)


def test_protected_gcp_bucket_detected():
    http = _FakeHttp({"storage.googleapis.com/victim": _Resp(403, "AccessDenied")})
    findings = _scanner(http).run(CloudStorageTarget(name="victim", providers=("gcp",)))
    assert any(f.category == "cloud-storage-gcp-bucket-protected" for f in findings)


def test_azure_open_container_detected():
    http = _FakeHttp({
        # account root exists (auth-required = exists), container 'backup' is open
        "victim.blob.core.windows.net/backup/?restype=container&comp=list": _Resp(200, _AZURE_LIST),
        "victim.blob.core.windows.net/": _Resp(
            400, "Value for one of the query parameters specified in the request URI is invalid"
        ),
    })
    findings = _scanner(http).run(
        CloudStorageTarget(name="victim", providers=("azure",), azure_containers=("backup",))
    )
    cats = {f.category for f in findings}
    assert "cloud-storage-azure-account" in cats
    assert "cloud-storage-azure-blob-open" in cats
    blob = next(f for f in findings if f.category == "cloud-storage-azure-blob-open")
    assert blob.evidence["container"] == "backup"


def test_azure_disabled_account_not_reported():
    http = _FakeHttp({
        "victim.blob.core.windows.net/": _Resp(409, "The specified account is disabled"),
    })
    findings = _scanner(http).run(CloudStorageTarget(name="victim", providers=("azure",)))
    assert findings == []


def test_azure_name_with_separators_is_reduced():
    # "ac-me" -> azure account "acme"; the probe must hit the reduced host.
    http = _FakeHttp({
        "acme.blob.core.windows.net/": _Resp(401, "Server failed to authenticate the request"),
    })
    findings = _scanner(http).run(CloudStorageTarget(name="ac-me", providers=("azure",)))
    assert any(f.category == "cloud-storage-azure-account" for f in findings)
    assert all("acme.blob.core.windows.net" in url for _, url in http.calls)
