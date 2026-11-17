"""Phase 3: API-keys / secrets exposure scanner.

Driven entirely through provided text sources (offline), plus one fake-HTTP
case for the JS-fetch path. Asserts that the raw secret is never stored in the
finding (only a masked indicator) and that detection never authenticates.
"""

from dataclasses import dataclass

from wily.report.json_report import export_json
from wily.scanners.secret_scan import SecretScanScanner, SecretScanTarget, SecretSource

_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
_JS_WITH_SECRETS = f"""
(function(){{
  var cfg = {{ accessKeyId: "{_AWS_KEY}", region: "us-east-1" }};
  var gh = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12";
  fetch("/api", {{ headers: {{ Authorization: "Bearer averylongbearertoken123" }} }});
}})();
"""


@dataclass
class _Resp:
    status_code: int
    text: str = ""


class _FakeHttp:
    def __init__(self, body):
        self.body = body
        self.calls = []

    def request(self, method, url, headers=None, body=None):
        self.calls.append((method, url))
        return _Resp(200, self.body)


def test_detects_secrets_in_provided_source():
    target = SecretScanTarget(
        sources=[SecretSource(label="app.js", content=_JS_WITH_SECRETS, location="https://x/app.js")]
    )
    findings = SecretScanScanner().run(target)
    kinds = {f.evidence["secret_kind"] for f in findings}
    assert "aws_access_key_id" in kinds
    assert "github_token" in kinds


def test_raw_secret_never_stored_in_evidence():
    target = SecretScanTarget(
        sources=[SecretSource(label="app.js", content=_JS_WITH_SECRETS)]
    )
    findings = SecretScanScanner().run(target)
    aws = next(f for f in findings if f.evidence["secret_kind"] == "aws_access_key_id")
    # The full key is masked, not present anywhere in the evidence.
    blob = repr(aws.evidence)
    assert _AWS_KEY not in blob
    assert aws.evidence["masked_secret"].startswith("AKIA")
    assert aws.evidence["is_live_cloud_credential"] is True


def test_secret_survives_report_redaction_as_masked_only(tmp_path):
    target = SecretScanTarget(
        sources=[SecretSource(label="app.js", content=_JS_WITH_SECRETS)]
    )
    findings = SecretScanScanner().run(target)
    # Even with redaction OFF (--show-leak), the raw key is not in the report,
    # because the scanner never stored it in the first place.
    path = export_json(findings, tmp_path / "r.json", redact=False)
    assert _AWS_KEY not in path.read_text(encoding="utf-8")


def test_fetch_urls_scanned_via_http_engine():
    http = _FakeHttp(_JS_WITH_SECRETS)
    target = SecretScanTarget(fetch_urls=["https://x/bundle.js"])
    # scope=None -> no scope filtering; the fake engine returns the JS body.
    findings = SecretScanScanner(scope_manager=None, http_engine=http).run(target)
    assert any(f.evidence["secret_kind"] == "aws_access_key_id" for f in findings)
    assert http.calls and http.calls[0][0] == "GET"  # detection only reads


def test_clean_source_yields_nothing():
    target = SecretScanTarget(
        sources=[SecretSource(label="clean.js", content="const x = 1; // nothing secret here")]
    )
    assert SecretScanScanner().run(target) == []


def test_duplicate_secret_across_sources_reported_once():
    src = SecretSource(label="a.js", content=f'key="{_AWS_KEY}"')
    src2 = SecretSource(label="b.js", content=f'key="{_AWS_KEY}"')
    findings = SecretScanScanner().run(SecretScanTarget(sources=[src, src2]))
    aws = [f for f in findings if f.evidence["secret_kind"] == "aws_access_key_id"]
    assert len(aws) == 1
