"""Phase 0 robustness fixes:
  - JwtTamperScanner must not crash when the sample token is not a decodable
    JWT (the expiry-claim analysis used to run unguarded).
  - run_full_scan must not abort when the IAM authorization-details file is
    malformed - it should skip IAM and still produce a report.
"""

import asyncio
from dataclasses import dataclass

from wily.cli.commands import scan_all
from wily.scanners.jwt_tamper import JwtTamperScanner, JwtTarget


@dataclass
class _Resp:
    status_code: int
    text: str = ""


class _FakeHttp:
    def request(self, method, url, headers=None, body=None):
        # Protected endpoint: 200 with a token present, 401 with none.
        if (headers or {}).get("Authorization"):
            return _Resp(200, '{"ok":true}')
        return _Resp(401, "unauthorized")

    def similarity(self, a, b):
        return 0.0


def test_jwt_scanner_survives_non_jwt_token():
    scanner = JwtTamperScanner(scope_manager=None, http_engine=_FakeHttp())
    target = JwtTarget(url="https://example.com/api", sample_token="opaque-not-a-jwt")
    # Must return cleanly (no exception) even though the token can't be decoded.
    findings = scanner.run(target)
    assert findings == []


def test_scan_survives_malformed_iam_file(tmp_path):
    bad = tmp_path / "auth.json"
    bad.write_text("{ this is not valid json", encoding="utf-8")
    out = tmp_path / "report.json"

    # domain empty + only a (broken) IAM file: the IAM block must be caught
    # and the scan must still finish and write a report.
    asyncio.run(
        scan_all.run_full_scan(
            domain="",
            token=None,
            identities_raw=[],
            iam_file=str(bad),
            allow_local=False,
            blind=False,
            output=str(out),
        )
    )
    assert out.exists()
