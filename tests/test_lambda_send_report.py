"""Phase 5 Lambda handler tests (offline, mocked client - no real SES/S3/network).

Loads lambda/send_report/handler.py by path ('lambda' is a Python keyword, so
it can't be imported as a normal module). Verifies env-var/event-driven config,
redaction-agnostic attachment building, S3 + inline + direct-invoke shapes, and
that NO address is hardcoded.
"""

import base64
import importlib.util
from email import message_from_string
from pathlib import Path

import pytest

_HANDLER_PATH = (
    Path(__file__).resolve().parents[1] / "lambda" / "send_report" / "handler.py"
)


def _load_handler():
    spec = importlib.util.spec_from_file_location("wily_send_report_handler", _HANDLER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _FakeSes:
    def __init__(self):
        self.calls = []

    def send_raw_email(self, **kwargs):
        self.calls.append(kwargs)
        return {"MessageId": "fake-message-id"}


class _FakeS3:
    def __init__(self, body=b"", metadata=None):
        self._body = body
        self._metadata = metadata or {}

    def get_object(self, Bucket, Key):  # noqa: N803 - boto3 kwarg casing
        class _Body:
            def __init__(self, data):
                self._data = data

            def read(self):
                return self._data

        return {"Body": _Body(self._body), "Metadata": self._metadata}


@pytest.fixture
def handler_mod(monkeypatch):
    mod = _load_handler()
    fake_ses = _FakeSes()

    def _fake_client(service, region=None):
        if service == "ses":
            return fake_ses
        raise AssertionError(f"unexpected service {service}")

    monkeypatch.setattr(mod, "_boto3_client", _fake_client)
    mod._fake_ses = fake_ses  # stash for assertions
    return mod


def test_no_hardcoded_email_in_source():
    # No literal address pattern "<word>@<word>.<tld>" anywhere in the handler:
    # recipient/sender are configured purely via env vars / the event.
    import re

    source = _HANDLER_PATH.read_text(encoding="utf-8")
    assert not re.search(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", source)


def test_requires_sender(handler_mod, monkeypatch):
    monkeypatch.delenv("SES_SENDER_EMAIL", raising=False)
    with pytest.raises(handler_mod.ReportEmailError):
        handler_mod.handler({"report": {"content": "{}"}}, None)


def test_requires_recipient(handler_mod, monkeypatch):
    monkeypatch.setenv("SES_SENDER_EMAIL", "sender@test.local")
    monkeypatch.delenv("REPORT_RECIPIENT_EMAIL", raising=False)
    with pytest.raises(handler_mod.ReportEmailError):
        handler_mod.handler({"report": {"content": "{}"}}, None)


def test_inline_report_sent(handler_mod, monkeypatch):
    monkeypatch.setenv("SES_SENDER_EMAIL", "sender@test.local")
    monkeypatch.setenv("REPORT_RECIPIENT_EMAIL", "rcpt@test.local")
    event = {"report": {"filename": "wily-report.json", "content": '{"findings": []}'}}
    result = handler_mod.handler(event, None)

    assert result["status"] == "sent"
    assert result["attachment"] == "wily-report.json"
    assert result["message_id"] == "fake-message-id"

    call = handler_mod._fake_ses.calls[0]
    assert call["Source"] == "sender@test.local"
    assert call["Destinations"] == ["rcpt@test.local"]
    msg = message_from_string(call["RawMessage"]["Data"])
    assert msg["To"] == "rcpt@test.local"
    # The attachment carries the report content.
    parts = [p for p in msg.walk() if p.get_filename() == "wily-report.json"]
    assert parts and b'"findings"' in parts[0].get_payload(decode=True)


def test_event_recipient_overrides_env(handler_mod, monkeypatch):
    monkeypatch.setenv("SES_SENDER_EMAIL", "sender@test.local")
    monkeypatch.setenv("REPORT_RECIPIENT_EMAIL", "default@test.local")
    event = {
        "recipient": "override@test.local",
        "subject": "Custom subject",
        "report": {"content": "{}"},
    }
    handler_mod.handler(event, None)
    call = handler_mod._fake_ses.calls[0]
    assert call["Destinations"] == ["override@test.local"]
    msg = message_from_string(call["RawMessage"]["Data"])
    assert msg["Subject"] == "Custom subject"


def test_base64_inline_content(handler_mod, monkeypatch):
    monkeypatch.setenv("SES_SENDER_EMAIL", "sender@test.local")
    monkeypatch.setenv("REPORT_RECIPIENT_EMAIL", "rcpt@test.local")
    raw = base64.b64encode(b"<html>report</html>").decode()
    event = {"report": {"filename": "r.html", "content": raw, "encoding": "base64"}}
    handler_mod.handler(event, None)
    call = handler_mod._fake_ses.calls[0]
    msg = message_from_string(call["RawMessage"]["Data"])
    parts = [p for p in msg.walk() if p.get_filename() == "r.html"]
    assert parts and parts[0].get_payload(decode=True) == b"<html>report</html>"


def test_s3_event_fetches_object(monkeypatch):
    mod = _load_handler()
    fake_ses = _FakeSes()
    fake_s3 = _FakeS3(body=b"{}", metadata={"recipient": "meta@test.local"})

    def _fake_client(service, region=None):
        return fake_ses if service == "ses" else fake_s3

    monkeypatch.setattr(mod, "_boto3_client", _fake_client)
    monkeypatch.setenv("SES_SENDER_EMAIL", "sender@test.local")
    monkeypatch.delenv("REPORT_RECIPIENT_EMAIL", raising=False)

    event = {
        "Records": [
            {"s3": {"bucket": {"name": "wily-reports"}, "object": {"key": "run/report.html"}}}
        ]
    }
    result = mod.handler(event, None)
    assert result["attachment"] == "report.html"
    # Recipient resolved from the S3 object metadata.
    assert fake_ses.calls[0]["Destinations"] == ["meta@test.local"]
