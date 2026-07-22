"""Tests for privacy-safe diagnostics."""

import json

from click.testing import CliRunner

from xhs_cli.cli import cli
from xhs_cli.commands import diagnostics

runner = CliRunner()


def test_doctor_json_never_contains_credentials(monkeypatch):
    secret = "secret-cookie-value"
    monkeypatch.setattr(diagnostics, "load_saved_cookies", lambda: {"a1": secret})
    monkeypatch.setattr(diagnostics, "_cookie_check", lambda: {"status": "ok", "has_required_cookie": True})
    monkeypatch.setattr(diagnostics, "_available_browsers", lambda: ("chrome",))

    result = runner.invoke(cli, ["doctor", "--json"])

    assert result.exit_code == 0
    assert secret not in result.output
    assert json.loads(result.output)["data"]["checks"]["api"]["status"] == "skipped"


def test_network_check_sends_only_transport_cookies(monkeypatch):
    captured = {}

    class FakeClient:
        def __init__(self, cookies):
            captured.update(cookies)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get_self_info(self):
            return {"nickname": "tester"}

    monkeypatch.setattr(
        diagnostics,
        "load_saved_cookies",
        lambda: {"a1": "secret", "web_session": "session", "saved_at": 123.0, "nickname": "local"},
    )
    monkeypatch.setattr(diagnostics, "XhsClient", FakeClient)
    monkeypatch.setattr(diagnostics, "_cookie_check", lambda: {"status": "ok"})
    monkeypatch.setattr(diagnostics, "_available_browsers", lambda: ())

    report = diagnostics.collect_diagnostics(check_api=True)

    assert report["checks"]["api"]["status"] == "ok"
    assert captured == {"a1": "secret", "web_session": "session"}


def test_support_bundle_is_redacted_and_private(monkeypatch, tmp_path):
    secret = "secret-cookie-value"
    monkeypatch.setattr(diagnostics, "load_saved_cookies", lambda: {"a1": secret})
    monkeypatch.setattr(diagnostics, "_cookie_check", lambda: {"status": "ok", "has_required_cookie": True})
    monkeypatch.setattr(diagnostics, "_available_browsers", lambda: ("chrome",))
    output = tmp_path / "bundle.json"

    result = runner.invoke(cli, ["support-bundle", str(output), "--json"])

    assert result.exit_code == 0
    content = output.read_text()
    assert secret not in content
    assert output.stat().st_mode & 0o777 == 0o600
    assert json.loads(content)["data"]["privacy"]["contains_cookie_values"] is False
