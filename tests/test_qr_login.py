"""QR confirmation is not login: verify the session, never save from the library."""

import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from xhs_cli.qr_login import (
    QR_CREATE_ENDPOINT,
    QR_STATUS_ENDPOINT,
    QR_USERINFO_ENDPOINT,
    QrLoginError,
    _cookies,
    _render_qr,
    qrcode_login,
)


def response(path, payload, method="GET", status=200, host="edith.xiaohongshu.com"):
    return SimpleNamespace(
        url="https://" + host + path,
        request=SimpleNamespace(method=method),
        status=status,
        json=lambda: {"success": True, "data": payload},
    )


def events():
    return [
        response(QR_CREATE_ENDPOINT, {"url": "secret-qr"}, "POST"),
        response(QR_USERINFO_ENDPOINT, {"codeStatus": 2, "userId": "ours"}),
        response(QR_STATUS_ENDPOINT, {"login_info": {"user_id": "ours", "session": "secret-session"}}),
    ]


@pytest.fixture
def scenario(tmp_path, monkeypatch):
    state = SimpleNamespace(
        events=events(),
        cookies=[
            {"name": "a1", "value": "secret-a1", "domain": ".xiaohongshu.com"},
            {"name": "webId", "value": "secret-webid", "domain": ".xiaohongshu.com"},
        ],
        user={"user_id": "ours", "guest": False},
        closed=[],
        rendered=[],
        status=[],
        immediate=False,
        api_error=None,
        callback=None,
        cookie_path=tmp_path / ".xiaohongshu-cli" / "cookies.json",
    )
    monkeypatch.setenv("HOME", str(tmp_path))

    class Page:
        context = SimpleNamespace(cookies=lambda: state.cookies)

        def on(self, event, callback):
            assert event == "response"
            state.callback = callback

        def goto(self, *args, **kwargs):
            if state.immediate:
                while state.events:
                    state.callback(state.events.pop(0))

        def wait_for_timeout(self, _timeout):
            if state.events:
                state.callback(state.events.pop(0))

    @contextmanager
    def browser():
        try:
            yield Page()
        finally:
            state.closed.append("browser")

    class Client:
        def __init__(self, cookies, **kwargs):
            assert cookies["web_session"] == "secret-session"
            assert kwargs["max_retries"] == 1

        def __enter__(self):
            return self

        def __exit__(self, *args):
            state.closed.append("client")

        def get_self_info(self):
            if state.api_error:
                raise state.api_error
            return state.user

    monkeypatch.setattr("xhs_cli.qr_login.browser_page", browser)
    monkeypatch.setattr("xhs_cli.qr_login.XhsClient", Client)
    return state


def run(state, **kwargs):
    return qrcode_login(on_qr=state.rendered.append, on_status=state.status.append, **kwargs)


@pytest.mark.parametrize("immediate", [False, True])
def test_confirmed_verified_login_returns_without_saving_or_losing_fast_events(scenario, immediate):
    scenario.immediate = immediate
    result = run(scenario)
    assert result.cookies["web_session"] == "secret-session"
    assert result.user["user_id"] == "ours"
    assert scenario.rendered == ["secret-qr"]
    assert scenario.closed == ["browser", "client"]
    assert not scenario.cookie_path.exists()
    assert "secret" not in repr(result)
    assert "secret" not in " ".join(scenario.status)
    assert "Phone confirmed" in " ".join(scenario.status)


@pytest.mark.parametrize("user", [{"guest": True, "user_id": "ours"}, {"user_id": "other"}, {}, None])
def test_guest_mismatched_or_missing_identity_is_not_success(scenario, user):
    scenario.user = user
    with pytest.raises(QrLoginError, match="session does not match") as caught:
        run(scenario)
    assert caught.value.stage == "account verification"
    assert not scenario.cookie_path.exists()
    assert scenario.closed == ["browser", "client"]


@pytest.mark.parametrize("http_status", [400, 403, 461, 471, 500])
def test_platform_failure_reports_safe_stage_and_status(scenario, http_status):
    scenario.events[-1] = response(QR_STATUS_ENDPOINT, {"secret": "private"}, status=http_status)
    with pytest.raises(QrLoginError, match=f"HTTP {http_status}") as caught:
        run(scenario)
    assert "private" not in str(caught.value)
    assert caught.value.stage == "session completion"
    assert scenario.closed == ["browser"]
    assert not scenario.cookie_path.exists()


def test_phone_confirmation_does_not_skip_completion(scenario):
    scenario.events.pop()
    with pytest.raises(QrLoginError, match="timed out"):
        run(scenario, timeout_s=0.01)
    assert "Phone confirmed" in " ".join(scenario.status)
    assert scenario.closed == ["browser"]
    assert not scenario.cookie_path.exists()


def test_cookies_are_allowlisted_and_domain_boundary_is_exact():
    assert _cookies(
        [
            {"name": "a1", "value": "yes", "domain": ".xiaohongshu.com"},
            {"name": "web_session", "value": "no", "domain": "evilxiaohongshu.com"},
            {"name": "customer-sso-sid", "value": "no", "domain": "xiaohongshu.com"},
            {"name": "web_session", "value": "no", "domain": "xiaohongshu.com.evil"},
            {"name": "web_session", "value": "no", "domain": None},
        ]
    ) == {"a1": "yes"}


def test_missing_session_cookie_is_rejected(scenario):
    scenario.events[-1] = response(QR_STATUS_ENDPOINT, {"login_info": {"user_id": "ours"}})
    with pytest.raises(QrLoginError, match="incomplete authenticated cookies"):
        run(scenario)
    assert scenario.closed == ["browser"]


def test_unrelated_origin_cannot_complete_login(scenario):
    scenario.events[-1] = response(QR_STATUS_ENDPOINT, {"login_info": {"user_id": "ours"}}, host="evilxiaohongshu.com")
    with pytest.raises(QrLoginError, match="timed out"):
        run(scenario, timeout_s=0.01)


def test_api_verification_error_does_not_leak_response(scenario):
    from xhs_cli.exceptions import XhsApiError

    scenario.api_error = XhsApiError("secret-session response=private")
    with pytest.raises(QrLoginError) as caught:
        run(scenario)
    assert "secret" not in str(caught.value)
    assert "private" not in str(caught.value)


@pytest.mark.parametrize("timeout", [0, -1, True, float("nan"), float("inf")])
def test_invalid_timeout_is_rejected_before_startup(timeout):
    with pytest.raises(ValueError, match="positive finite"):
        qrcode_login(timeout_s=timeout)


def test_terminal_qr_is_compact_and_does_not_print_the_secret_url(capsys):
    _render_qr("https://example.invalid/secret-qr")
    output = capsys.readouterr().out
    assert any(character in output for character in "█▀▄")
    assert "secret" not in output


def test_cli_saves_only_verified_result_and_keeps_json_stdout_clean(scenario, monkeypatch):
    from click.testing import CliRunner

    from xhs_cli.cli import cli
    from xhs_cli.qr_login import QrLoginResult

    def login(**kwargs):
        assert kwargs == {}
        print("Scan QR here")
        return QrLoginResult(
            {"a1": "fixture", "web_session": "fixture-session"},
            {"user_id": "ours", "basic_info": {"nickname": "Cat", "red_id": "cat"}},
        )

    monkeypatch.setattr("xhs_cli.qr_login.qrcode_login", login)
    result = CliRunner().invoke(cli, ["login", "--qrcode", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["data"]["authenticated"] is True
    assert "Scan QR here" in result.stderr
    assert scenario.cookie_path.exists()


def test_cli_login_failure_retains_previous_credentials(scenario, monkeypatch):
    from click.testing import CliRunner

    from xhs_cli.cli import cli
    from xhs_cli.cookies import save_cookies

    save_cookies({"a1": "previous", "web_session": "previous"})
    previous = scenario.cookie_path.read_bytes()

    def fail(**kwargs):
        raise QrLoginError("account verification", "guest session")

    monkeypatch.setattr("xhs_cli.qr_login.qrcode_login", fail)
    result = CliRunner().invoke(cli, ["login", "--qrcode", "--json"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["ok"] is False
    assert scenario.cookie_path.read_bytes() == previous


def test_user_cancellation_closes_browser_and_never_saves(scenario):
    def cancel(url):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        qrcode_login(on_qr=cancel, on_status=scenario.status.append)
    assert scenario.closed == ["browser"]
    assert not scenario.cookie_path.exists()


def test_changing_confirmed_account_is_rejected(scenario):
    scenario.events[1] = response(QR_USERINFO_ENDPOINT, {"codeStatus": 2, "userId": "other"})
    with pytest.raises(QrLoginError, match="inconsistent confirmed account"):
        run(scenario)
    assert scenario.closed == ["browser"]
    assert not scenario.cookie_path.exists()


def test_qr_refresh_fails_instead_of_waiting_on_an_outdated_qr(scenario):
    scenario.events.insert(1, response(QR_CREATE_ENDPOINT, {"url": "secret-replacement"}, "POST"))
    with pytest.raises(QrLoginError, match="QR was replaced"):
        run(scenario)
    assert scenario.rendered == ["secret-qr"]
    assert scenario.closed == ["browser"]


def test_renderer_failure_closes_browser_and_does_not_expose_callback_secrets(scenario):
    def fail(url):
        raise RuntimeError("secret-qr callback failure")

    with pytest.raises(QrLoginError) as caught:
        qrcode_login(on_qr=fail, on_status=scenario.status.append)
    assert "secret" not in str(caught.value)
    assert scenario.closed == ["browser"]
    assert not scenario.cookie_path.exists()
