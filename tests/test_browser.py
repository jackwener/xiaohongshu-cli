"""Fixed CloakBrowser launch options, lazy dependency and deterministic resource ownership."""

import sys
from types import SimpleNamespace

import pytest

from xhs_cli.browser import BrowserUnavailable, browser_page


@pytest.mark.parametrize("failure", [None, "launch", "context", "page", "body", "interrupt"])
def test_only_visible_humanized_cloakbrowser_is_started_and_resources_close(monkeypatch, failure):
    calls = []

    def launch(**kwargs):
        assert kwargs == {"headless": False, "humanize": True}
        calls.append("launch")
        if failure == "launch":
            raise RuntimeError("private-license-key")
        return browser

    def new_context():
        if failure == "context":
            raise RuntimeError("context")
        return context

    def new_page():
        if failure == "page":
            raise RuntimeError("page")
        return "page"

    browser = SimpleNamespace(new_context=new_context, close=lambda: calls.append("browser closed"))
    context = SimpleNamespace(new_page=new_page, close=lambda: calls.append("context closed"))
    monkeypatch.setitem(sys.modules, "cloakbrowser", SimpleNamespace(launch=launch))
    if failure:
        error = KeyboardInterrupt if failure == "interrupt" else (RuntimeError, BrowserUnavailable)
        with pytest.raises(error) as caught:
            with browser_page():
                if failure == "interrupt":
                    raise KeyboardInterrupt
                raise RuntimeError("body")
        assert "private-license-key" not in str(caught.value)
    else:
        with browser_page() as page:
            assert page == "page"
    if failure not in {"launch", "context"}:
        assert calls[-2:] == ["context closed", "browser closed"]
    if failure == "context":
        assert calls[-1] == "browser closed"


def test_browser_extra_is_optional(monkeypatch):
    monkeypatch.setitem(sys.modules, "cloakbrowser", None)
    with pytest.raises(BrowserUnavailable, match=r"xiaohongshu-cli\[browser\]"):
        with browser_page():
            pytest.fail("must not launch without the optional dependency")


@pytest.mark.parametrize("sdk_fails", [False, True])
def test_missing_display_environment_does_not_prevent_sdk_launch(monkeypatch, sdk_fails):
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    calls = []
    page = SimpleNamespace()
    context = SimpleNamespace(new_page=lambda: page, close=lambda: calls.append("context closed"))
    browser = SimpleNamespace(new_context=lambda: context, close=lambda: calls.append("browser closed"))

    def launch(**kwargs):
        assert kwargs == {"headless": False, "humanize": True}
        calls.append("SDK called")
        if sdk_fails:
            raise RuntimeError("SDK launch failed")
        return browser

    monkeypatch.setitem(sys.modules, "cloakbrowser", SimpleNamespace(launch=launch))
    if sdk_fails:
        with pytest.raises(BrowserUnavailable, match="could not start"):
            with browser_page():
                pytest.fail("SDK failure must propagate as a safe error")
    else:
        with browser_page() as actual:
            assert actual is page
        assert calls[-2:] == ["context closed", "browser closed"]
    assert calls[0] == "SDK called"


@pytest.mark.parametrize("display", ["DISPLAY", "WAYLAND_DISPLAY"])
def test_either_explicit_graphical_session_can_be_used_without_mutation(monkeypatch, display):
    import os

    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setenv(display, ":authorized")
    page = SimpleNamespace()
    context = SimpleNamespace(new_page=lambda: page, close=lambda: None)
    browser = SimpleNamespace(new_context=lambda: context, close=lambda: None)
    monkeypatch.setitem(sys.modules, "cloakbrowser", SimpleNamespace(launch=lambda **kwargs: browser))
    before = dict(os.environ)
    with browser_page() as actual:
        assert actual is page
    assert dict(os.environ) == before


@pytest.mark.parametrize(
    "kind, message, expected",
    [
        ("TimeoutError", "secret launch command", "browser launch timed out"),
        ("CloakBrowserLicenseError", "private-license-key", "SDK rejected license validation"),
        ("TargetClosedError", "secret-command exitCode=17, signal=SIGTRAP", "exitCode=17. signal=SIGTRAP"),
        ("Error", "Missing X server secret-command", "could not connect to the graphical display"),
        ("Error", "Authorization required private-cookie", "graphical-session authorization failure"),
        ("RuntimeError", "private-launch-command", "SDK raised RuntimeError"),
    ],
)
def test_actual_sdk_errors_get_safe_specific_diagnostics(monkeypatch, kind, message, expected):
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    error_type = type(kind, (Exception,), {})
    calls = []

    def fail(**kwargs):
        assert kwargs == {"headless": False, "humanize": True}
        calls.append("SDK called")
        raise error_type(message)

    monkeypatch.setitem(sys.modules, "cloakbrowser", SimpleNamespace(launch=fail))
    with pytest.raises(BrowserUnavailable) as caught:
        with browser_page():
            pytest.fail("must propagate the actual SDK startup failure")
    diagnostic = str(caught.value)
    assert expected in diagnostic
    assert "secret" not in diagnostic and "private" not in diagnostic
    assert calls == ["SDK called"]
