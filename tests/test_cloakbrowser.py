"""Exercise the installed Python SDK, replacing binary/license/Playwright IO only."""

from types import SimpleNamespace

import pytest

from xhs_cli.browser import browser_page

cloak = pytest.importorskip("cloakbrowser")


def test_installed_sdk_uses_visible_chromium_and_activates_humanization(monkeypatch):
    import cloakbrowser.browser as vendor
    import cloakbrowser.human as human
    import playwright.sync_api as playwright

    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    calls = []
    context = SimpleNamespace(new_page=lambda: "page", close=lambda: calls.append("context closed"))
    browser = SimpleNamespace(
        new_context=lambda **kwargs: context,
        new_page=lambda **kwargs: "page",
        close=lambda: calls.append("browser closed"),
    )

    def launch(**kwargs):
        assert kwargs["headless"] is False
        assert kwargs["executable_path"] == "/fixture/cloakbrowser"
        calls.append("visible Chromium launched")
        return browser

    driver = SimpleNamespace(chromium=SimpleNamespace(launch=launch), stop=lambda: calls.append("driver stopped"))
    monkeypatch.setattr(playwright, "sync_playwright", lambda: SimpleNamespace(start=lambda: driver))
    monkeypatch.setattr(vendor, "ensure_binary", lambda **kwargs: "/fixture/cloakbrowser")
    monkeypatch.setattr(vendor, "resolve_license_key", lambda *args: None)
    monkeypatch.setattr(vendor, "build_launch_env", lambda *args, **kwargs: None)
    monkeypatch.setattr(vendor, "build_args", lambda *args, **kwargs: [])

    def patch(actual_browser, config):
        assert actual_browser is browser
        calls.append("humanization applied")

    monkeypatch.setattr(human, "patch_browser", patch)
    with browser_page() as page:
        assert page == "page"
    assert calls == [
        "visible Chromium launched",
        "humanization applied",
        "context closed",
        "browser closed",
        "driver stopped",
    ]
