"""Tests for local Chrome DevTools Protocol cookie extraction."""

import pytest

from xhs_cli.cdp_cookies import extract_cdp_cookies


class _FakeContext:
    def __init__(self, cookies):
        self._cookies = cookies

    def cookies(self, urls):
        assert urls == ["https://www.xiaohongshu.com/"]
        return self._cookies


class _FakeChromium:
    def __init__(self, browser):
        self.browser = browser
        self.calls = []

    def connect_over_cdp(self, endpoint, timeout):
        self.calls.append((endpoint, timeout))
        return self.browser


class _FakePlaywrightManager:
    def __init__(self, chromium):
        self.playwright = type("Playwright", (), {"chromium": chromium})()

    def __enter__(self):
        return self.playwright

    def __exit__(self, *args):
        return None


def _install_fake_playwright(monkeypatch, contexts):
    browser = type("Browser", (), {"contexts": contexts})()
    chromium = _FakeChromium(browser)
    monkeypatch.setattr(
        "playwright.sync_api.sync_playwright",
        lambda: _FakePlaywrightManager(chromium),
    )
    return chromium


def test_extract_cdp_cookies_uses_loopback_and_xhs_domain(monkeypatch):
    chromium = _install_fake_playwright(
        monkeypatch,
        [
            _FakeContext(
                [
                    {"name": "a1", "value": "valid", "domain": ".xiaohongshu.com"},
                    {"name": "web_session", "value": "session", "domain": "www.xiaohongshu.com"},
                    {"name": "foreign", "value": "secret", "domain": ".example.com"},
                ]
            )
        ],
    )

    assert extract_cdp_cookies(9222) == {
        "a1": "valid",
        "web_session": "session",
    }
    assert chromium.calls == [("http://127.0.0.1:9222", 5_000)]


def test_extract_cdp_cookies_does_not_mix_browser_contexts(monkeypatch):
    _install_fake_playwright(
        monkeypatch,
        [
        _FakeContext(
            [
                {"name": "web_session", "value": "session-a", "domain": ".xiaohongshu.com"},
            ]
            ),
            _FakeContext(
                [
                    {"name": "a1", "value": "account-b", "domain": ".xiaohongshu.com"},
                    {"name": "web_session", "value": "session-b", "domain": ".xiaohongshu.com"},
                ]
            ),
        ],
    )

    assert extract_cdp_cookies(9222) == {
        "a1": "account-b",
        "web_session": "session-b",
    }


def test_extract_cdp_cookies_requires_a1(monkeypatch):
    _install_fake_playwright(
        monkeypatch,
        [
            _FakeContext(
                [
                    {"name": "web_session", "value": "session", "domain": ".xiaohongshu.com"},
                ]
            )
        ],
    )

    assert extract_cdp_cookies(9222) is None


def test_rejects_invalid_port():
    with pytest.raises(ValueError, match="between 1 and 65535"):
        extract_cdp_cookies(0)
