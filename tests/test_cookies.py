"""Unit tests for cookie management (no network required)."""


import sys
import time
import types
from pathlib import Path

import pytest

from xhs_cli.cookies import (
    NOTE_CONTEXT_TTL_SECONDS,
    _available_browsers,
    _cookies_for_domain,
    _extract_via_subprocess,
    cache_note_context,
    clear_cookies,
    cookies_to_string,
    extract_browser_cookies,
    get_cached_note_context,
    get_cached_xsec_token,
    get_cookies,
    get_index_cache_path,
    get_note_by_index,
    get_token_cache_path,
    load_saved_cookies,
    load_token_cache,
    save_cookies,
    save_note_index,
)


@pytest.fixture
def tmp_config_dir(tmp_path, monkeypatch):
    """Override config dir to use temp directory."""
    monkeypatch.setattr("xhs_cli.cookies.get_config_dir", lambda: tmp_path)
    monkeypatch.setattr("xhs_cli.cookies.get_cookie_path", lambda: tmp_path / "cookies.json")
    monkeypatch.setattr("xhs_cli.cookies._TOKEN_CACHE_MEMORY", None)
    monkeypatch.setattr("xhs_cli.cookies._TOKEN_CACHE_PATH", None)
    return tmp_path


class TestSaveCookies:
    def test_save_and_load(self, tmp_config_dir):
        cookies = {"a1": "test_value", "web_session": "sess123"}
        save_cookies(cookies)

        loaded = load_saved_cookies()
        assert loaded is not None
        assert loaded["a1"] == "test_value"
        assert loaded["web_session"] == "sess123"

    def test_file_permissions(self, tmp_config_dir):
        cookies = {"a1": "test"}
        save_cookies(cookies)

        cookie_file = tmp_config_dir / "cookies.json"
        stat = cookie_file.stat()
        assert stat.st_mode & 0o777 == 0o600


class TestLoadSavedCookies:
    def test_no_file(self, tmp_config_dir):
        assert load_saved_cookies() is None

    def test_invalid_json(self, tmp_config_dir):
        (tmp_config_dir / "cookies.json").write_text("not json")
        assert load_saved_cookies() is None

    def test_missing_a1(self, tmp_config_dir):
        (tmp_config_dir / "cookies.json").write_text('{"web_session": "x"}')
        assert load_saved_cookies() is None


class TestClearCookies:
    def test_clear_existing(self, tmp_config_dir):
        save_cookies({"a1": "test"})
        clear_cookies()
        assert load_saved_cookies() is None

    def test_clear_nonexistent(self, tmp_config_dir):
        # Should not raise
        clear_cookies()


class TestCookiesToString:
    def test_format(self):
        result = cookies_to_string({"a1": "v1", "web_session": "v2"})
        assert "a1=v1" in result
        assert "web_session=v2" in result
        assert "; " in result


class TestCookieDomainFiltering:
    def test_matches_exact_domain_and_subdomains_only(self):
        class FakeCookie:
            def __init__(self, name: str, value: str, domain: str):
                self.name = name
                self.value = value
                self.domain = domain

        cookies = _cookies_for_domain(
            [
                FakeCookie("exact", "1", ".xiaohongshu.com"),
                FakeCookie("subdomain", "2", ".www.xiaohongshu.com"),
                FakeCookie("unrelated", "3", ".fake-xiaohongshu.com"),
            ],
            ".xiaohongshu.com",
        )

        assert cookies == {"exact": "1", "subdomain": "2"}


class TestGetCookies:
    def test_prefers_saved_cookies_by_default(self, monkeypatch):
        monkeypatch.setattr("xhs_cli.cookies.load_saved_cookies", lambda: {"a1": "saved"})
        monkeypatch.setattr(
            "xhs_cli.cookies.extract_browser_cookies",
            lambda source: ("chrome", {"a1": "fresh"}),
        )

        browser, cookies = get_cookies("chrome")
        assert browser == "saved"
        assert cookies == {"a1": "saved"}

    def test_force_refresh_bypasses_saved_cookies(self, monkeypatch):
        monkeypatch.setattr("xhs_cli.cookies.load_saved_cookies", lambda: {"a1": "saved"})
        monkeypatch.setattr(
            "xhs_cli.cookies.extract_browser_cookies",
            lambda source: ("chrome", {"a1": "fresh"}),
        )
        saved = []
        monkeypatch.setattr("xhs_cli.cookies.save_cookies", lambda cookies: saved.append(cookies))

        browser, cookies = get_cookies("chrome", force_refresh=True)
        assert browser == "chrome"
        assert cookies == {"a1": "fresh"}
        assert saved == [{"a1": "fresh"}]

    def test_extract_browser_cookies_supports_comet(self, tmp_path, monkeypatch):
        comet_dir = tmp_path / "Library" / "Application Support" / "Comet"
        default_dir = comet_dir / "Default"
        default_dir.mkdir(parents=True)
        (default_dir / "Cookies").write_text("placeholder")

        captured: list[dict[str, object]] = []

        class FakeCookie:
            def __init__(self, name: str, value: str, domain: str):
                self.name = name
                self.value = value
                self.domain = domain

        class FakeChromiumBased:
            def __init__(self, **kwargs):
                captured.append(kwargs)

            def load(self):
                return [
                    FakeCookie("a1", "comet-a1", ".xiaohongshu.com"),
                    FakeCookie("web_session", "session", ".xiaohongshu.com"),
                ]

        fake_bc3 = types.SimpleNamespace(ChromiumBased=FakeChromiumBased)
        monkeypatch.setitem(sys.modules, "browser_cookie3", fake_bc3)
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        browser, cookies = extract_browser_cookies("comet")

        assert browser == "comet"
        assert cookies["a1"] == "comet-a1"
        assert captured == [
            {
                "browser": "Comet",
                "cookie_file": str(default_dir / "Cookies"),
                "domain_name": ".xiaohongshu.com",
                "os_crypt_name": "chrome",
                "osx_key_service": "Comet Safe Storage",
                "osx_key_user": "Comet",
            }
        ]

    def test_available_browsers_includes_comet(self, monkeypatch):
        def fake_loader(domain_name=""):
            return None

        fake_bc3 = types.SimpleNamespace(chrome=fake_loader)
        monkeypatch.setitem(sys.modules, "browser_cookie3", fake_bc3)
        _available_browsers.cache_clear()

        try:
            assert "comet" in _available_browsers()
        finally:
            _available_browsers.cache_clear()

    def test_custom_browser_falls_back_to_custom_subprocess_when_no_native_loader(self, monkeypatch):
        fake_bc3 = types.SimpleNamespace(chrome=lambda domain_name="": None)
        monkeypatch.setitem(sys.modules, "browser_cookie3", fake_bc3)
        monkeypatch.setattr(
            "xhs_cli.cookies._load_custom_browser_cookies_subprocess",
            lambda source, domain_name: {"a1": "custom-subprocess"},
        )

        cookies = _extract_via_subprocess("comet")

        assert cookies == {"a1": "custom-subprocess"}

    def test_extract_browser_cookies_prefers_native_loader_when_available(self, monkeypatch):
        class FakeCookie:
            def __init__(self, name: str, value: str, domain: str):
                self.name = name
                self.value = value
                self.domain = domain

        def comet(domain_name=""):
            return [FakeCookie("a1", "native-a1", ".xiaohongshu.com")]

        fake_bc3 = types.SimpleNamespace(comet=comet)
        monkeypatch.setitem(sys.modules, "browser_cookie3", fake_bc3)
        monkeypatch.setattr(
            "xhs_cli.cookies._load_custom_browser_cookies",
            lambda *args, **kwargs: pytest.fail("custom fallback should not run when native loader succeeds"),
        )

        browser, cookies = extract_browser_cookies("comet")

        assert browser == "comet"
        assert cookies == {"a1": "native-a1"}


class TestNoteContextCache:
    def test_cache_persists_token_and_source(self, tmp_config_dir):
        cache_note_context("note-1", "token-1", "pc_search", context="search")

        assert get_cached_xsec_token("note-1") == "token-1"
        context = get_cached_note_context("note-1")
        assert context["token"] == "token-1"
        assert context["source"] == "pc_search"
        assert context["context"] == "search"

    def test_load_token_cache_keeps_legacy_entries_compatible(self, tmp_config_dir):
        get_token_cache_path().write_text('{"note-1":"legacy-token"}')

        cache = load_token_cache()
        assert cache["note-1"]["token"] == "legacy-token"
        assert cache["note-1"]["source"] == ""

    def test_expired_note_context_is_not_returned(self, tmp_config_dir):
        stale_ts = time.time() - NOTE_CONTEXT_TTL_SECONDS - 10
        get_token_cache_path().write_text(
            f'{{"note-1":{{"token":"stale-token","source":"pc_search","ts":{stale_ts}}}}}'
        )

        assert get_cached_note_context("note-1") == {}


class TestNoteIndexCache:
    def test_save_and_resolve_index_with_source(self, tmp_config_dir):
        save_note_index([
            {
                "note_id": "note-1",
                "xsec_token": "token-1",
                "xsec_source": "pc_search",
            }
        ])

        assert get_note_by_index(1) == {
            "note_id": "note-1",
            "xsec_token": "token-1",
            "xsec_source": "pc_search",
        }

    def test_save_empty_index_clears_previous_entries(self, tmp_config_dir):
        save_note_index([
            {
                "note_id": "note-1",
                "xsec_token": "token-1",
                "xsec_source": "pc_search",
            }
        ])
        save_note_index([])

        assert get_note_by_index(1) is None
        assert get_index_cache_path().read_text() == "[]"

    def test_index_file_permissions(self, tmp_config_dir):
        save_note_index([{"note_id": "note-1", "xsec_token": "", "xsec_source": ""}])

        stat = get_index_cache_path().stat()
        assert stat.st_mode & 0o777 == 0o600

    def test_index_normalizes_missing_optional_fields(self, tmp_config_dir):
        get_index_cache_path().write_text('[{"note_id":"note-1"}]')

        assert get_note_by_index(1) == {
            "note_id": "note-1",
            "xsec_token": "",
            "xsec_source": "",
        }
