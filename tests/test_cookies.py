"""Unit tests for cookie management (no network required)."""


import pytest

from xhs_cli.cookies import (
    clear_cookies,
    cookies_to_string,
    get_cookies,
    get_note_by_index,
    load_saved_cookies,
    save_cookies,
    save_note_index,
)


@pytest.fixture
def tmp_config_dir(tmp_path, monkeypatch):
    """Override config dir to use temp directory."""
    monkeypatch.setattr("xhs_cli.cookies.get_config_dir", lambda: tmp_path)
    monkeypatch.setattr("xhs_cli.cookies.get_cookie_path", lambda: tmp_path / "cookies.json")
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


@pytest.fixture
def tmp_index_dir(tmp_path, monkeypatch):
    """Redirect index cache to a temporary directory."""
    monkeypatch.setattr("xhs_cli.cookies.get_config_dir", lambda: tmp_path)
    monkeypatch.setattr("xhs_cli.cookies.get_index_cache_path", lambda: tmp_path / "index_cache.json")
    return tmp_path


class TestSaveNoteIndex:
    def test_saves_entries(self, tmp_index_dir):
        items = [
            {"note_id": "aaa111", "xsec_token": "tok_a"},
            {"note_id": "bbb222", "xsec_token": "tok_b"},
        ]
        save_note_index(items)
        assert (tmp_index_dir / "index_cache.json").exists()

    def test_file_permissions(self, tmp_index_dir):
        save_note_index([{"note_id": "x", "xsec_token": ""}])
        stat = (tmp_index_dir / "index_cache.json").stat()
        assert stat.st_mode & 0o777 == 0o600

    def test_overwrites_previous(self, tmp_index_dir):
        save_note_index([{"note_id": "old", "xsec_token": ""}])
        save_note_index([{"note_id": "new1", "xsec_token": ""}, {"note_id": "new2", "xsec_token": ""}])
        assert get_note_by_index(1)["note_id"] == "new1"
        assert get_note_by_index(3) is None


class TestGetNoteByIndex:
    def test_first_entry(self, tmp_index_dir):
        save_note_index([
            {"note_id": "aaa111", "xsec_token": "tok_a"},
            {"note_id": "bbb222", "xsec_token": "tok_b"},
        ])
        entry = get_note_by_index(1)
        assert entry == {"note_id": "aaa111", "xsec_token": "tok_a"}

    def test_last_entry(self, tmp_index_dir):
        save_note_index([
            {"note_id": "aaa111", "xsec_token": "tok_a"},
            {"note_id": "bbb222", "xsec_token": "tok_b"},
        ])
        entry = get_note_by_index(2)
        assert entry == {"note_id": "bbb222", "xsec_token": "tok_b"}

    def test_out_of_range_returns_none(self, tmp_index_dir):
        save_note_index([{"note_id": "aaa111", "xsec_token": ""}])
        assert get_note_by_index(99) is None

    def test_zero_index_returns_none(self, tmp_index_dir):
        save_note_index([{"note_id": "aaa111", "xsec_token": ""}])
        assert get_note_by_index(0) is None

    def test_no_cache_file_returns_none(self, tmp_index_dir):
        assert get_note_by_index(1) is None

    def test_corrupt_json_returns_none(self, tmp_index_dir):
        (tmp_index_dir / "index_cache.json").write_text("not json!!!")
        assert get_note_by_index(1) is None

    def test_preserves_xsec_token(self, tmp_index_dir):
        save_note_index([{"note_id": "n1", "xsec_token": "ABCDE12345"}])
        entry = get_note_by_index(1)
        assert entry["xsec_token"] == "ABCDE12345"

    def test_empty_token_allowed(self, tmp_index_dir):
        save_note_index([{"note_id": "n1", "xsec_token": ""}])
        entry = get_note_by_index(1)
        assert entry["note_id"] == "n1"
        assert entry["xsec_token"] == ""
