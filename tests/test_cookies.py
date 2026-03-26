"""Unit tests for cookie management (no network required)."""


import base64
import hashlib
import json
import time

import httpx
import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from xhs_cli.cookies import (
    NOTE_CONTEXT_TTL_SECONDS,
    cache_note_context,
    clear_cookies,
    cookies_to_string,
    extract_cookiecloud_cookies,
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
from xhs_cli.exceptions import NoCookieError, XhsApiError


def _evp_bytes_to_key(password: bytes, salt: bytes, key_len: int = 32, iv_len: int = 16) -> tuple[bytes, bytes]:
    derived = b""
    block = b""
    while len(derived) < key_len + iv_len:
        block = hashlib.md5(block + password + salt).digest()
        derived += block
    return derived[:key_len], derived[key_len : key_len + iv_len]


def _encrypt_cookiecloud_payload(
    payload: dict[str, object],
    *,
    uuid: str = "uuid-1",
    password: str = "secret-1",
    salt: bytes = b"12345678",
) -> dict[str, str]:
    passphrase = hashlib.md5(f"{uuid}-{password}".encode()).hexdigest()[:16].encode()
    key, iv = _evp_bytes_to_key(passphrase, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(json.dumps(payload).encode(), AES.block_size))
    encrypted = base64.b64encode(b"Salted__" + salt + ciphertext).decode()
    return {"encrypted": encrypted}


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

    def test_force_refresh_uses_cookiecloud_provider(self, monkeypatch):
        monkeypatch.setattr("xhs_cli.cookies.load_saved_cookies", lambda: {"a1": "saved"})
        monkeypatch.setattr(
            "xhs_cli.cookies.extract_cookiecloud_cookies",
            lambda: ("cookiecloud", {"a1": "fresh-cookie"}),
        )
        saved = []
        monkeypatch.setattr("xhs_cli.cookies.save_cookies", lambda cookies: saved.append(cookies))

        browser, cookies = get_cookies("cookiecloud", force_refresh=True)

        assert browser == "cookiecloud"
        assert cookies == {"a1": "fresh-cookie"}
        assert saved == [{"a1": "fresh-cookie"}]

    def test_stale_saved_cookies_refresh_from_cookiecloud(self, monkeypatch):
        now = 1_000_000.0
        monkeypatch.setattr(
            "xhs_cli.cookies.load_saved_cookies",
            lambda: {"a1": "stale-cookie", "saved_at": now - (8 * 86400)},
        )
        monkeypatch.setattr("xhs_cli.cookies.time.time", lambda: now)
        monkeypatch.setattr(
            "xhs_cli.cookies.extract_cookiecloud_cookies",
            lambda: ("cookiecloud", {"a1": "fresh-cookie"}),
        )
        saved = []
        monkeypatch.setattr("xhs_cli.cookies.save_cookies", lambda cookies: saved.append(cookies))

        browser, cookies = get_cookies("cookiecloud")

        assert browser == "cookiecloud"
        assert cookies == {"a1": "fresh-cookie"}
        assert saved == [{"a1": "fresh-cookie"}]

    def test_force_refresh_cookiecloud_raises_when_no_usable_cookies(self, monkeypatch):
        monkeypatch.setattr("xhs_cli.cookies.extract_cookiecloud_cookies", lambda: None)

        with pytest.raises(NoCookieError):
            get_cookies("cookiecloud", force_refresh=True)


class TestCookieCloudExtraction:
    def test_cookiecloud_requires_config(self, monkeypatch):
        monkeypatch.delenv("COOKIECLOUD_HOST", raising=False)
        monkeypatch.delenv("COOKIECLOUD_UUID", raising=False)
        monkeypatch.delenv("COOKIECLOUD_PASSWORD", raising=False)

        with pytest.raises(XhsApiError, match="COOKIECLOUD_HOST"):
            extract_cookiecloud_cookies()

    def test_extract_cookiecloud_cookies_returns_xhs_cookie_dict(self, monkeypatch):
        monkeypatch.setenv("COOKIECLOUD_HOST", "https://cookiecloud.example.com")
        monkeypatch.setenv("COOKIECLOUD_UUID", "uuid-1")
        monkeypatch.setenv("COOKIECLOUD_PASSWORD", "secret-1")
        payload = _encrypt_cookiecloud_payload(
            {
                "cookie_data": {
                    ".xiaohongshu.com": [
                        {"name": "a1", "value": "a1-cookie"},
                        {"name": "web_session", "value": "session-cookie"},
                    ],
                    "xiaohongshu.com": [
                        {"name": "web_session_sec", "value": "session-sec-cookie"},
                    ],
                    ".example.com": [
                        {"name": "ignore_me", "value": "1"},
                    ],
                }
            }
        )
        monkeypatch.setattr("xhs_cli.cookies._fetch_cookiecloud_payload", lambda config: payload)

        result = extract_cookiecloud_cookies()

        assert result == (
            "cookiecloud",
            {
                "a1": "a1-cookie",
                "web_session": "session-cookie",
                "web_session_sec": "session-sec-cookie",
            },
        )

    def test_extract_cookiecloud_cookies_returns_none_without_xhs_domain(self, monkeypatch):
        monkeypatch.setenv("COOKIECLOUD_HOST", "https://cookiecloud.example.com")
        monkeypatch.setenv("COOKIECLOUD_UUID", "uuid-1")
        monkeypatch.setenv("COOKIECLOUD_PASSWORD", "secret-1")
        payload = _encrypt_cookiecloud_payload(
            {
                "cookie_data": {
                    ".example.com": [
                        {"name": "a1", "value": "other-cookie"},
                    ]
                }
            }
        )
        monkeypatch.setattr("xhs_cli.cookies._fetch_cookiecloud_payload", lambda config: payload)

        assert extract_cookiecloud_cookies() is None

    def test_extract_cookiecloud_cookies_returns_none_without_a1(self, monkeypatch):
        monkeypatch.setenv("COOKIECLOUD_HOST", "https://cookiecloud.example.com")
        monkeypatch.setenv("COOKIECLOUD_UUID", "uuid-1")
        monkeypatch.setenv("COOKIECLOUD_PASSWORD", "secret-1")
        payload = _encrypt_cookiecloud_payload(
            {
                "cookie_data": {
                    ".xiaohongshu.com": [
                        {"name": "web_session", "value": "session-cookie"},
                    ]
                }
            }
        )
        monkeypatch.setattr("xhs_cli.cookies._fetch_cookiecloud_payload", lambda config: payload)

        assert extract_cookiecloud_cookies() is None

    def test_extract_cookiecloud_cookies_raises_on_decrypt_failure(self, monkeypatch):
        monkeypatch.setenv("COOKIECLOUD_HOST", "https://cookiecloud.example.com")
        monkeypatch.setenv("COOKIECLOUD_UUID", "uuid-1")
        monkeypatch.setenv("COOKIECLOUD_PASSWORD", "secret-1")
        monkeypatch.setattr(
            "xhs_cli.cookies._fetch_cookiecloud_payload",
            lambda config: {"encrypted": "not-valid-base64"},
        )

        with pytest.raises(XhsApiError, match="decrypt"):
            extract_cookiecloud_cookies()


class TestCookieCloudFetchErrors:
    def test_fetch_cookiecloud_payload_timeout_raises_actionable_error(self, monkeypatch):
        def fake_get(url, timeout, follow_redirects):
            raise httpx.TimeoutException("timeout")

        monkeypatch.setattr("xhs_cli.cookies.httpx.get", fake_get)

        from xhs_cli.cookies import _fetch_cookiecloud_payload

        with pytest.raises(XhsApiError, match="timed out"):
            _fetch_cookiecloud_payload(
                {"host": "https://cookiecloud.example.com", "uuid": "uuid-1", "timeout": 10.0}
            )

    def test_fetch_cookiecloud_payload_http_status_error_raises_actionable_error(self, monkeypatch):
        request = httpx.Request("GET", "https://cookiecloud.example.com/get/uuid-1")
        response = httpx.Response(502, request=request)

        def fake_get(url, timeout, follow_redirects):
            return response

        monkeypatch.setattr("xhs_cli.cookies.httpx.get", fake_get)

        from xhs_cli.cookies import _fetch_cookiecloud_payload

        with pytest.raises(XhsApiError, match="HTTP 502"):
            _fetch_cookiecloud_payload(
                {"host": "https://cookiecloud.example.com", "uuid": "uuid-1", "timeout": 10.0}
            )

    def test_fetch_cookiecloud_payload_http_error_raises_actionable_error(self, monkeypatch):
        def fake_get(url, timeout, follow_redirects):
            raise httpx.HTTPError("network down")

        monkeypatch.setattr("xhs_cli.cookies.httpx.get", fake_get)

        from xhs_cli.cookies import _fetch_cookiecloud_payload

        with pytest.raises(XhsApiError, match="request failed"):
            _fetch_cookiecloud_payload(
                {"host": "https://cookiecloud.example.com", "uuid": "uuid-1", "timeout": 10.0}
            )

    def test_fetch_cookiecloud_payload_invalid_json_raises_actionable_error(self, monkeypatch):
        request = httpx.Request("GET", "https://cookiecloud.example.com/get/uuid-1")
        response = httpx.Response(200, request=request, content=b"not-json")

        def fake_get(url, timeout, follow_redirects):
            return response

        monkeypatch.setattr("xhs_cli.cookies.httpx.get", fake_get)

        from xhs_cli.cookies import _fetch_cookiecloud_payload

        with pytest.raises(XhsApiError, match="invalid JSON"):
            _fetch_cookiecloud_payload(
                {"host": "https://cookiecloud.example.com", "uuid": "uuid-1", "timeout": 10.0}
            )

    def test_fetch_cookiecloud_payload_invalid_shape_raises_actionable_error(self, monkeypatch):
        request = httpx.Request("GET", "https://cookiecloud.example.com/get/uuid-1")
        response = httpx.Response(200, request=request, json=["not", "a", "dict"])

        def fake_get(url, timeout, follow_redirects):
            return response

        monkeypatch.setattr("xhs_cli.cookies.httpx.get", fake_get)

        from xhs_cli.cookies import _fetch_cookiecloud_payload

        with pytest.raises(XhsApiError, match="invalid response payload"):
            _fetch_cookiecloud_payload(
                {"host": "https://cookiecloud.example.com", "uuid": "uuid-1", "timeout": 10.0}
            )

    def test_fetch_cookiecloud_payload_missing_encrypted_field_raises_actionable_error(self, monkeypatch):
        request = httpx.Request("GET", "https://cookiecloud.example.com/get/uuid-1")
        response = httpx.Response(200, request=request, json={"cookie_data": {}})

        def fake_get(url, timeout, follow_redirects):
            return response

        monkeypatch.setattr("xhs_cli.cookies.httpx.get", fake_get)

        from xhs_cli.cookies import _fetch_cookiecloud_payload

        with pytest.raises(XhsApiError, match="encrypted payload"):
            _fetch_cookiecloud_payload(
                {"host": "https://cookiecloud.example.com", "uuid": "uuid-1", "timeout": 10.0}
            )


class TestNoCookieError:
    def test_cookiecloud_message_is_actionable(self):
        message = str(NoCookieError("cookiecloud"))

        assert "CookieCloud" in message
        assert "COOKIECLOUD_HOST" in message
        assert "COOKIECLOUD_UUID" in message
        assert "COOKIECLOUD_PASSWORD" in message
        assert "xhs login --cookie-source cookiecloud" in message

    def test_named_browser_message_keeps_browser_guidance(self):
        message = str(NoCookieError("chrome"))

        assert "in chrome" in message
        assert "Open a browser" in message
        assert "xhs login --cookie-source <browser>" in message

    def test_auto_message_keeps_browser_autodetect_guidance(self):
        message = str(NoCookieError("auto"))

        assert "in any installed browser" in message
        assert "Open a browser" in message
        assert "xhs login --cookie-source <browser>" in message


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
