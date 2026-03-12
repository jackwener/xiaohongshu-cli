"""Unit tests for signing adapter (no network required).

The cryptographic internals are tested by xhshow's own test suite.
These tests verify our adapter's public interface and config overrides.
"""

import time

import pytest

from xhs_cli.signing import build_get_uri, extract_uri, sign_main_api


class TestBuildUri:
    def test_no_params(self):
        assert build_get_uri("/api/test") == "/api/test"

    def test_with_params(self):
        result = build_get_uri("/api/test", {"a": "1", "b": 2})
        assert "/api/test?" in result
        assert "a=1" in result
        assert "b=2" in result

    def test_with_list_params(self):
        result = build_get_uri("/api/test", {"types": ["a", "b"]})
        assert "types=a,b" in result


class TestExtractUri:
    def test_full_url(self):
        assert extract_uri("https://example.com/api/test") == "/api/test"

    def test_path_only(self):
        assert extract_uri("/api/test") == "/api/test"


class TestSignMainApi:
    def test_generates_all_headers(self):
        cookies = {"a1": "test_a1_value_1234567890abcdef1234567890abcdef1234567890ab"}
        headers = sign_main_api("GET", "/api/sns/web/v2/user/me", cookies)

        assert "x-s" in headers
        assert "x-s-common" in headers
        assert "x-t" in headers
        assert "x-b3-traceid" in headers
        assert "x-xray-traceid" in headers

    def test_xs_prefix(self):
        cookies = {"a1": "test_a1_value_1234567890abcdef1234567890abcdef1234567890ab"}
        headers = sign_main_api("GET", "/api/test", cookies)
        assert headers["x-s"].startswith("XYS_")

    def test_xt_is_timestamp(self):
        cookies = {"a1": "test_a1_value_1234567890abcdef1234567890abcdef1234567890ab"}
        headers = sign_main_api("GET", "/api/test", cookies)
        ts = int(headers["x-t"])
        now_ms = int(time.time() * 1000)
        assert abs(ts - now_ms) < 5000  # within 5 seconds

    def test_post_signing(self):
        cookies = {"a1": "test_a1_value_1234567890abcdef1234567890abcdef1234567890ab"}
        headers = sign_main_api(
            "POST",
            "/api/sns/web/v1/search/notes",
            cookies,
            payload={"keyword": "test", "page": 1},
        )
        assert headers["x-s"].startswith("XYS_")

    def test_missing_a1_raises(self):
        with pytest.raises(ValueError, match="Missing 'a1'"):
            sign_main_api("GET", "/api/test", {})

    def test_with_params(self):
        cookies = {"a1": "test_a1_value_1234567890abcdef1234567890abcdef1234567890ab"}
        headers = sign_main_api(
            "GET", "/api/test", cookies,
            params={"user_id": "12345"},
        )
        assert headers["x-s"].startswith("XYS_")

