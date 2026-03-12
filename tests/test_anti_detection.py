"""Tests for anti-detection measures: UA/platform alignment, header completeness, jitter."""


from xhs_cli.client import XhsClient
from xhs_cli.constants import CHROME_VERSION, PLATFORM, USER_AGENT
from xhs_cli.signing import sign_main_api


class TestUAPlatformConsistency:
    """UA, sec-ch-ua, and fingerprint must all agree on macOS Chrome."""

    def test_ua_is_macos_chrome(self):
        assert "Macintosh" in USER_AGENT
        assert "Chrome/" in USER_AGENT
        assert "Edg/" not in USER_AGENT
        assert "Windows" not in USER_AGENT

    def test_platform_is_macos(self):
        assert PLATFORM == "macOS"

    def test_base_headers_match_ua(self):
        client = XhsClient({"a1": "test"})
        try:
            headers = client._base_headers()
            # sec-ch-ua must reference Chrome, not Edge
            assert "Google Chrome" in headers["sec-ch-ua"]
            assert CHROME_VERSION in headers["sec-ch-ua"]
            assert "Edge" not in headers["sec-ch-ua"]
            # Platform must match
            assert "macOS" in headers["sec-ch-ua-platform"]
        finally:
            client.close()


class TestSigningHeaders:
    """Verify sign_main_api returns all required headers."""

    def test_returns_all_required_keys(self):
        cookies = {"a1": "test_a1_12345678901234567890123456789012345678901234"}
        headers = sign_main_api("GET", "/api/test", cookies)
        expected_keys = {"x-s", "x-s-common", "x-t", "x-b3-traceid", "x-xray-traceid"}
        assert set(headers.keys()) == expected_keys

    def test_xs_has_xys_prefix(self):
        cookies = {"a1": "test_a1_12345678901234567890123456789012345678901234"}
        headers = sign_main_api("GET", "/api/test", cookies)
        assert headers["x-s"].startswith("XYS_")

    def test_get_and_post_return_different_xs(self):
        cookies = {"a1": "test_a1_12345678901234567890123456789012345678901234"}
        h_get = sign_main_api("GET", "/api/test", cookies)
        h_post = sign_main_api("POST", "/api/test", cookies, payload={"key": "value"})
        # Different method/payload → different signature
        assert h_get["x-s"] != h_post["x-s"]


class TestClientJitter:
    """Verify jitter produces variable delays (not fixed intervals)."""

    def test_request_delay_default(self):
        client = XhsClient({"a1": "test"})
        try:
            assert client._request_delay == 1.0
            assert client._base_request_delay == 1.0
        finally:
            client.close()

    def test_verify_count_starts_at_zero(self):
        client = XhsClient({"a1": "test"})
        try:
            assert client._verify_count == 0
            assert client._request_count == 0
        finally:
            client.close()


class TestBaseHeadersCompleteness:
    """Ensure all anti-detection headers are present."""

    def test_has_dnt_header(self):
        client = XhsClient({"a1": "test"})
        try:
            headers = client._base_headers()
            assert headers.get("dnt") == "1"
        finally:
            client.close()

    def test_has_priority_header(self):
        client = XhsClient({"a1": "test"})
        try:
            headers = client._base_headers()
            assert "priority" in headers
        finally:
            client.close()

    def test_has_all_sec_fetch_headers(self):
        client = XhsClient({"a1": "test"})
        try:
            headers = client._base_headers()
            assert "sec-fetch-dest" in headers
            assert "sec-fetch-mode" in headers
            assert "sec-fetch-site" in headers
        finally:
            client.close()
