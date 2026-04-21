"""Unit tests for XHS client request payloads, cookies, and endpoint selection."""

from collections import OrderedDict

import httpx
import pytest

from xhs_cli.client import XhsClient
from xhs_cli.cookies import cache_note_context, get_cached_note_context
from xhs_cli.exceptions import UnsupportedOperationError, XhsApiError


class TestFavorites:
    def test_unfavorite_uses_note_ids_payload(self, monkeypatch):
        captured = {}

        def fake_post(self, uri, data, header_overrides=None):
            captured["uri"] = uri
            captured["data"] = data
            return True

        monkeypatch.setattr(XhsClient, "_main_api_post", fake_post)

        client = XhsClient({"a1": "cookie"})
        try:
            client.unfavorite_note("note-123")
        finally:
            client.close()

        assert captured["uri"] == "/api/sns/web/v1/note/uncollect"
        assert captured["data"] == {"note_ids": "note-123"}


class TestCreatorEndpoints:
    def test_creator_note_list_uses_v2_endpoint(self, monkeypatch):
        captured = {}

        def fake_get(self, uri, params=None):
            captured["uri"] = uri
            captured["params"] = params
            return {"notes": [], "page": -1}

        monkeypatch.setattr(XhsClient, "_creator_get", fake_get)

        client = XhsClient({"a1": "cookie"})
        try:
            result = client.get_creator_note_list(page=2)
        finally:
            client.close()

        assert result["page"] == -1
        assert captured["uri"] == "/api/galaxy/v2/creator/note/user/posted"
        assert captured["params"] == {"tab": 0, "page": 2}

    def test_delete_note_raises_unsupported_for_404(self, monkeypatch):
        def fake_post(self, uri, data):
            raise XhsApiError(
                "API error: {\"status\": 404}",
                response={"status": 404},
            )

        monkeypatch.setattr(XhsClient, "_creator_post", fake_post)

        client = XhsClient({"a1": "cookie"})
        try:
            with pytest.raises(UnsupportedOperationError, match="Delete note is currently unavailable"):
                client.delete_note("note-123")
        finally:
            client.close()


class TestTransportCookies:
    def test_request_with_retry_merges_response_cookies(self, monkeypatch):
        request = httpx.Request("POST", "https://edith.xiaohongshu.com/api/test")
        response = httpx.Response(
            200,
            headers=[
                ("set-cookie", "web_session=real-session; Path=/; Domain=.xiaohongshu.com"),
                ("set-cookie", "web_session_sec=real-sec; Path=/; Domain=.xiaohongshu.com"),
            ],
            json={"success": True, "data": {"ok": True}},
            request=request,
        )

        class _FakeHttpClient:
            def request(self, method, url, **kwargs):
                return response

            def close(self):
                return None

        client = XhsClient({"a1": "cookie", "web_session": "guest-session"}, request_delay=0)
        client._http = _FakeHttpClient()
        try:
            resp = client._request_with_retry("POST", "https://edith.xiaohongshu.com/api/test")
        finally:
            client.close()

        assert resp is response
        assert client.cookies["web_session"] == "real-session"
        assert client.cookies["web_session_sec"] == "real-sec"


class TestReadingEndpointBehavior:
    def test_get_note_detail_prefers_cached_xsec_source(self, monkeypatch):
        captured = {}

        def fake_get_note_by_id(self, note_id, xsec_token="", xsec_source="pc_feed"):
            captured["note_id"] = note_id
            captured["token"] = xsec_token
            captured["source"] = xsec_source
            return {"items": [{"note_card": {"title": "ok"}}]}

        monkeypatch.setattr(XhsClient, "get_note_by_id", fake_get_note_by_id)
        cache_note_context("note-123", "token-xyz", "pc_search")

        client = XhsClient({"a1": "cookie"})
        try:
            client.get_note_detail("note-123")
        finally:
            client.close()

        assert captured == {
            "note_id": "note-123",
            "token": "token-xyz",
            "source": "pc_search",
        }

    def test_search_notes_uses_browser_like_prewarm_sequence(self, monkeypatch):
        calls = []

        monkeypatch.setattr("xhs_cli.client_mixins._SEARCH_SESSION_CACHE", OrderedDict())
        monkeypatch.setattr("xhs_cli.client_mixins._SEARCH_SESSION_CACHE_LOADED", True)

        def fake_get(self, uri, params=None):
            calls.append(("GET", uri, params))
            return {"ok": True}

        def fake_post(self, uri, data, header_overrides=None):
            calls.append(("POST", uri, data))
            if uri == "/api/sns/web/v1/search/notes":
                return {"items": [], "has_more": False}
            return {"ok": True}

        monkeypatch.setattr(XhsClient, "_main_api_get", fake_get)
        monkeypatch.setattr(XhsClient, "_main_api_post", fake_post)

        client = XhsClient({"a1": "cookie"})
        try:
            client.search_notes("openclaw prompt", page=2)
        finally:
            client.close()

        assert [call[1] for call in calls] == [
            "/api/sns/web/v1/search/onebox",
            "/api/sns/web/v1/search/filter",
            "/api/sns/web/v1/search/notes",
            "/api/sns/web/v1/search/recommend",
        ]

        notes_payload = calls[2][2]
        assert notes_payload["page"] == 2
        assert notes_payload["filters"][0]["type"] == "sort_type"
        assert notes_payload["filters"][1]["type"] == "filter_note_type"

    def test_search_notes_applies_filter_overrides(self, monkeypatch):
        calls = []

        monkeypatch.setattr("xhs_cli.client_mixins._SEARCH_SESSION_CACHE", OrderedDict())
        monkeypatch.setattr("xhs_cli.client_mixins._SEARCH_SESSION_CACHE_LOADED", True)

        def fake_get(self, uri, params=None):
            calls.append(("GET", uri, params))
            return {"ok": True}

        def fake_post(self, uri, data, header_overrides=None):
            calls.append(("POST", uri, data))
            if uri == "/api/sns/web/v1/search/notes":
                return {"items": [], "has_more": False}
            return {"ok": True}

        monkeypatch.setattr(XhsClient, "_main_api_get", fake_get)
        monkeypatch.setattr(XhsClient, "_main_api_post", fake_post)

        client = XhsClient({"a1": "cookie"})
        try:
            client.search_notes(
                "旅行",
                filter_overrides={
                    "filter_note_time": "一周内",
                    "filter_note_range": "图文",
                    "filter_pos_distance": "附近",
                },
            )
        finally:
            client.close()

        notes_payload = next(call[2] for call in calls if call[1] == "/api/sns/web/v1/search/notes")
        filters_by_type = {item["type"]: item["tags"] for item in notes_payload["filters"]}
        assert filters_by_type["filter_note_time"] == ["一周内"]
        assert filters_by_type["filter_note_range"] == ["图文"]
        assert filters_by_type["filter_pos_distance"] == ["附近"]

    def test_search_notes_reuses_search_id_across_pages(self, monkeypatch):
        calls = []

        monkeypatch.setattr("xhs_cli.client_mixins._SEARCH_SESSION_CACHE", OrderedDict())
        monkeypatch.setattr("xhs_cli.client_mixins._SEARCH_SESSION_CACHE_LOADED", True)

        def fake_get(self, uri, params=None):
            calls.append(("GET", uri, params))
            return {"ok": True}

        def fake_post(self, uri, data, header_overrides=None):
            calls.append(("POST", uri, data))
            if uri == "/api/sns/web/v1/search/notes":
                return {"items": [], "has_more": False}
            return {"ok": True}

        monkeypatch.setattr(XhsClient, "_main_api_get", fake_get)
        monkeypatch.setattr(XhsClient, "_main_api_post", fake_post)

        client = XhsClient({"a1": "cookie"})
        try:
            client.search_notes("openclaw", page=1)
            client.search_notes("openclaw", page=2)
        finally:
            client.close()

        notes_calls = [call for call in calls if call[1] == "/api/sns/web/v1/search/notes"]
        assert len(notes_calls) == 2
        assert notes_calls[0][2]["search_id"] == notes_calls[1][2]["search_id"]

        onebox_calls = [call for call in calls if call[1] == "/api/sns/web/v1/search/onebox"]
        filter_calls = [call for call in calls if call[1] == "/api/sns/web/v1/search/filter"]
        recommend_calls = [call for call in calls if call[1] == "/api/sns/web/v1/search/recommend"]
        assert len(onebox_calls) == 1
        assert len(filter_calls) == 1
        assert len(recommend_calls) == 1

    def test_search_notes_reuses_search_id_after_cache_reload(self, monkeypatch, tmp_path):
        first_calls = []
        second_calls = []

        monkeypatch.setattr("xhs_cli.client_mixins.get_config_dir", lambda: tmp_path)
        monkeypatch.setattr("xhs_cli.client_mixins._SEARCH_SESSION_CACHE", OrderedDict())
        monkeypatch.setattr("xhs_cli.client_mixins._SEARCH_SESSION_CACHE_LOADED", False)
        monkeypatch.setattr("xhs_cli.client_mixins._SEARCH_SESSION_CACHE_PATH", None)

        def fake_get_first(self, uri, params=None):
            first_calls.append(("GET", uri, params))
            return {"ok": True}

        def fake_post_first(self, uri, data, header_overrides=None):
            first_calls.append(("POST", uri, data))
            if uri == "/api/sns/web/v1/search/notes":
                return {"items": [], "has_more": False}
            return {"ok": True}

        monkeypatch.setattr(XhsClient, "_main_api_get", fake_get_first)
        monkeypatch.setattr(XhsClient, "_main_api_post", fake_post_first)

        client = XhsClient({"a1": "cookie"})
        try:
            client.search_notes("openclaw", page=1)
        finally:
            client.close()

        monkeypatch.setattr("xhs_cli.client_mixins._SEARCH_SESSION_CACHE", OrderedDict())
        monkeypatch.setattr("xhs_cli.client_mixins._SEARCH_SESSION_CACHE_LOADED", False)
        monkeypatch.setattr("xhs_cli.client_mixins._SEARCH_SESSION_CACHE_PATH", None)

        def fake_get_second(self, uri, params=None):
            second_calls.append(("GET", uri, params))
            return {"ok": True}

        def fake_post_second(self, uri, data, header_overrides=None):
            second_calls.append(("POST", uri, data))
            if uri == "/api/sns/web/v1/search/notes":
                return {"items": [], "has_more": False}
            return {"ok": True}

        monkeypatch.setattr(XhsClient, "_main_api_get", fake_get_second)
        monkeypatch.setattr(XhsClient, "_main_api_post", fake_post_second)

        client = XhsClient({"a1": "cookie"})
        try:
            client.search_notes("openclaw", page=2)
        finally:
            client.close()

        first_notes_call = next(call for call in first_calls if call[1] == "/api/sns/web/v1/search/notes")
        second_notes_call = next(call for call in second_calls if call[1] == "/api/sns/web/v1/search/notes")
        assert first_notes_call[2]["search_id"] == second_notes_call[2]["search_id"]
        assert [call[1] for call in second_calls] == ["/api/sns/web/v1/search/notes"]

    def test_get_note_detail_invalidates_cached_context_after_feed_failure(self, monkeypatch):
        cache_note_context("note-123", "stale-token", "pc_search")

        def fake_get_note_by_id(self, note_id, xsec_token="", xsec_source="pc_feed"):
            raise XhsApiError("stale token")

        def fake_get_note_from_html(self, note_id, xsec_token="", xsec_source="pc_feed"):
            return {"items": [{"note_card": {"title": "html-ok"}}]}

        monkeypatch.setattr(XhsClient, "get_note_by_id", fake_get_note_by_id)
        monkeypatch.setattr(XhsClient, "get_note_from_html", fake_get_note_from_html)

        client = XhsClient({"a1": "cookie"})
        try:
            result = client.get_note_detail("note-123")
        finally:
            client.close()

        assert result["items"][0]["note_card"]["title"] == "html-ok"
        assert get_cached_note_context("note-123") == {}
