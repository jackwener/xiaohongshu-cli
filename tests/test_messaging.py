"""Direct-message endpoints and normalizers (no network)."""

from __future__ import annotations

import pytest

from xhs_cli.client import XhsClient
from xhs_cli.command_normalizers import (
    normalize_chat_messages,
    normalize_chats,
    unwrap_message_content,
)
from xhs_cli.exceptions import RateLimitedError, XhsApiError


class TestMessagingEndpoints:
    """私信端点在 /api/im/web/ 命名空间，但复用同一套 x-s 签名。"""

    @pytest.mark.parametrize(
        ("call", "uri"),
        [
            (lambda c: c.get_im_unread(), "/api/im/web/chat/get_unread"),
            (lambda c: c.get_chats(), "/api/im/web/v3/chats"),
            (lambda c: c.get_chat_messages("peer-1"), "/api/im/web/messages/history"),
        ],
    )
    def test_endpoint_uris(self, monkeypatch, call, uri):
        captured = {}

        def fake_get(self, target, params=None):
            captured["uri"] = target
            captured["params"] = params
            return {}

        monkeypatch.setattr(XhsClient, "_main_api_get", fake_get)
        client = XhsClient({"a1": "cookie"})
        try:
            call(client)
        finally:
            client.close()
        assert captured["uri"] == uri

    def test_chat_messages_params(self, monkeypatch):
        captured = {}
        monkeypatch.setattr(
            XhsClient, "_main_api_get",
            lambda self, uri, params=None: captured.update(params=params) or {},
        )
        client = XhsClient({"a1": "cookie"})
        try:
            client.get_chat_messages("peer-1", limit=5)
        finally:
            client.close()
        assert captured["params"]["chat_user_id"] == "peer-1"
        assert captured["params"]["limit"] == 5


class TestUnwrapMessageContent:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ('{"content":"9.26-9.28两晚"}', "9.26-9.28两晚"),
            ("plain text", "plain text"),
            ("", ""),
            (None, ""),
            ("{broken json", "{broken json"),
        ],
    )
    def test_shapes(self, raw, expected):
        assert unwrap_message_content(raw) == expected

    def test_card_prefers_front_chain(self):
        """卡片/笔记分享保留 "[笔记]" 类型标记，与网页显示一致。"""
        raw = '{"content":"{\\"frontChain\\":\\"[笔记]标题\\",\\"title\\":\\"标题\\"}"}'
        assert unwrap_message_content(raw) == "[笔记]标题"

    def test_deep_nesting_stops_at_max_depth(self):
        """畸形深嵌套不能死循环。"""
        assert unwrap_message_content('{"content":' * 40, max_depth=4)


class TestNormalizeChats:
    def test_lifts_nickname_and_merges_unread(self):
        raw = {
            "total": 2,
            "chats": [
                {"chat_user_id": "u1", "last_msg_content": '{"content":"hi"}',
                 "last_msg_time": 7, "info": {"nickname": "Alice", "is_friend": True}},
                {"chat_user_id": "u2", "last_msg_content": "yo",
                 "last_msg_time": 8, "info": {"user_name": "bob"}},
            ],
        }
        out = normalize_chats(raw, {"u1": 3})
        assert [c["nickname"] for c in out["chats"]] == ["Alice", "bob"]
        assert out["chats"][0]["unread"] == 3
        assert out["chats"][1]["unread"] == 0
        assert out["unread_total"] == 3
        assert out["chats"][0]["last_msg"] == "hi"

    def test_empty_payload(self):
        out = normalize_chats({}, None)
        assert out == {"chats": [], "total": 0, "unread_total": 0}


class TestNormalizeChatMessages:
    def test_direction_uses_self_id(self):
        raw = {"out_message_list": [
            {"sender_id": "me", "content": '{"content":"a"}', "created_at": 2},
            {"sender_id": "peer", "content": '{"content":"b"}', "created_at": 1},
        ]}
        out = normalize_chat_messages(raw, "me")
        assert [m["direction"] for m in out] == ["sent", "received"]
        assert [m["text"] for m in out] == ["a", "b"]

    def test_unknown_self_id_marks_everything_received(self):
        raw = {"out_message_list": [{"sender_id": "me", "content": "a"}]}
        assert normalize_chat_messages(raw, "")[0]["direction"] == "received"

    def test_revoked_flag(self):
        raw = {"out_message_list": [{"sender_id": "p", "content": "x", "revoked": True}]}
        assert normalize_chat_messages(raw, "me")[0]["revoked"] is True


class TestSendDirectMessage:
    """发送走 HTTP short-link：protobuf + RSA，不需要 WebSocket。"""

    def _client(self, monkeypatch, captured, post_result, self_info=None):
        monkeypatch.setattr(
            XhsClient, "get_self_info",
            lambda self: {"user_id": "me-1"} if self_info is None else self_info,
        )

        def fake_post(self, uri, data, header_overrides=None):
            captured["uri"] = uri
            captured["data"] = data
            return post_result

        monkeypatch.setattr(XhsClient, "_main_api_post", fake_post)
        return XhsClient({"a1": "cookie"})

    def test_uses_short_link_endpoint_and_encrypted_payload(self, monkeypatch):
        captured = {}
        client = self._client(monkeypatch, captured, {"code": 0})
        try:
            result = client.send_direct_message("peer-1", "hello")
        finally:
            client.close()

        assert captured["uri"] == "/api/im/web/short_link/send_message"
        message = captured["data"]["message"]
        assert isinstance(message, str)
        raw = message.encode("latin-1")
        assert raw and len(raw) % 128 == 0
        assert result["receiver_id"] == "peer-1"
        assert result["local_mid"]

    def test_throttle_checks_dm_bucket(self, monkeypatch):
        buckets = []
        monkeypatch.setattr(
            "xhs_cli.client_mixins.check_write_budget", lambda bucket: buckets.append(bucket)
        )
        captured = {}
        client = self._client(monkeypatch, captured, {"code": 0})
        try:
            client.send_direct_message("peer-1", "hello")
        finally:
            client.close()
        assert buckets == ["dm"]

    def test_throttle_error_propagates(self, monkeypatch):
        def deny(bucket):
            raise RateLimitedError("too fast")

        monkeypatch.setattr("xhs_cli.client_mixins.check_write_budget", deny)
        monkeypatch.setattr(XhsClient, "get_self_info", lambda self: {"user_id": "me-1"})
        monkeypatch.setattr(XhsClient, "_main_api_post", lambda *a, **k: {"code": 0})
        client = XhsClient({"a1": "cookie"})
        try:
            with pytest.raises(RateLimitedError):
                client.send_direct_message("peer-1", "hello")
        finally:
            client.close()

    def test_rejects_nested_failure_code(self, monkeypatch):
        captured = {}
        client = self._client(monkeypatch, captured, {"code": 12345, "msg": "blocked"})
        try:
            with pytest.raises(XhsApiError, match="rejected"):
                client.send_direct_message("peer-1", "hello")
        finally:
            client.close()

    @pytest.mark.parametrize("payload", [None, {}, "str", [], {"data": {"code": 0}}])
    def test_unrecognised_response_is_unconfirmed_not_success(self, monkeypatch, payload):
        """空响应/未知形状必须报未确认，不能当成发送成功。"""
        captured = {}
        client = self._client(monkeypatch, captured, payload)
        try:
            with pytest.raises(XhsApiError, match="unconfirmed"):
                client.send_direct_message("peer-1", "hello")
        finally:
            client.close()

    def test_server_message_id_is_surfaced(self, monkeypatch):
        """真实成功响应形状：{"chat_ack": ..., "message_id": "<server id>"}。"""
        captured = {}
        client = self._client(
            monkeypatch, captured,
            {"chat_ack": {"ts": 1}, "message_id": "srv-123"},
        )
        try:
            out = client.send_direct_message("peer-1", "hello")
        finally:
            client.close()
        assert out["message_id"] == "srv-123"
        assert out["local_mid"] and out["local_mid"] != "srv-123"

    @pytest.mark.parametrize("payload", [{"code": 0}, {"success": True}, {"code": "0"}])
    def test_positive_confirmation_accepted(self, monkeypatch, payload):
        captured = {}
        client = self._client(monkeypatch, captured, payload)
        try:
            assert client.send_direct_message("peer-1", "hello")["receiver_id"] == "peer-1"
        finally:
            client.close()

    def test_non_text_content_type_rejected(self, monkeypatch):
        captured = {}
        client = self._client(monkeypatch, captured, {"code": 0})
        try:
            with pytest.raises(XhsApiError, match="content_type=1"):
                client.send_direct_message("peer-1", "hello", content_type=2)
        finally:
            client.close()

    def test_requires_resolvable_sender(self, monkeypatch):
        monkeypatch.setattr(XhsClient, "get_self_info", lambda self: {})
        monkeypatch.setattr(XhsClient, "_main_api_post", lambda *a, **k: {})
        client = XhsClient({"a1": "cookie"})
        try:
            with pytest.raises(XhsApiError, match="current user id"):
                client.send_direct_message("peer-1", "hello")
        finally:
            client.close()

    def test_empty_content_fails_before_network(self, monkeypatch):
        client = XhsClient({"a1": "cookie"})
        self_info_calls = []
        monkeypatch.setattr(
            XhsClient, "get_self_info",
            lambda self: self_info_calls.append(1) or {"user_id": "me"},
        )
        try:
            with pytest.raises(XhsApiError, match="content is required"):
                client.send_direct_message("peer-1", "")
        finally:
            client.close()
        assert self_info_calls == []

    def test_empty_receiver_fails_before_network(self, monkeypatch):
        client = XhsClient({"a1": "cookie"})
        monkeypatch.setattr(XhsClient, "get_self_info", lambda self: {"user_id": "me"})
        try:
            with pytest.raises(XhsApiError, match="receiver_id is required"):
                client.send_direct_message("", "hello")
        finally:
            client.close()
