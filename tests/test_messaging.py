"""Direct-message endpoints and normalizers (no network)."""

from __future__ import annotations

import pytest

from xhs_cli.client import XhsClient
from xhs_cli.command_normalizers import (
    normalize_chat_messages,
    normalize_chats,
    unwrap_message_content,
)


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
