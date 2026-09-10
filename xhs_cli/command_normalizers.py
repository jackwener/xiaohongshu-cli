"""Helpers that normalize raw client responses for command-layer use."""

from __future__ import annotations

import json
from typing import Any


def normalize_xhs_user_payload(info: dict[str, Any]) -> dict[str, object]:
    """Normalize Xiaohongshu user info for structured command output."""
    basic = info.get("basic_info", info) if isinstance(info, dict) else {}
    if not isinstance(basic, dict):
        basic = {}

    user_id = (
        basic.get("user_id")
        or info.get("user_id")
        or info.get("userid")
        or basic.get("red_id")
        or info.get("red_id")
        or ""
    )

    return {
        "id": user_id,
        "name": basic.get("nickname") or info.get("nickname", "Unknown"),
        "username": basic.get("red_id") or info.get("red_id", ""),
        "nickname": basic.get("nickname") or info.get("nickname", "Unknown"),
        "red_id": basic.get("red_id") or info.get("red_id", ""),
        "ip_location": basic.get("ip_location") or info.get("ip_location", ""),
        "desc": basic.get("desc") or info.get("desc", ""),
        "guest": bool(info.get("guest", False)),
    }


def normalize_unread_summary(data: dict[str, Any]) -> dict[str, int]:
    return {
        "mentions": int(data.get("mentions", 0)),
        "likes": int(data.get("likes", 0)),
        "connections": int(data.get("connections", 0)),
        "unread_count": int(data.get("unread_count", 0)),
    }


def normalize_paged_notes(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "notes": data.get("notes", []),
        "has_more": bool(data.get("has_more", False)),
        "cursor": data.get("cursor", ""),
    }


def select_topic_payload(topic_data: Any, fallback_name: str) -> list[dict[str, str]]:
    topics = topic_data if isinstance(topic_data, list) else topic_data.get("topic_info_dtos", [])
    if not topics:
        return []
    first = topics[0]
    return [{
        "id": first.get("id", ""),
        "name": first.get("name", fallback_name),
        "type": "topic",
    }]


def resolve_current_user_id(info: dict[str, Any]) -> str:
    return info.get("user_id", "") if isinstance(info, dict) else ""

# frontChain 带 "[笔记]"/"[卡片]" 类型标记，比裸 title 更接近网页显示
_CONTENT_TEXT_KEYS = ("text", "frontChain", "title", "content")


def unwrap_message_content(raw: Any, max_depth: int = 8) -> str:
    """Peel a direct-message body down to its innermost text.

    私信正文是多层嵌套的 JSON 字符串（卡片/笔记分享往往嵌 3 层以上），
    逐层剥到第一个纯文本为止；剥不动就原样返回，不抛错。
    """
    value: Any = raw
    for _ in range(max_depth):
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped.startswith(("{", "[")):
                return value
            try:
                value = json.loads(stripped)
            except (json.JSONDecodeError, TypeError, ValueError):
                return value
            continue
        if isinstance(value, dict):
            for key in _CONTENT_TEXT_KEYS:
                if key in value:
                    value = value[key]
                    break
            else:
                return json.dumps(value, ensure_ascii=False)
            continue
        return "" if value is None else str(value)
    return value if isinstance(value, str) else str(value)


def normalize_chats(
    data: dict[str, Any], unread_map: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Flatten the conversation list; merge per-peer unread when available."""
    counts = unread_map or {}
    chats = []
    for chat in data.get("chats", []) or []:
        info = chat.get("info") or {}
        peer_id = str(chat.get("chat_user_id", ""))
        chats.append({
            "user_id": peer_id,
            "nickname": info.get("nickname", "") or info.get("user_name", ""),
            "unread": int(counts.get(peer_id, 0) or 0),
            "last_msg": unwrap_message_content(chat.get("last_msg_content", "")),
            "last_msg_time": chat.get("last_msg_time", 0),
            "is_official": bool(info.get("is_official", False)),
            "is_friend": bool(info.get("is_friend", False)),
        })
    return {
        "chats": chats,
        "total": int(data.get("total", len(chats)) or 0),
        "unread_total": sum(c["unread"] for c in chats),
    }


def normalize_chat_messages(data: dict[str, Any], me_id: str = "") -> list[dict[str, Any]]:
    """Flatten one conversation's history (API returns newest first)."""
    out = []
    for msg in data.get("out_message_list", []) or []:
        sender = str(msg.get("sender_id", ""))
        out.append({
            "direction": "sent" if me_id and sender == me_id else "received",
            "sender_id": sender,
            "text": unwrap_message_content(msg.get("content", "")),
            "created_at": msg.get("created_at", 0),
            "revoked": bool(msg.get("revoked", False)),
        })
    return out
