"""Normalize reverse-engineered API payloads into stable renderer-friendly shapes."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode


def _coerce_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def normalize_user_info(data: dict[str, Any]) -> dict[str, Any]:
    basic = data.get("basic_info", data)
    interactions = data.get("interactions", [])

    stats = {}
    for item in interactions:
        stats[item.get("type", "")] = item.get("count", "0")

    return {
        "nickname": basic.get("nickname", basic.get("nick_name", "Unknown")),
        "red_id": basic.get("red_id", ""),
        "desc": basic.get("desc", ""),
        "ip_location": basic.get("ip_location", ""),
        "user_id": basic.get("user_id", data.get("user_id", "")),
        "gender": basic.get("gender"),
        "stats": stats,
    }


def normalize_note_detail(data: dict[str, Any]) -> dict[str, Any] | None:
    items = data.get("items", [])
    if not items:
        return None

    note = items[0].get("note_card", {})
    user = note.get("user", {})
    interact = note.get("interact_info", {})
    tags = note.get("tag_list", [])

    return {
        "title": note.get("title", "Untitled"),
        "desc": note.get("desc", ""),
        "author": user.get("nickname", "Unknown"),
        "liked_count": interact.get("liked_count", "0"),
        "collected_count": interact.get("collected_count", "0"),
        "comment_count": interact.get("comment_count", "0"),
        "share_count": interact.get("share_count", "0"),
        "tags": [tag.get("name", "") for tag in tags if tag.get("name")],
        "image_count": len(note.get("image_list", [])),
    }


def normalize_hydrated_note(
    data: dict[str, Any],
    *,
    note_id: str,
    xsec_token: str = "",
    xsec_source: str = "pc_feed",
) -> dict[str, Any] | None:
    """Normalize note detail into a stable agent-facing shape."""
    items = data.get("items", [])
    if not items or not isinstance(items[0], dict):
        return None

    entry = items[0]
    note = entry.get("note_card", {})
    if not isinstance(note, dict):
        return None
    user = note.get("user", {}) if isinstance(note.get("user"), dict) else {}
    interact = note.get("interact_info", {}) if isinstance(note.get("interact_info"), dict) else {}
    tags = note.get("tag_list", []) if isinstance(note.get("tag_list"), list) else []
    images = note.get("image_list", []) if isinstance(note.get("image_list"), list) else []
    published_at = _published_at(note, entry)
    token = xsec_token or entry.get("xsec_token") or note.get("xsec_token") or ""
    token = str(token)
    url = f"https://www.xiaohongshu.com/explore/{note_id}"
    if token:
        url += "?" + urlencode({"xsec_token": token, "xsec_source": xsec_source})

    return {
        "id": note_id,
        "url": url,
        "title": note.get("title") or note.get("display_title") or "Untitled",
        "body": note.get("desc", ""),
        "author": {
            "id": user.get("user_id", ""),
            "name": user.get("nickname", user.get("nick_name", "Unknown")),
        },
        "note_type": "video" if note.get("type") == "video" else "image",
        "liked_count": _coerce_int(interact.get("liked_count")),
        "collected_count": _coerce_int(interact.get("collected_count")),
        "comment_count": _coerce_int(interact.get("comment_count")),
        "share_count": _coerce_int(interact.get("share_count")),
        "tags": [tag.get("name", "") for tag in tags if isinstance(tag, dict) and tag.get("name")],
        "images": [image_url for image in images if (image_url := _image_url(image))],
        "published_at": published_at,
    }


def _image_url(image: Any) -> str:
    if not isinstance(image, dict):
        return ""
    candidates = [image.get("url_default"), image.get("url_pre"), image.get("url")]
    info_list = image.get("info_list", [])
    for info in info_list if isinstance(info_list, list) else []:
        if isinstance(info, dict):
            candidates.append(info.get("url"))
    value = next((str(value).strip() for value in candidates if value), "")
    if value.startswith("//"):
        return f"https:{value}"
    if value.startswith("http://"):
        return f"https://{value.removeprefix('http://')}"
    return value


def _published_at(*objects: dict[str, Any]) -> str:
    keys = ("time", "timestamp", "create_time", "ctime")
    value = next((obj.get(key) for obj in objects for key in keys if obj.get(key)), None)
    try:
        timestamp = float(value)
        while abs(timestamp) > 10_000_000_000:
            timestamp /= 1000
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def normalize_note_summary(item: dict[str, Any]) -> dict[str, Any] | None:
    note_card = item.get("note_card", item)
    if not isinstance(note_card, dict):
        return None
    user = note_card.get("user", {})
    interact = note_card.get("interact_info", {})
    return {
        "title": str(note_card.get("title", note_card.get("display_title", "")))[:40],
        "author": user.get("nickname", ""),
        "liked": str(interact.get("liked_count", "")),
        "note_type": "video" if note_card.get("type") == "video" else "image",
        "note_id": item.get("id", note_card.get("note_id", "")),
        "xsec_token": item.get("xsec_token", note_card.get("xsec_token", "")),
    }


def normalize_search_results(data: dict[str, Any]) -> dict[str, Any]:
    items = [item for item in (normalize_note_summary(item) for item in data.get("items", [])) if item]
    return {
        "items": items,
        "has_more": bool(data.get("has_more", False)),
    }


def normalize_comments(data: dict[str, Any]) -> list[dict[str, Any]]:
    normalized = []
    for comment in data.get("comments", []):
        user = comment.get("user_info", {})
        normalized.append({
            "nickname": user.get("nickname", "Unknown"),
            "content": comment.get("content", ""),
            "like_count": comment.get("like_count", "0"),
            "sub_comment_count": _coerce_int(comment.get("sub_comment_count", 0)),
            "published_at": _published_at(comment),
        })
    return normalized


def normalize_feed(data: dict[str, Any]) -> list[dict[str, Any]]:
    normalized = []
    for item in data.get("items", [])[:20]:
        note_card = item.get("note_card", {})
        user = note_card.get("user", {})
        interact = note_card.get("interact_info", {})
        normalized.append({
            "title": note_card.get("title", note_card.get("display_title", ""))[:40],
            "author": user.get("nickname", ""),
            "liked": str(interact.get("liked_count", "")),
            "note_id": item.get("id", ""),
            "xsec_token": item.get("xsec_token", note_card.get("xsec_token", "")),
        })
    return normalized


def normalize_user_posts(notes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for note in notes:
        interact = note.get("interact_info", {})
        normalized.append({
            "title": note.get("display_title", "")[:40],
            "liked": str(interact.get("liked_count", note.get("liked_count", ""))),
            "note_type": "video" if note.get("type") == "video" else "image",
            "note_id": note.get("note_id", ""),
        })
    return normalized


def normalize_topics(data: Any) -> list[dict[str, Any]]:
    topics = data if isinstance(data, list) else data.get("topic_info_dtos", [])
    return [
        {
            "name": topic.get("name", ""),
            "view_num": topic.get("view_num", 0),
            "topic_id": topic.get("id", ""),
        }
        for topic in topics
    ]


def normalize_users(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        users = data
    elif isinstance(data, dict):
        users = data.get("user_info_dtos") or data.get("users") or data.get("items") or []
    else:
        users = []

    normalized = []
    for user in users:
        base = user.get("user_base_dto", user)
        normalized.append({
            "nickname": base.get("user_nickname", base.get("nickname", base.get("nick_name", ""))),
            "red_id": base.get("red_id", ""),
            "fans": user.get("fans_total", base.get("fans", base.get("fansCount", 0))),
            "user_id": base.get("user_id", base.get("id", "")),
        })
    return normalized


def normalize_creator_notes(data: Any) -> list[dict[str, Any]]:
    notes = data if isinstance(data, list) else data.get("notes", data.get("note_list", []))
    normalized = []
    for note in notes:
        interact = note.get("interact_info", {})
        normalized.append({
            "title": note.get("title", note.get("display_title", ""))[:40],
            "liked": str(note.get("liked_count", interact.get("liked_count", ""))),
            "comment_count": str(note.get("comment_count", interact.get("comment_count", ""))),
            "status": note.get("status"),
            "note_id": note.get("note_id", note.get("id", "")),
        })
    return normalized


def normalize_notifications(data: dict[str, Any]) -> list[dict[str, Any]]:
    normalized = []
    for message in data.get("message_list", []):
        user = message.get("user_info", {}) or {}
        item = message.get("item_info", {}) or {}
        normalized.append({
            "nickname": user.get("nickname", ""),
            "title": message.get("title", ""),
            "note_content": item.get("content", ""),
            "time": message.get("time", 0),
        })
    return normalized
