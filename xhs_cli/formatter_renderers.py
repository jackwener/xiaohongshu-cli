"""Rich renderers for human-readable CLI output."""

from __future__ import annotations

from typing import Any

from rich.panel import Panel
from rich.table import Table

from .formatter_normalizers import (
    normalize_comments,
    normalize_creator_notes,
    normalize_feed,
    normalize_note_detail,
    normalize_notifications,
    normalize_search_results,
    normalize_topics,
    normalize_user_info,
    normalize_user_posts,
    normalize_users,
)
from .formatter_utils import coerce_int, console, format_count, print_error, print_info

HOME_URL = "https://www.xiaohongshu.com"


def _build_note_url(
    note_id: str,
    xsec_token: str = "",
    source: str = "pc_feed",
    route: str = "explore",
) -> str:
    """Build a full note URL, including xsec_token when available."""
    if xsec_token:
        return f"{HOME_URL}/{route}/{note_id}?xsec_token={xsec_token}&xsec_source={source}"
    return note_id  # bare ID fallback


def _build_note_link(
    note_id: str,
    xsec_token: str = "",
    source: str = "pc_feed",
    route: str = "explore",
) -> str:
    url = _build_note_url(note_id, xsec_token=xsec_token, source=source, route=route)
    label = f"{route}/{note_id}"
    if xsec_token:
        return f"[link={url}][dim]{label}[/dim][/link]"
    return f"[dim]{label}[/dim]"


def render_user_info(data: dict[str, Any]) -> None:
    """Render user profile info as a Rich panel."""
    user = normalize_user_info(data)

    nickname = user["nickname"]
    red_id = user["red_id"]
    desc = user["desc"]
    ip_location = user["ip_location"]
    user_id = user["user_id"]
    gender_val = user["gender"]
    gender = "♂️" if gender_val == 0 else "♀️" if gender_val == 1 else ""
    stats = user["stats"]

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="dim")
    table.add_column("Value")

    table.add_row("昵称", f"[bold]{nickname}[/bold] {gender}")
    if red_id:
        table.add_row("小红书号", red_id)
    if user_id:
        table.add_row("User ID", user_id)
    if desc:
        table.add_row("简介", desc)
    if ip_location:
        table.add_row("IP 属地", ip_location)
    if "fans" in stats:
        table.add_row("粉丝", format_count(stats["fans"]))
    if "follows" in stats:
        table.add_row("关注", format_count(stats["follows"]))
    if "interaction" in stats:
        table.add_row("获赞与收藏", format_count(stats["interaction"]))

    console.print(Panel(table, title=f"👤 {nickname}", border_style="blue"))


def render_note(data: dict[str, Any]) -> None:
    """Render a note as a Rich panel."""
    note = normalize_note_detail(data)
    if not note:
        print_error("No note data found")
        return

    title = note["title"]
    desc = note["desc"]
    nickname = note["author"]
    liked_count = note["liked_count"]
    collected_count = note["collected_count"]
    comment_count = note["comment_count"]
    share_count = note["share_count"]

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="dim")
    table.add_column("Value")

    table.add_row("作者", f"[bold]{nickname}[/bold]")
    table.add_row("标题", f"[bold]{title}[/bold]")
    if desc:
        display_desc = desc[:500] + "..." if len(desc) > 500 else desc
        table.add_row("正文", display_desc)

    tags = note["tags"]
    if tags:
        tag_str = " ".join(f"[cyan]#{tag}[/cyan]" for tag in tags)
        table.add_row("标签", tag_str)

    stats_str = (
        f"❤️ {format_count(liked_count)}  "
        f"⭐ {format_count(collected_count)}  "
        f"💬 {format_count(comment_count)}  "
        f"🔗 {format_count(share_count)}"
    )
    table.add_row("数据", stats_str)

    if note["image_count"]:
        table.add_row("图片", f"{note['image_count']} 张")
        for index, image_url in enumerate(note.get("image_urls", []), 1):
            table.add_row(f"图片 {index}", f"[link={image_url}]{image_url}[/link]")

    console.print(Panel(table, title=f"📝 {title}", border_style="green"))


def render_search_results(data: dict[str, Any]) -> None:
    """Render search results as a Rich table."""
    normalized = normalize_search_results(data)
    items = normalized["items"]
    if not items:
        print_info("No results found")
        return

    has_next = normalized["has_more"]
    table = Table(title="搜索结果", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("标题", width=30)
    table.add_column("作者", width=10)
    table.add_column("❤️", justify="right", width=8)
    table.add_column("类型", width=4)
    table.add_column("链接", style="cyan", no_wrap=True)

    for i, item in enumerate(items, 1):
        note_type = "📹" if item["note_type"] == "video" else "📷"
        link = _build_note_link(
            item["note_id"],
            item.get("xsec_token", ""),
            source="pc_search",
            route="search_result",
        )
        table.add_row(str(i), item["title"], item["author"], item["liked"], note_type, link)

    console.print(table)
    if has_next:
        print_info("More results available — use --page to paginate")


def render_comments(data: dict[str, Any]) -> None:
    """Render comments as a Rich display."""
    comments = normalize_comments(data)
    if not comments:
        print_info("No comments found")
        return

    for comment in comments:
        nickname = comment["nickname"]
        content = comment["content"]
        like_count = format_count(comment["like_count"])
        sub_comment_count = coerce_int(comment["sub_comment_count"])

        header = f"[bold]{nickname}[/bold]  [dim]❤️ {like_count}[/dim]"
        if sub_comment_count > 0:
            header += f"  [dim]💬 {sub_comment_count} replies[/dim]"

        console.print(header)
        console.print(f"  {content}")
        console.print()


def render_feed(data: dict[str, Any]) -> None:
    """Render feed items as a Rich table."""
    items = normalize_feed(data)
    if not items:
        print_info("No feed items")
        return

    table = Table(title="推荐页", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("标题", width=30)
    table.add_column("作者", width=10)
    table.add_column("❤️", justify="right", width=8)
    table.add_column("链接", style="cyan", no_wrap=True)

    for i, item in enumerate(items, 1):
        link = _build_note_link(item["note_id"], item.get("xsec_token", ""), source="pc_feed")
        table.add_row(str(i), item["title"], item["author"], item["liked"], link)

    console.print(table)


def render_user_posts(notes: list[dict[str, Any]]) -> None:
    """Render a list of user's notes."""
    normalized = normalize_user_posts(notes)
    if not normalized:
        print_info("No notes found")
        return

    table = Table(title="用户笔记", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("标题", width=30)
    table.add_column("❤️", justify="right", width=8)
    table.add_column("类型", width=4)
    table.add_column("ID", style="dim", width=24)

    for i, note in enumerate(normalized, 1):
        note_type = "📹" if note["note_type"] == "video" else "📷"
        table.add_row(str(i), note["title"], note["liked"], note_type, note["note_id"])

    console.print(table)


def render_topics(data: Any) -> None:
    """Render topic search results."""
    topics = normalize_topics(data)
    if not topics:
        print_info("No topics found")
        return

    table = Table(title="话题", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("话题名", width=15)
    table.add_column("热度", justify="right", width=10)
    table.add_column("ID", style="dim", width=24)

    for i, topic in enumerate(topics, 1):
        table.add_row(str(i), f"#{topic['name']}", format_count(topic["view_num"]), topic["topic_id"])

    console.print(table)


def render_users(data: Any) -> None:
    """Render user search/list results."""
    users = normalize_users(data)
    if not users:
        print_info("No users found")
        return

    table = Table(title="用户列表", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("昵称", width=14)
    table.add_column("小红书号", width=12)
    table.add_column("粉丝", justify="right", width=8)
    table.add_column("ID", style="dim", width=24)

    for i, user in enumerate(users, 1):
        table.add_row(str(i), user["nickname"], user["red_id"], format_count(user["fans"]), user["user_id"])

    console.print(table)


def render_creator_notes(data: Any) -> None:
    """Render creator's own note list."""
    notes = normalize_creator_notes(data)
    if not notes:
        print_info("No notes found")
        return

    table = Table(title="我的笔记", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("标题", width=30)
    table.add_column("❤️", justify="right", width=8)
    table.add_column("💬", justify="right", width=6)
    table.add_column("状态", width=6)
    table.add_column("ID", style="dim", width=24)

    for i, note in enumerate(notes, 1):
        status = "✅" if note["status"] in (None, 0, "published") else "⏳"
        table.add_row(str(i), note["title"], note["liked"], note["comment_count"], status, note["note_id"])

    console.print(table)


def render_notifications(data: dict[str, Any], notif_type: str) -> None:
    """Render notification messages."""
    import time as _time

    messages = normalize_notifications(data)
    if not messages:
        print_info("No notifications")
        return

    table = Table(title=f"通知 — {notif_type}", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("用户", width=12)
    table.add_column("内容", width=40)
    table.add_column("时间", width=12)

    for i, msg in enumerate(messages[:20], 1):
        nickname = msg["nickname"]
        title = msg["title"]
        note_content = msg["note_content"]
        display = title + (f"\n{note_content[:30]}" if note_content else "")
        ts = msg["time"]
        time_str = _time.strftime("%m-%d %H:%M", _time.localtime(ts)) if ts else ""
        table.add_row(str(i), nickname, display, time_str)

    console.print(table)
