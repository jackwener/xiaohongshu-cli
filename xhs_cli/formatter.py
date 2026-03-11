"""Rich formatting utilities for XHS CLI output."""

import json
import os
import sys
from typing import Any

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console(stderr=True)
error_console = Console(stderr=True)
_stdout = Console()
_OUTPUT_ENV = "OUTPUT"
_SCHEMA_VERSION = "1"


def resolve_output_format(*, as_json: bool, as_yaml: bool) -> str | None:
    """Resolve explicit flags first, then env override, then TTY default."""
    if as_json and as_yaml:
        raise click.UsageError("Use only one of --json or --yaml.")
    if as_yaml:
        return "yaml"
    if as_json:
        return "json"

    output_mode = os.getenv(_OUTPUT_ENV, "auto").strip().lower()
    if output_mode == "yaml":
        return "yaml"
    if output_mode == "json":
        return "json"
    if output_mode == "rich":
        return None

    if not sys.stdout.isatty():
        return "yaml"
    return None


def print_json(data: Any) -> None:
    """Print raw JSON output to stdout."""
    _stdout.print_json(json.dumps(data, ensure_ascii=False, indent=2))


def print_yaml(data: Any) -> None:
    """Print raw YAML output to stdout."""
    click.echo(
        yaml.safe_dump(
            data,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )
    )


def maybe_print_structured(data: Any, *, as_json: bool, as_yaml: bool) -> bool:
    """Print structured output when requested or when stdout is non-TTY."""
    fmt = resolve_output_format(as_json=as_json, as_yaml=as_yaml)
    if not fmt:
        return False
    payload = _normalize_success_payload(data)
    if fmt == "json":
        print_json(payload)
    else:
        print_yaml(payload)
    return True


def success_payload(data: Any) -> dict[str, Any]:
    """Wrap structured success data in the shared agent schema."""
    return {
        "ok": True,
        "schema_version": _SCHEMA_VERSION,
        "data": data,
    }


def error_payload(code: str, message: str, *, details: Any | None = None) -> dict[str, Any]:
    """Wrap structured error data in the shared agent schema."""
    error = {
        "code": code,
        "message": message,
    }
    if details is not None:
        error["details"] = details
    return {
        "ok": False,
        "schema_version": _SCHEMA_VERSION,
        "error": error,
    }


def _normalize_success_payload(data: Any) -> Any:
    """Wrap plain structured data in the shared agent success schema."""
    if isinstance(data, dict) and data.get("schema_version") == _SCHEMA_VERSION and "ok" in data:
        return data
    return success_payload(data)


def emit_error(
    code: str,
    message: str,
    *,
    as_json: bool | None = None,
    as_yaml: bool | None = None,
    details: Any | None = None,
) -> bool:
    """Emit a structured error when the active output mode is machine-readable."""
    if as_json is None or as_yaml is None:
        ctx = click.get_current_context(silent=True)
        params = ctx.params if ctx is not None else {}
        as_json = bool(params.get("as_json", False)) if as_json is None else as_json
        as_yaml = bool(params.get("as_yaml", False)) if as_yaml is None else as_yaml

    fmt = resolve_output_format(as_json=bool(as_json), as_yaml=bool(as_yaml))
    if fmt is None:
        return False

    payload = error_payload(code, message, details=details)
    if fmt == "json":
        print_json(payload)
    else:
        print_yaml(payload)
    return True


def print_error(message: str) -> None:
    """Print error message."""
    if emit_error("api_error", message):
        return
    error_console.print(f"[red]✗[/red] {message}")


def print_success(message: str) -> None:
    """Print success message."""
    console.print(f"[green]✓[/green] {message}")


def print_info(message: str) -> None:
    """Print info message."""
    console.print(f"[dim]ℹ[/dim] {message}")


def coerce_int(value: Any, default: int = 0) -> int:
    """Best-effort integer coercion for reverse-engineered API fields."""
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


def format_count(n: int | str) -> str:
    """Format number for display (e.g., 12345 → 1.2万)."""
    if isinstance(n, str):
        try:
            n = int(n)
        except ValueError:
            return str(n)
    if n >= 100_000_000:
        return f"{n / 100_000_000:.1f}亿"
    if n >= 10_000:
        return f"{n / 10_000:.1f}万"
    return str(n)


def parse_note_url(id_or_url: str) -> tuple[str, str]:
    """Extract note ID and xsec_token from URL or plain ID.

    Returns (note_id, xsec_token). xsec_token may be empty if not in URL.
    """
    if "xiaohongshu.com" in id_or_url:
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(id_or_url)
        # Extract note ID from path
        parts = parsed.path.rstrip("/").split("/")
        note_id = parts[-1]
        # Extract xsec_token from query params
        qs = parse_qs(parsed.query)
        xsec_token = qs.get("xsec_token", [""])[0]
        return note_id, xsec_token
    return id_or_url, ""


def extract_note_id(id_or_url: str) -> str:
    """Extract note ID from URL or return as-is (drops query params)."""
    note_id, _ = parse_note_url(id_or_url)
    return note_id


def render_user_info(data: dict[str, Any]) -> None:
    """Render user profile info as a Rich panel.

    Handles both flat format (from /user/me) and nested format (from /user/otherinfo).
    """
    # Support both nested (basic_info.nickname) and flat (nickname) formats
    basic = data.get("basic_info", data)
    interactions = data.get("interactions", [])

    nickname = basic.get("nickname", basic.get("nick_name", "Unknown"))
    red_id = basic.get("red_id", "")
    desc = basic.get("desc", "")
    ip_location = basic.get("ip_location", "")
    user_id = basic.get("user_id", data.get("user_id", ""))
    gender_val = basic.get("gender")
    gender = "♂️" if gender_val == 0 else "♀️" if gender_val == 1 else ""

    # Build interaction stats
    stats = {}
    for item in interactions:
        stats[item.get("type", "")] = item.get("count", "0")

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
    items = data.get("items", [])
    if not items:
        print_error("No note data found")
        return

    note = items[0].get("note_card", {})
    title = note.get("title", "Untitled")
    desc = note.get("desc", "")
    user = note.get("user", {})
    nickname = user.get("nickname", "Unknown")
    interact = note.get("interact_info", {})

    liked_count = interact.get("liked_count", "0")
    collected_count = interact.get("collected_count", "0")
    comment_count = interact.get("comment_count", "0")
    share_count = interact.get("share_count", "0")

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="dim")
    table.add_column("Value")

    table.add_row("作者", f"[bold]{nickname}[/bold]")
    table.add_row("标题", f"[bold]{title}[/bold]")
    if desc:
        # Truncate long descriptions
        display_desc = desc[:500] + "..." if len(desc) > 500 else desc
        table.add_row("正文", display_desc)

    tags = note.get("tag_list", [])
    if tags:
        tag_str = " ".join(f"[cyan]#{t.get('name', '')}[/cyan]" for t in tags)
        table.add_row("标签", tag_str)

    stats_str = (
        f"❤️ {format_count(liked_count)}  "
        f"⭐ {format_count(collected_count)}  "
        f"💬 {format_count(comment_count)}  "
        f"🔗 {format_count(share_count)}"
    )
    table.add_row("数据", stats_str)

    # Image list
    image_list = note.get("image_list", [])
    if image_list:
        table.add_row("图片", f"{len(image_list)} 张")

    console.print(Panel(table, title=f"📝 {title}", border_style="green"))


def render_search_results(data: dict[str, Any]) -> None:
    """Render search results as a Rich table."""
    items = data.get("items", [])
    if not items:
        print_info("No results found")
        return

    has_next = data.get("has_more", False)

    table = Table(title="搜索结果", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("标题", width=30)
    table.add_column("作者", width=10)
    table.add_column("❤️", justify="right", width=8)
    table.add_column("类型", width=4)
    table.add_column("ID", style="dim", width=24)

    for i, item in enumerate(items, 1):
        note_card = item.get("note_card", item)
        if not isinstance(note_card, dict):
            continue

        title = str(note_card.get("title", note_card.get("display_title", "")))[:40]
        user = note_card.get("user", {})
        nickname = user.get("nickname", "")
        liked = str(note_card.get("interact_info", {}).get("liked_count", ""))
        note_type = "📹" if note_card.get("type") == "video" else "📷"
        note_id = item.get("id", note_card.get("note_id", ""))

        table.add_row(str(i), title, nickname, liked, note_type, note_id)

    console.print(table)
    if has_next:
        print_info("More results available — use --page to paginate")


def render_comments(data: dict[str, Any]) -> None:
    """Render comments as a Rich display."""
    comments = data.get("comments", [])
    if not comments:
        print_info("No comments found")
        return

    for comment in comments:
        user = comment.get("user_info", {})
        nickname = user.get("nickname", "Unknown")
        content = comment.get("content", "")
        like_count = format_count(comment.get("like_count", "0"))
        sub_comment_count = coerce_int(comment.get("sub_comment_count", 0))

        header = f"[bold]{nickname}[/bold]  [dim]❤️ {like_count}[/dim]"
        if sub_comment_count > 0:
            header += f"  [dim]💬 {sub_comment_count} replies[/dim]"

        console.print(header)
        console.print(f"  {content}")
        console.print()


def render_feed(data: dict[str, Any]) -> None:
    """Render feed items as a Rich table."""
    items = data.get("items", [])
    if not items:
        print_info("No feed items")
        return

    table = Table(title="推荐页", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("标题", width=30)
    table.add_column("作者", width=10)
    table.add_column("❤️", justify="right", width=8)
    table.add_column("ID", style="dim", width=24)

    for i, item in enumerate(items[:20], 1):
        note_card = item.get("note_card", {})
        title = note_card.get("title", note_card.get("display_title", ""))[:40]
        user = note_card.get("user", {})
        nickname = user.get("nickname", "")
        liked = str(note_card.get("interact_info", {}).get("liked_count", ""))
        note_id = item.get("id", "")

        table.add_row(str(i), title, nickname, liked, note_id)

    console.print(table)


def render_user_posts(notes: list[dict[str, Any]]) -> None:
    """Render a list of user's notes."""
    if not notes:
        print_info("No notes found")
        return

    table = Table(title="用户笔记", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("标题", width=30)
    table.add_column("❤️", justify="right", width=8)
    table.add_column("类型", width=4)
    table.add_column("ID", style="dim", width=24)

    for i, note in enumerate(notes, 1):
        title = note.get("display_title", "")[:40]
        liked = str(note.get("interact_info", {}).get("liked_count", note.get("liked_count", "")))
        note_type = "📹" if note.get("type") == "video" else "📷"
        note_id = note.get("note_id", "")

        table.add_row(str(i), title, liked, note_type, note_id)

    console.print(table)


def render_topics(data: Any) -> None:
    """Render topic search results."""
    topics = data if isinstance(data, list) else data.get("topic_info_dtos", [])
    if not topics:
        print_info("No topics found")
        return

    table = Table(title="话题", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("话题名", width=15)
    table.add_column("热度", justify="right", width=10)
    table.add_column("ID", style="dim", width=24)

    for i, topic in enumerate(topics, 1):
        name = topic.get("name", "")
        view_num = format_count(topic.get("view_num", 0))
        topic_id = topic.get("id", "")
        table.add_row(str(i), f"#{name}", view_num, topic_id)

    console.print(table)


def render_users(data: Any) -> None:
    """Render user search/list results.

    Handles:
    - Creator search: {user_info_dtos: [{user_base_dto: {user_nickname, ...}, fans_total}]}
    - Social API: {users: [{nickname, user_id, ...}]}
    - Direct list: [{nickname, ...}]
    """
    if isinstance(data, list):
        users = data
    elif isinstance(data, dict):
        users = (
            data.get("user_info_dtos")
            or data.get("users")
            or data.get("items")
            or []
        )
    else:
        users = []

    if not users:
        print_info("No users found")
        return

    table = Table(title="用户列表", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("昵称", width=14)
    table.add_column("小红书号", width=12)
    table.add_column("粉丝", justify="right", width=8)
    table.add_column("ID", style="dim", width=24)

    for i, u in enumerate(users, 1):
        # Handle nested user_base_dto (Creator API) or flat format
        base = u.get("user_base_dto", u)
        nickname = base.get("user_nickname", base.get("nickname", base.get("nick_name", "")))
        red_id = base.get("red_id", "")
        fans = format_count(u.get("fans_total", base.get("fans", base.get("fansCount", 0))))
        user_id = base.get("user_id", base.get("id", ""))
        table.add_row(str(i), nickname, red_id, fans, user_id)

    console.print(table)


def render_creator_notes(data: Any) -> None:
    """Render creator's own note list."""
    notes = data if isinstance(data, list) else data.get("notes", data.get("note_list", []))
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
        title = note.get("title", note.get("display_title", ""))[:40]
        liked = str(note.get("liked_count", note.get("interact_info", {}).get("liked_count", "")))
        comment_count = str(note.get("comment_count", note.get("interact_info", {}).get("comment_count", "")))
        status = "✅" if note.get("status") in (None, 0, "published") else "⏳"
        note_id = note.get("note_id", note.get("id", ""))
        table.add_row(str(i), title, liked, comment_count, status, note_id)

    console.print(table)


def render_notifications(data: dict[str, Any], notif_type: str) -> None:
    """Render notification messages."""
    import time as _time

    messages = data.get("message_list", []) if isinstance(data, dict) else []
    if not messages:
        print_info("No notifications")
        return

    table = Table(title=f"通知 — {notif_type}", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("用户", width=12)
    table.add_column("内容", width=40)
    table.add_column("时间", width=12)

    for i, msg in enumerate(messages[:20], 1):
        # API uses "user_info" not "user"
        user = msg.get("user_info", {}) or {}
        nickname = user.get("nickname", "")
        title = msg.get("title", "")
        # Try to get note content from item_info
        item = msg.get("item_info", {}) or {}
        note_content = item.get("content", "")
        display = title + (f"\n{note_content[:30]}" if note_content else "")
        ts = msg.get("time", 0)
        time_str = _time.strftime("%m-%d %H:%M", _time.localtime(ts)) if ts else ""
        table.add_row(str(i), nickname, display, time_str)

    console.print(table)
