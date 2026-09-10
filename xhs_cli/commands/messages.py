"""Direct-message commands: conversation list and message history.

只读。小红书的私信发送走另一套传输（protobuf over WebSocket，或 RSA 加密的
short-link HTTP 兜底），本模块不涉及。
"""

import click

from ..command_normalizers import (
    normalize_chat_messages,
    normalize_chats,
    resolve_current_user_id,
)
from ..formatter import console
from ._common import handle_command, run_client_action, structured_output_options


@click.command()
@click.option("--limit", default=50, help="Conversations per page")
@click.option("--page", default=0, help="Page number")
@click.option(
    "--unread/--no-unread", "with_unread", default=True,
    help="Merge per-peer unread counts (one extra request)",
)
@structured_output_options
@click.pass_context
def chats(ctx, limit: int, page: int, with_unread: bool, as_json: bool, as_yaml: bool):
    """List direct-message conversations."""
    def _load(client):
        raw = client.get_chats(limit=limit, page=page)
        counts = {}
        if with_unread:
            counts = (client.get_im_unread() or {}).get("user_chat_unread_counts", {})
        return normalize_chats(raw, counts)

    def _render(data):
        console.print(
            f"💬 会话 [bold]{len(data['chats'])}[/bold]/{data['total']}"
            f"  未读 [bold]{data['unread_total']}[/bold]"
        )
        for chat in data["chats"]:
            badge = f" [red]({chat['unread']})[/red]" if chat["unread"] else ""
            console.print(
                f"  {chat['nickname'] or chat['user_id']}{badge}"
                f"  [dim]{' '.join(chat['last_msg'].split())[:40]}[/dim]"
            )
            console.print(f"    [dim]{chat['user_id']}[/dim]")

    handle_command(ctx, action=_load, render=_render, as_json=as_json, as_yaml=as_yaml)


@click.command()
@click.argument("user_id")
@click.option("--limit", default=30, help="Messages to fetch")
@structured_output_options
@click.pass_context
def messages(ctx, user_id: str, limit: int, as_json: bool, as_yaml: bool):
    """Read the message history of one conversation."""
    me_id = ""
    try:
        me_id = resolve_current_user_id(run_client_action(ctx, lambda c: c.get_self_info()))
    except Exception:  # noqa: BLE001 — direction labels are best-effort
        me_id = ""

    def _render(items):
        if not items:
            console.print("[dim]（无消息）[/dim]")
            return
        for item in reversed(items):  # API 返回最新在前，展示按时间正序
            arrow = "→" if item["direction"] == "sent" else "←"
            tag = " [dim](已撤回)[/dim]" if item["revoked"] else ""
            # 正文可能自带换行，单行展示时压平（--json 输出保持原样）
            flat = " ".join(item["text"].split())
            console.print(f"  {arrow} {flat[:70]}{tag}")

    handle_command(
        ctx,
        action=lambda client: normalize_chat_messages(
            client.get_chat_messages(user_id, limit=limit), me_id
        ),
        render=_render,
        as_json=as_json,
        as_yaml=as_yaml,
    )
