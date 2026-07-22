"""Social commands: follow, unfollow, favorites, likes."""

from collections.abc import Callable
from typing import Any

import click

from ..command_normalizers import normalize_paged_notes, resolve_current_user_id
from ..formatter import print_info, print_success, render_user_posts
from ..note_refs import save_index_from_notes
from ._common import handle_command, run_client_action, structured_output_options


def _resolve_user_id(ctx, user_id: str | None) -> str:
    """Resolve user_id: use provided value or fall back to current user."""
    if user_id:
        return user_id
    info = run_client_action(ctx, lambda client: client.get_self_info())
    uid = resolve_current_user_id(info)
    if not uid:
        raise click.UsageError("Cannot determine current user_id. Please specify user_id explicitly.")
    return uid


def _paged_notes_command(
    ctx,
    fetcher: Callable[[Any, str, str], dict[str, Any]],
    user_id: str | None,
    cursor: str,
    as_json: bool,
    as_yaml: bool,
) -> None:
    """Shared logic for paged-notes commands (favorites, likes, etc.)."""
    uid = _resolve_user_id(ctx, user_id)

    def _action(client):
        data = fetcher(client, uid, cursor)
        page = normalize_paged_notes(data)
        save_index_from_notes(page["notes"])
        return data

    def _render(data):
        page = normalize_paged_notes(data)
        render_user_posts(page["notes"])
        if page["has_more"]:
            print_info(f"More notes — use --cursor {page['cursor']}")

    handle_command(ctx, action=_action, render=_render, as_json=as_json, as_yaml=as_yaml)


@click.command()
@click.argument("user_id")
@structured_output_options
@click.pass_context
def follow(ctx, user_id: str, as_json: bool, as_yaml: bool):
    """Follow a user."""
    handle_command(
        ctx,
        action=lambda client: client.follow_user(user_id),
        render=lambda _data: print_success(f"Followed user {user_id}"),
        as_json=as_json,
        as_yaml=as_yaml,
    )


@click.command()
@click.argument("user_id")
@structured_output_options
@click.pass_context
def unfollow(ctx, user_id: str, as_json: bool, as_yaml: bool):
    """Unfollow a user."""
    handle_command(
        ctx,
        action=lambda client: client.unfollow_user(user_id),
        render=lambda _data: print_success(f"Unfollowed user {user_id}"),
        as_json=as_json,
        as_yaml=as_yaml,
    )


@click.command()
@click.argument("user_id", required=False, default=None)
@click.option("--cursor", default="", help="Pagination cursor")
@structured_output_options
@click.pass_context
def favorites(ctx, user_id: str | None, cursor: str, as_json: bool, as_yaml: bool):
    """List favorited (bookmarked) notes. Defaults to current user if user_id is omitted."""
    _paged_notes_command(
        ctx,
        fetcher=lambda client, uid, cur: client.get_user_favorites(uid, cursor=cur),
        user_id=user_id, cursor=cursor, as_json=as_json, as_yaml=as_yaml,
    )


@click.command()
@click.argument("user_id", required=False, default=None)
@click.option("--cursor", default="", help="Pagination cursor")
@structured_output_options
@click.pass_context
def likes(ctx, user_id: str | None, cursor: str, as_json: bool, as_yaml: bool):
    """List liked notes. Defaults to current user if user_id is omitted."""
    _paged_notes_command(
        ctx,
        fetcher=lambda client, uid, cur: client.get_user_likes(uid, cursor=cur),
        user_id=user_id, cursor=cursor, as_json=as_json, as_yaml=as_yaml,
    )

