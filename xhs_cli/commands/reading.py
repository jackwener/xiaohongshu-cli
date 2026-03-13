"""Reading commands: search, read, comments, sub-comments, user, user-posts, feed, hot, topics, search-user."""

import click

from ..command_normalizers import normalize_paged_notes
from ..cookies import cache_note_context
from ..formatter import (
    maybe_print_structured,
    print_info,
    render_comments,
    render_feed,
    render_note,
    render_search_results,
    render_topics,
    render_user_info,
    render_user_posts,
    render_users,
)
from ..note_refs import resolve_note_reference, save_index_from_items, save_index_from_notes
from ._common import exit_for_error, handle_command, run_client_action, structured_output_options

# ─── Token propagation ─────────────────────────────────────────────────────

def _cache_tokens_from_items(data: dict, *, xsec_source: str) -> None:
    """Auto-cache xsec_token from search/feed API results.

    Each note item may carry its own xsec_token bound to the source
    (search, feed, explore).  Caching them lets a subsequent
    `xhs read <note_id>` use the correct token automatically.
    """
    for item in data.get("items", []):
        note_card = item.get("note_card", {})
        note_id = item.get("id", note_card.get("note_id", ""))
        token = item.get("xsec_token", note_card.get("xsec_token", ""))
        if note_id and token:
            cache_note_context(note_id, token, xsec_source)

# ─── Sort mapping ────────────────────────────────────────────────────────────

SORT_MAP = {
    "general": "general",
    "popular": "popularity_descending",
    "latest": "time_descending",
}

TYPE_MAP = {
    "all": 0,
    "video": 1,
    "image": 2,
}


@click.command()
@click.argument("keyword")
@click.option("--sort", type=click.Choice(["general", "popular", "latest"]), default="general", help="Sort order")
@click.option("--type", "note_type", type=click.Choice(["all", "video", "image"]), default="all", help="Note type")
@click.option("--page", default=1, help="Page number")
@structured_output_options
@click.pass_context
def search(ctx, keyword: str, sort: str, note_type: str, page: int, as_json: bool, as_yaml: bool):
    """Search notes by keyword."""
    def _search_action(client):
        result = client.search_notes(
            keyword=keyword,
            page=page,
            sort=SORT_MAP[sort],
            note_type=TYPE_MAP[note_type],
        )
        _cache_tokens_from_items(result, xsec_source="pc_search")
        save_index_from_items(result, xsec_source="pc_search")
        return result

    handle_command(
        ctx,
        action=_search_action,
        render=render_search_results,
        as_json=as_json,
        as_yaml=as_yaml,
    )


@click.command()
@click.argument("id_or_url")
@click.option("--xsec-token", default="", help="Security token (or reuse a cached token for this note)")
@structured_output_options
@click.pass_context
def read(ctx, id_or_url: str, xsec_token: str, as_json: bool, as_yaml: bool):
    """Read a note by ID, URL, or short index."""
    note_id, token, url_source = resolve_note_reference(id_or_url, xsec_token=xsec_token)
    xsec_source = url_source or "pc_feed"
    if token:
        cache_note_context(note_id, token, xsec_source)

    def _read_action(client):
        kwargs = {"xsec_token": token}
        if url_source:
            kwargs["xsec_source"] = url_source
        return client.get_note_detail(note_id, **kwargs)

    handle_command(
        ctx,
        action=_read_action,
        render=render_note,
        as_json=as_json,
        as_yaml=as_yaml,
    )


@click.command()
@click.argument("id_or_url")
@click.option("--cursor", default="", help="Pagination cursor")
@click.option("--xsec-token", default="", help="Security token")
@click.option("--all", "fetch_all", is_flag=True, help="Auto-paginate to fetch ALL comments")
@structured_output_options
@click.pass_context
def comments(ctx, id_or_url: str, cursor: str, xsec_token: str, fetch_all: bool, as_json: bool, as_yaml: bool):
    """View comments on a note by ID, URL, or short index."""
    note_id, token, url_source = resolve_note_reference(id_or_url, xsec_token=xsec_token)
    xsec_source = url_source or "pc_feed"
    if token:
        cache_note_context(note_id, token, xsec_source)

    def _load_comments(client):
        common_kwargs = {"xsec_token": token}
        if url_source:
            common_kwargs["xsec_source"] = url_source
        if fetch_all:
            return client.get_all_comments(note_id, **common_kwargs)
        return client.get_comments(
            note_id,
            cursor=cursor,
            **common_kwargs,
        )

    def _render_comments(data):
        render_comments(data)
        if fetch_all and isinstance(data, dict):
            total = data.get("total_fetched", 0)
            pages = data.get("pages_fetched", 0)
            print_info(f"Fetched {total} comments across {pages} pages")

    try:
        data = run_client_action(ctx, _load_comments)
        if not maybe_print_structured(data, as_json=as_json, as_yaml=as_yaml):
            _render_comments(data)
    except Exception as exc:
        exit_for_error(exc, as_json=as_json, as_yaml=as_yaml)


@click.command()
@click.argument("user_id")
@structured_output_options
@click.pass_context
def user(ctx, user_id: str, as_json: bool, as_yaml: bool):
    """View user profile info."""
    handle_command(
        ctx,
        action=lambda client: client.get_user_info(user_id),
        render=render_user_info,
        as_json=as_json,
        as_yaml=as_yaml,
    )


@click.command("user-posts")
@click.argument("user_id")
@click.option("--cursor", default="", help="Pagination cursor")
@structured_output_options
@click.pass_context
def user_posts(ctx, user_id: str, cursor: str, as_json: bool, as_yaml: bool):
    """List a user's published notes."""
    def _user_posts_action(client):
        data = client.get_user_notes(user_id, cursor=cursor)
        page = normalize_paged_notes(data)
        save_index_from_notes(page["notes"])
        return data

    def _render_user_posts(data):
        page = normalize_paged_notes(data)
        render_user_posts(page["notes"])
        if page["has_more"]:
            print_info(f"More notes available — use --cursor {page['cursor']}")

    handle_command(
        ctx,
        action=_user_posts_action,
        render=_render_user_posts,
        as_json=as_json,
        as_yaml=as_yaml,
    )


@click.command()
@structured_output_options
@click.pass_context
def feed(ctx, as_json: bool, as_yaml: bool):
    """Browse the recommendation feed."""
    def _feed_action(client):
        result = client.get_home_feed()
        _cache_tokens_from_items(result, xsec_source="pc_feed")
        save_index_from_items(result, xsec_source="pc_feed")
        return result

    handle_command(
        ctx,
        action=_feed_action,
        render=render_feed,
        as_json=as_json,
        as_yaml=as_yaml,
    )


@click.command()
@click.argument("keyword")
@structured_output_options
@click.pass_context
def topics(ctx, keyword: str, as_json: bool, as_yaml: bool):
    """Search for topics/hashtags."""
    handle_command(
        ctx,
        action=lambda client: client.search_topics(keyword),
        render=render_topics,
        as_json=as_json,
        as_yaml=as_yaml,
    )


@click.command("sub-comments")
@click.argument("note_id")
@click.argument("comment_id")
@click.option("--cursor", default="", help="Pagination cursor")
@structured_output_options
@click.pass_context
def sub_comments(ctx, note_id: str, comment_id: str, cursor: str, as_json: bool, as_yaml: bool):
    """View replies to a specific comment."""
    handle_command(
        ctx,
        action=lambda client: client.get_sub_comments(note_id, comment_id, cursor=cursor),
        render=render_comments,
        as_json=as_json,
        as_yaml=as_yaml,
    )


@click.command("search-user")
@click.argument("keyword")
@structured_output_options
@click.pass_context
def search_user(ctx, keyword: str, as_json: bool, as_yaml: bool):
    """Search for users by keyword."""
    handle_command(
        ctx,
        action=lambda client: client.search_users(keyword),
        render=render_users,
        as_json=as_json,
        as_yaml=as_yaml,
    )


HOT_CATEGORIES = {
    "fashion": "homefeed.fashion_v3",
    "food": "homefeed.food_v3",
    "cosmetics": "homefeed.cosmetics_v3",
    "movie": "homefeed.movie_and_tv_v3",
    "career": "homefeed.career_v3",
    "love": "homefeed.love_v3",
    "home": "homefeed.household_product_v3",
    "gaming": "homefeed.gaming_v3",
    "travel": "homefeed.travel_v3",
    "fitness": "homefeed.fitness_v3",
}


@click.command()
@click.option(
    "--category", "-c",
    type=click.Choice(list(HOT_CATEGORIES.keys())),
    default="food",
    help="Category (fashion, food, cosmetics, movie, career, love, home, gaming, travel, fitness)",
)
@structured_output_options
@click.pass_context
def hot(ctx, category: str, as_json: bool, as_yaml: bool):
    """Browse hot/trending notes by category."""
    def _hot_action(client):
        result = client.get_hot_feed(HOT_CATEGORIES[category])
        _cache_tokens_from_items(result, xsec_source="pc_feed")
        save_index_from_items(result, xsec_source="pc_feed")
        return result

    handle_command(
        ctx,
        action=_hot_action,
        render=render_feed,
        as_json=as_json,
        as_yaml=as_yaml,
    )
