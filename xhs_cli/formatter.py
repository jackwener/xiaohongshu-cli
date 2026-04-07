"""Rich formatting utilities for XHS CLI output.

Re-exports from formatter_utils (base utilities) and formatter_renderers
(rich display functions). This module is the public API surface that
commands should import from.
"""

from .formatter_renderers import (  # noqa: F401
    render_comments,
    render_creator_notes,
    render_feed,
    render_note,
    render_notifications,
    render_search_results,
    render_topics,
    render_user_info,
    render_user_posts,
    render_users,
)
from .formatter_utils import (  # noqa: F401
    coerce_int,
    console,
    emit_error,
    error_console,
    error_payload,
    format_count,
    maybe_print_structured,
    print_error,
    print_info,
    print_json,
    print_success,
    print_yaml,
    resolve_output_format,
    success_payload,
)

# ─── URL parsing ────────────────────────────────────────────────────────────


def parse_note_reference(id_or_url: str) -> tuple[str, str, str]:
    """Extract note ID, xsec_token, and xsec_source from a URL or plain ID."""
    if "xiaohongshu.com" in id_or_url:
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(id_or_url)
        parts = parsed.path.rstrip("/").split("/")
        note_id = parts[-1]
        qs = parse_qs(parsed.query)
        xsec_token = qs.get("xsec_token", [""])[0]
        xsec_source = qs.get("xsec_source", [""])[0]
        return note_id, xsec_token, xsec_source
    return id_or_url, "", ""


def parse_note_url(id_or_url: str) -> tuple[str, str]:
    """Extract note ID and xsec_token from URL or plain ID.

    Returns (note_id, xsec_token). xsec_token may be empty if not in URL.
    """
    note_id, xsec_token, _xsec_source = parse_note_reference(id_or_url)
    return note_id, xsec_token


def extract_note_id(id_or_url: str) -> str:
    """Extract note ID from URL or return as-is (drops query params)."""
    note_id, _ = parse_note_url(id_or_url)
    return note_id


def parse_user_reference(id_or_url: str) -> tuple[str, str, str]:
    """Extract user ID, xsec_token, and xsec_source from a profile URL or plain ID."""
    if "xiaohongshu.com" in id_or_url:
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(id_or_url)
        parts = parsed.path.rstrip("/").split("/")
        user_id = parts[-1]
        qs = parse_qs(parsed.query)
        xsec_token = qs.get("xsec_token", [""])[0]
        xsec_source = qs.get("xsec_source", [""])[0]
        return user_id, xsec_token, xsec_source
    return id_or_url, "", ""
