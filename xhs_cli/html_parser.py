"""Parse note data from Xiaohongshu HTML pages (SSR __INITIAL_STATE__).

This module provides an alternative to the feed API for reading notes.
The HTML endpoint embeds note data in a server-rendered `window.__INITIAL_STATE__`
object, which does not require a valid xsec_token to access.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from .exceptions import XhsApiError

logger = logging.getLogger(__name__)

# Regex to extract the __INITIAL_STATE__ JSON blob from the HTML.
_STATE_PATTERN = re.compile(r"window\.__INITIAL_STATE__=({.*?})\s*</script>", re.DOTALL)


def parse_initial_state(html: str) -> dict[str, Any]:
    """Extract and parse `window.__INITIAL_STATE__` from an XHS note page.

    The server-rendered HTML contains a global state object with note data.
    XHS uses bare `undefined` values in the JS object which are not valid JSON,
    so we replace them before parsing.
    """
    match = _STATE_PATTERN.search(html)
    if not match:
        raise XhsApiError("Could not parse __INITIAL_STATE__ from HTML")

    raw = match.group(1)

    # Replace bare `undefined` with empty string (not valid JSON)
    cleaned = re.sub(r":\s*undefined", ':""', raw)
    cleaned = re.sub(r",\s*undefined", ',""', cleaned)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise XhsApiError(f"Failed to parse __INITIAL_STATE__ JSON: {exc}") from None


def extract_note_from_state(
    state: dict[str, Any],
    note_id: str,
) -> dict[str, Any]:
    """Extract a single note dict from the parsed __INITIAL_STATE__.

    The state structure is:
        state.note.noteDetailMap[note_id].note -> full note object
    """
    detail_map = state.get("note", {}).get("noteDetailMap", {})
    if not detail_map:
        raise XhsApiError("Note not found in HTML state: empty noteDetailMap")

    # Try exact noteId first, then fall back to first entry
    entry = detail_map.get(note_id)
    if entry is None:
        entry = next(iter(detail_map.values()), None)

    if entry and isinstance(entry, dict) and "note" in entry:
        return entry["note"]

    raise XhsApiError("Note not found in HTML state")


def extract_note_from_html(html: str, note_id: str) -> dict[str, Any]:
    """High-level: parse HTML → extract note in one step."""
    state = parse_initial_state(html)
    return extract_note_from_state(state, note_id)


def extract_user_from_state(state: dict[str, Any]) -> dict[str, Any]:
    """Extract profile data from a parsed XHS user homepage state."""
    user_page_data = state.get("user", {}).get("userPageData")
    if isinstance(user_page_data, dict):
        return user_page_data

    raise XhsApiError("User profile not found in HTML state")


def extract_user_from_html(html: str) -> dict[str, Any]:
    """High-level: parse HTML → extract user profile in one step."""
    state = parse_initial_state(html)
    return extract_user_from_state(state)
