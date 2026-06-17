"""Helpers for downloading media referenced by note payloads."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .formatter_normalizers import normalize_note_detail

DEFAULT_DOWNLOAD_DIR = "xhs-downloads"


@dataclass(frozen=True)
class SavedImage:
    index: int
    url: str
    path: Path


def _safe_path_part(value: str, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip(".-")
    return cleaned or fallback


def _image_extension(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path.split("!", 1)[0]
    suffix = Path(path).suffix.lower()
    if suffix in {".jpg", ".jpeg", ".png", ".webp", ".gif", ".avif"}:
        return suffix
    return ".jpg"


def _note_id_from_detail(data: dict) -> str:
    items = data.get("items", [])
    if not items:
        return "note"
    note_card = items[0].get("note_card", {})
    note_id = items[0].get("id") or note_card.get("note_id")
    return _safe_path_part(str(note_id or ""), "note")


def download_note_images(data: dict, output_dir: Path | str = DEFAULT_DOWNLOAD_DIR) -> list[SavedImage]:
    """Download images referenced by a note detail payload."""
    note = normalize_note_detail(data)
    if not note:
        return []

    image_urls = note.get("image_urls", [])
    if not image_urls:
        return []

    note_dir = Path(output_dir) / _note_id_from_detail(data)
    note_dir.mkdir(parents=True, exist_ok=True)

    saved_images = []
    with httpx.Client(follow_redirects=True, timeout=30) as client:
        for index, url in enumerate(image_urls, 1):
            response = client.get(url)
            response.raise_for_status()
            image_path = note_dir / f"image-{index}{_image_extension(url)}"
            image_path.write_bytes(response.content)
            saved_images.append(SavedImage(index=index, url=url, path=image_path))
    return saved_images
