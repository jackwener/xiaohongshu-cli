"""Creator commands: post, my-notes, delete, text2img."""

import re
from pathlib import Path

import click

from ..command_normalizers import select_topic_payload
from ..exceptions import XhsApiError
from ..formatter import (
    extract_note_id,
    maybe_print_structured,
    print_info,
    print_success,
    render_creator_notes,
)
from ..note_refs import save_index_from_notes
from ._common import exit_for_error, handle_command, run_client_action, structured_output_options


def extract_hashtags(body: str) -> list[str]:
    """Extract hashtag names from body text.

    Matches '#tag' at start-of-string or preceded by whitespace.
    Does not match URL fragments like 'https://example.com#section'.
    """
    return re.findall(r"(?:^|(?<=\s))#([^\s#]+)", body)


@click.command()
@click.option("--title", required=True, help="Note title")
@click.option("--body", required=True, help="Note body text")
@click.option("--images", required=True, multiple=True, help="Image file path(s)")
@click.option("--topic", "topics_flag", multiple=True, help="Topic(s)/hashtag(s) to search and attach")
@click.option("--private", "is_private", is_flag=True, help="Publish as private note")
@structured_output_options
@click.pass_context
def post(
    ctx,
    title: str,
    body: str,
    images: tuple[str, ...],
    topics_flag: tuple[str, ...],
    is_private: bool,
    as_json: bool,
    as_yaml: bool,
):
    """Publish an image note."""
    def _publish(client):
        file_ids = []
        for img_path in images:
            print_info(f"Uploading {img_path}...")
            permit = client.get_upload_permit()
            client.upload_file(permit["fileId"], permit["token"], img_path)
            file_ids.append(permit["fileId"])
            print_success(f"Uploaded: {img_path}")

        # Combine CLI --topic flags with hashtags found in the body text
        body_hashtags = extract_hashtags(body)
        all_topics = list(topics_flag) + body_hashtags
        unique_topics = list(dict.fromkeys(all_topics))  # deduplicate, preserve order

        if len(unique_topics) > 10:
            print_info(f"Found {len(unique_topics)} topics, using first 10")
            unique_topics = unique_topics[:10]

        resolved_topics = []
        for t in unique_topics:
            topic_data = client.search_topics(t)
            resolved_topics.extend(select_topic_payload(topic_data, t))

        return client.create_image_note(
            title=title,
            desc=body,
            image_file_ids=file_ids,
            topics=resolved_topics,
            is_private=is_private,
        )

    handle_command(
        ctx,
        action=_publish,
        render=lambda _data: print_success(f"Note published: {title}" + (" (private)" if is_private else "")),
        as_json=as_json,
        as_yaml=as_yaml,
    )


@click.command("my-notes")
@click.option("--page", default=0, help="Page number (0-indexed)")
@structured_output_options
@click.pass_context
def my_notes(ctx, page: int, as_json: bool, as_yaml: bool):
    """List your own published notes."""
    def _my_notes_action(client):
        data = client.get_creator_note_list(page=page)
        notes = data.get("notes", data.get("note_list", []))
        save_index_from_notes(notes)
        return data

    handle_command(
        ctx,
        action=_my_notes_action,
        render=render_creator_notes,
        as_json=as_json,
        as_yaml=as_yaml,
    )


@click.command("delete")
@click.argument("id_or_url")
@structured_output_options
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation")
@click.pass_context
def delete(ctx, id_or_url: str, as_json: bool, as_yaml: bool, yes: bool):
    """Delete a note. Experimental: the public web endpoint is unstable."""
    note_id = extract_note_id(id_or_url)

    if not yes:
        click.confirm(f"Delete note {note_id}?", abort=True)

    try:
        data = run_client_action(ctx, lambda client: client.delete_note(note_id))
        if not maybe_print_structured(data, as_json=as_json, as_yaml=as_yaml):
            print_success(f"Deleted note {note_id}")
    except Exception as exc:
        exit_for_error(exc, as_json=as_json, as_yaml=as_yaml)


@click.command("text2img")
@click.option("--text", required=True, help="Text content to render as image")
@click.option(
    "--page", "page_num", default=1, show_default=True,
    help="Style page number (1 = first batch of styles)",
)
@click.option(
    "--download", "download_dir", default=None,
    help="Download all style images to this directory (default: print URLs only)",
)
@structured_output_options
@click.pass_context
def text2img(
    ctx,
    text: str,
    page_num: int,
    download_dir: str | None,
    as_json: bool,
    as_yaml: bool,
):
    """Generate cover images from text via Xiaohongshu text2imgv3 API.

    Returns multiple style variants (基础/弥散/插图/简约/涂写 etc.) per request.
    By default prints each style's image URL; use --download to save them locally.
    """

    def _text2img_action(client):
        data = client.text2img(text=text, page_num=page_num)
        if download_dir:
            results = data.get("text2_img_type_results", []) if isinstance(data, dict) else []
            failures = _download_images(results, download_dir)
            if failures:
                failed_names = ", ".join(a for a, _ in failures)
                raise XhsApiError(
                    f"{len(failures)} image(s) failed to download: {failed_names}"
                )
        return data

    def _render(data):
        results = data.get("text2_img_type_results", []) if isinstance(data, dict) else []
        if not results:
            print_info("No image styles returned")
            return

        print_success(f"Generated {len(results)} style(s):")
        for i, item in enumerate(results):
            album = item.get("album_name", "unknown")
            img_url = item.get("img_url", "")
            config_id = item.get("config_id", "")
            print(f"  [{i}] {album} (config_id={config_id})")
            print(f"      {img_url}")

        has_next = data.get("has_next", False) if isinstance(data, dict) else False
        if has_next:
            print_info("More styles available, use --page 2 for next batch")

    handle_command(
        ctx,
        action=_text2img_action,
        render=_render,
        as_json=as_json,
        as_yaml=as_yaml,
    )


def _download_images(
    results: list[dict], download_dir: str
) -> list[tuple[str, str]]:
    """下载生成的各风格图片到指定目录。

    返回失败列表 [(album, error_message), ...],调用方据此决定是否非零退出。
    文件名做 slug 化处理并校验解析后路径仍在 download_dir 内,防止接口返回值越权写入。
    """
    import httpx

    out_dir = Path(download_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    failures: list[tuple[str, str]] = []
    used_names: set[str] = set()

    for i, item in enumerate(results):
        album = item.get("album_name") or f"style_{i}"
        img_url = item.get("img_url", "")
        if not img_url:
            continue

        # slug 化文件名:只保留非路径分隔符的字符,防止 ../ 或绝对路径注入
        safe_stem = re.sub(r"[^\w\u4e00-\u9fff.()-]+", "_", album).strip("._") or f"style_{i}"
        ext = ".jpg"
        for e in (".png", ".jpg", ".jpeg", ".webp"):
            if e in img_url:
                ext = e
                break
        # 同名去重
        filename = f"{safe_stem}{ext}"
        n = 1
        while filename in used_names:
            filename = f"{safe_stem}_{n}{ext}"
            n += 1
        used_names.add(filename)

        # 校验解析后路径仍在 download_dir 内
        filepath = (out_dir / filename).resolve()
        if not filepath.is_relative_to(out_dir):
            failures.append((album, f"resolved path escapes download dir: {filepath}"))
            continue

        try:
            resp = httpx.get(img_url, timeout=30.0, follow_redirects=True)
            resp.raise_for_status()
            filepath.write_bytes(resp.content)
            print_success(f"Downloaded: {filepath}")
        except Exception as exc:
            failures.append((album, str(exc)))
            print_info(f"Failed to download {album}: {exc}")

    return failures
