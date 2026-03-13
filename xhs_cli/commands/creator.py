"""Creator commands: post, my-notes, delete."""

import click

from ..command_normalizers import select_topic_payload
from ..formatter import (
    extract_note_id,
    maybe_print_structured,
    print_info,
    print_success,
    render_creator_notes,
)
from ..note_refs import save_index_from_notes
from ._common import exit_for_error, handle_command, run_client_action, structured_output_options


@click.command()
@click.option("--title", required=True, help="Note title")
@click.option("--body", required=True, help="Note body text")
@click.option("--images", required=True, multiple=True, help="Image file path(s)")
@click.option("--topic", default=None, help="Topic/hashtag to search and attach")
@click.option("--private", "is_private", is_flag=True, help="Publish as private note")
@structured_output_options
@click.pass_context
def post(
    ctx,
    title: str,
    body: str,
    images: tuple[str, ...],
    topic: str | None,
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

        topics = []
        if topic:
            topic_data = client.search_topics(topic)
            topics = select_topic_payload(topic_data, topic)

        return client.create_image_note(
            title=title,
            desc=body,
            image_file_ids=file_ids,
            topics=topics,
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
