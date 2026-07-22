# Structured Output Schema

`xiaohongshu-cli` uses a shared agent-friendly envelope for machine-readable output.

## Success

```yaml
ok: true
schema_version: "1"
data: ...
```

## Error

```yaml
ok: false
schema_version: "1"
error:
  code: not_authenticated
  message: need login
```

## Notes

- `--yaml` and `--json` both use this envelope
- non-TTY stdout defaults to YAML
- reading and search commands return their payload under `data`
- `hydrate` returns normalized `data.note`, a bounded `data.comments` sample,
  and `data.warnings` for recoverable comment-fetch failures
- `status` returns `data.authenticated` plus `data.user`
- `whoami` returns `data.user`
- common `error.code` values include `not_authenticated`, `verification_required`, `ip_blocked`, `signature_error`, `unsupported_operation`, and `api_error`

## Hydrate

`xhs hydrate <id_or_url_or_index> --yaml` returns a stable, agent-facing note
shape without requiring separate `read` and `comments` calls:

```yaml
ok: true
schema_version: "1"
data:
  note:
    id: note-id
    url: https://www.xiaohongshu.com/explore/note-id
    title: Example
    body: Note body
    author: {id: user-id, name: Author}
    note_type: image
    liked_count: 0
    collected_count: 0
    comment_count: 0
    share_count: 0
    tags: []
    images: []
    published_at: "2026-07-22T12:00:00Z"
  comments:
    - nickname: Commenter
      content: Example comment
      like_count: "0"
      sub_comment_count: 0
      published_at: "2026-07-22T12:01:00Z"
  warnings:
    - code: signature_error
      message: Signature verification failed
```

`warnings` is empty when comment retrieval succeeds. A warning means note
hydration succeeded but the optional comment sample was unavailable.
