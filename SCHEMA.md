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
- `status` returns `data.authenticated` plus `data.user`
- `whoami` returns `data.user`
- common `error.code` values include `not_authenticated`, `verification_required`, `ip_blocked`, `signature_error`, `rate_limited`, `unsupported_operation`, and `api_error`
