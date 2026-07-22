---
name: xiaohongshu-cli
description: Use xiaohongshu-cli for ALL Xiaohongshu (Little Red Book, 小红书) operations — searching notes, reading content, browsing users, liking, collecting, commenting, following, and posting. Invoke whenever the user requests any Xiaohongshu interaction.
author: jackwener
version: "0.6.4"
tags:
  - xiaohongshu
  - xhs
  - redbook
  - 小红书
  - social-media
  - cli
---

# xiaohongshu-cli — Xiaohongshu CLI Tool

> **Account risk:** This tool uses unofficial, reverse-engineered APIs. Xiaohongshu may warn, restrict, or suspend accounts for scripted or AI-assisted browsing and writes. Never run background, scheduled, bulk, or autonomous workflows. Stop immediately on `-104`, captcha, IP blocking, or any in-app account warning.

**Binary:** `xhs`
**Credentials:** browser cookies (auto-extracted) or browser-assisted QR login (`--qrcode`)

## Setup

```bash
# Install (requires Python 3.10+)
uv tool install xiaohongshu-cli
# Or: pipx install xiaohongshu-cli

# Upgrade to latest (recommended to avoid API errors)
uv tool upgrade xiaohongshu-cli
# Or: pipx upgrade xiaohongshu-cli
```

## Authentication

**IMPORTANT FOR AGENTS**: Before executing ANY xhs command, check if credentials exist first. Do NOT assume cookies are configured.

### Step 0: Check if already authenticated

```bash
xhs status --yaml >/dev/null && echo "AUTH_OK" || echo "AUTH_NEEDED"
```

If `AUTH_OK`, skip to [Command Reference](#command-reference).
If `AUTH_NEEDED`, proceed to Step 1. Prefer `--qrcode` when browser cookie extraction is unavailable but launching a browser is acceptable.

### Step 1: Guide user to authenticate

Ensure user is logged into xiaohongshu.com in any browser supported by [browser_cookie3](https://github.com/borisbabic/browser_cookie3). Supported browsers: Chrome, Arc, Edge, Firefox, Safari, Brave, Chromium, Opera, Opera GX, Vivaldi, LibreWolf, Lynx, w3m. Then:

```bash
xhs login                              # auto-detect browser with valid cookies
xhs login --cookie-source arc          # specify browser explicitly
xhs login --qrcode                     # browser-assisted QR login with terminal QR output
```

Verify with:

```bash
xhs status
xhs whoami
```

### Step 2: Handle common auth issues

| Symptom | Agent action |
|---------|-------------|
| `NoCookieError: No 'a1' cookie found` | Guide user to login to xiaohongshu.com in browser |
| `NeedVerifyError: Captcha required` | Ask user to open browser, complete captcha, then retry |
| `IpBlockedError: IP blocked` | Stop using the tool; do not switch networks to continue |
| `SessionExpiredError` | Run `xhs login` to refresh cookies |

## Agent Defaults

All machine-readable output uses the envelope documented in [SCHEMA.md](./SCHEMA.md).
Payloads live under `.data`.

- Non-TTY stdout → auto YAML
- `--json` / `--yaml` → explicit format
- `OUTPUT=json` env → global override
- `OUTPUT=rich` env → force human output

## Command Reference

### Reading

| Command | Description | Example |
|---------|-------------|---------|
| `xhs search <keyword>` | Search notes | `xhs search "美食" --sort popular --type video` |
| `xhs read <id_or_url_or_index>` | Read a note by ID, URL, or short index | `xhs read 1` / `xhs read "https://...?xsec_token=xxx"` |
| `xhs comments <id_or_url_or_index>` | Get comments by ID, URL, or short index | `xhs comments 1` / `xhs comments "https://...?xsec_token=..."` |
| `xhs comments <id_or_url> --all` | Get ALL comments (auto-paginate) | `xhs comments "<url>" --all --json` |
| `xhs sub-comments <note_id> <comment_id>` | Get replies to comment | `xhs sub-comments abc 123` |
| `xhs user <user_id>` | View user profile | `xhs user 5f2e123` |
| `xhs user-posts <user_id>` | List user's notes | `xhs user-posts 5f2e123 --cursor ""` |
| `xhs feed` | Browse recommendation feed | `xhs feed --yaml` |
| `xhs hot` | Browse trending notes | `xhs hot -c food` |
| `xhs topics <keyword>` | Search topics/hashtags | `xhs topics "旅行"` |
| `xhs search-user <keyword>` | Search users | `xhs search-user "摄影"` |
| `xhs my-notes` | List own published notes | `xhs my-notes --page 0` |
| `xhs notifications` | View notifications | `xhs notifications --type likes` |
| `xhs unread` | Show unread counts | `xhs unread --json` |

### Interactions (Write)

Every write requires the user to approve the exact action and target immediately before execution. Pass `--yes` only after that approval. A general request to browse, research, or manage an account is not approval to write.

| Command | Description | Example |
|---------|-------------|---------|
| `xhs like <id_or_url_or_index> --yes` | Like a note | `xhs like 1 --yes` |
| `xhs like <id_or_url_or_index> --undo --yes` | Unlike a note | `xhs like 1 --undo --yes` |
| `xhs favorite <id_or_url_or_index> --yes` | Bookmark a note | `xhs favorite 1 --yes` |
| `xhs unfavorite <id_or_url_or_index> --yes` | Remove bookmark | `xhs unfavorite 1 --yes` |
| `xhs comment <id_or_url_or_index> -c "text" --yes` | Post a comment | `xhs comment 1 -c "好看！" --yes` |
| `xhs reply <id_or_url_or_index> --comment-id ID -c "text" --yes` | Reply to comment | `xhs reply 1 --comment-id 456 -c "谢谢" --yes` |
| `xhs delete-comment <note_id> <comment_id>` | Delete own comment | `xhs delete-comment abc 123 -y` |

### Social

| Command | Description | Example |
|---------|-------------|---------|
| `xhs follow <user_id> --yes` | Follow a user | `xhs follow 5f2e123 --yes` |
| `xhs unfollow <user_id> --yes` | Unfollow a user | `xhs unfollow 5f2e123 --yes` |
| `xhs favorites [user_id]` | List bookmarked notes (defaults to self) | `xhs favorites --json` |

### Creator

| Command | Description | Example |
|---------|-------------|---------|
| `xhs post --title "..." --body "..." --images img.png --yes` | Publish a note | `xhs post --title "Test" --body "Hello" --images img.png --yes` |
| `xhs delete <id_or_url>` | Delete own note | `xhs delete abc123 -y` |

### Account

| Command | Description |
|---------|-------------|
| `xhs login` | Extract cookies from browser (auto-detect) |
| `xhs login --qrcode` | Browser-assisted QR login — terminal QR output, browser completes login |
| `xhs status` | Check authentication status |
| `xhs logout` | Clear cached cookies |
| `xhs whoami` | Show current user profile |

## Agent Workflow Examples

### Search → Read

```bash
NOTE_ID=$(xhs search "美食推荐" --json | jq -r '.data.items[0].id')
xhs read "$NOTE_ID" --json | jq '.data'
```

### Browse trending food notes

```bash
xhs hot -c food --json | jq '.data.items[:5] | .[].note_card | {title, likes: .interact_info.liked_count}'
```

### Get user info

```bash
xhs user 5f2e123 --json | jq '.data.basic_info | {nickname, user_id}'
```

### Check notifications

```bash
xhs unread --json | jq '.data'
xhs notifications --type mentions --json | jq '.data.message_list[:5]'
```

### Analyze all comments on a note

```bash
# Fetch ALL comments and analyze themes
xhs comments "$NOTE_URL" --all --json | jq '.data.comments | length'
# Count questions
xhs comments "$NOTE_URL" --all --json | jq '[.data.comments[] | select(.content | test("[\uff1f?]"))] | length'
```

### Daily reading workflow

```bash
# Browse recommendation feed
xhs feed --yaml

# Run one user-requested read action at a time
xhs search "旅行"
xhs read 1
xhs comments 1
```

### QR code login

```bash
# When browser cookie extraction is not available
xhs login --qrcode
# → Launches a browser-assisted login flow
# → Renders QR in terminal using Unicode half-blocks
# → Scan with Xiaohongshu app → confirm → export cookies
```

### URL to insights pipeline

```bash
# User pastes a URL → read + all comments
xhs read "https://www.xiaohongshu.com/explore/xxx?xsec_token=yyy" --json
xhs comments "https://www.xiaohongshu.com/explore/xxx?xsec_token=yyy" --all --json
```

## Hot Categories

Available for `xhs hot -c <category>`:
`fashion`, `food`, `cosmetics`, `movie`, `career`, `love`, `home`, `gaming`, `travel`, `fitness`

## Error Codes

Structured error codes returned in the `error.code` field:
- `not_authenticated` — cookies expired or missing
- `verification_required` — captcha/verification needed
- `ip_blocked` — IP rate limited
- `signature_error` — request signing failed
- `api_error` — upstream API error
- `unsupported_operation` — operation not available

## Limitations

- **No video download** — cannot download note images/videos
- **No DMs** — cannot access private messages
- **No live streaming** — live features not supported
- **No following/followers list** — XHS web API doesn't expose these endpoints
- **Single account** — one set of cookies at a time
- **Rate limited** — built-in Gaussian jitter delay (~1-1.5s) between requests; aggressive usage may trigger captchas or IP blocks

## Account Safety Rules for Agents

- Do not parallelize, batch, schedule, loop, or automatically continue to another command.
- Do not use `comments --all` for agent-driven collection.
- Stop immediately on `-104`, captcha, IP blocking, or an in-app warning. Do not retry from another network or account.
- Require immediate, exact user confirmation for every write; never infer it from a broader task.
- Do not present delays, fingerprints, or request signing as protection from platform enforcement.

## Safety Notes

- Do not ask users to share raw cookie values in chat logs.
- Prefer local browser cookie extraction over manual secret copy/paste.
- If auth fails, ask the user to re-login via `xhs login`.
- Agent should treat cookie values as secrets (do not echo to stdout unnecessarily).
- Built-in rate-limit delay protects accounts; do not bypass it.
- Unofficial API use can still trigger warnings despite rate limiting; no usage pattern is guaranteed safe.
