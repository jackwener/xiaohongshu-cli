# xiaohongshu-cli

[![CI](https://github.com/jackwener/xiaohongshu-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/jackwener/xiaohongshu-cli/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/xiaohongshu-cli.svg)](https://pypi.org/project/xiaohongshu-cli/)
[![Python](https://img.shields.io/badge/python-%3E%3D3.10-blue.svg)](https://pypi.org/project/xiaohongshu-cli/)

A CLI for Xiaohongshu (小红书) — search, read, interact, and post via reverse-engineered API 📕

[English](#features) | [中文](#功能特性)

## More Tools

- [bilibili-cli](https://github.com/jackwener/bilibili-cli) — Bilibili CLI for videos, users, search, and feeds
- [twitter-cli](https://github.com/jackwener/twitter-cli) — Twitter/X CLI for timelines, bookmarks, and posting
- [discord-cli](https://github.com/jackwener/discord-cli) — Discord CLI for local-first sync, search, and export
- [tg-cli](https://github.com/jackwener/tg-cli) — Telegram CLI for local-first sync, search, and export

## Features

- 🔐 **Auth** — auto-extract browser cookies, QR code login, status check, whoami
- 🔍 **Search** — notes by keyword, user search, topic search
- 📖 **Reading** — note detail, comments, sub-comments, user profiles
- 🔢 **Short-index navigation** — open recent list results with `xhs read 1` or `xhs comments 1`
- 📰 **Feed** — recommendation feed, hot/trending by category
- 👥 **Social** — follow/unfollow, favorites
- 👍 **Interactions** — like, favorite, comment, reply, delete
- ✍️ **Creator** — post image notes, my-notes list, delete
- 🔔 **Notifications** — unread count, mentions, likes, new followers
- 🛡️ **Anti-detection** — consistent macOS Chrome fingerprint, `sec-ch-ua` alignment, session-stable browser identity, Gaussian jitter, captcha cooldown, exponential backoff
- 📊 **Structured output** — commands support `--yaml` and `--json`; non-TTY stdout defaults to YAML
- 📦 **Stable envelope** — see [SCHEMA.md](./SCHEMA.md) for `ok/schema_version/data/error`

> **AI Agent Tip:** Prefer `--yaml` for structured output unless strict JSON is required. Non-TTY stdout defaults to YAML automatically.

## Installation

```bash
# Recommended: uv tool (fast, isolated)
uv tool install xiaohongshu-cli

# Or: pipx
pipx install xiaohongshu-cli
```

Upgrade to the latest version:

```bash
uv tool upgrade xiaohongshu-cli
# Or: pipx upgrade xiaohongshu-cli
```

> **Tip:** Upgrade regularly to avoid unexpected errors from outdated API handling.

From source:

```bash
git clone git@github.com:jackwener/xiaohongshu-cli.git
cd xiaohongshu-cli
uv sync
```

## Usage

```bash
# ─── Auth ─────────────────────────────────────────
xhs login                             # Extract cookies from browser
xhs login --qrcode                    # Browser-assisted QR login, scan in terminal
xhs status                            # Check login status
xhs whoami                            # Detailed profile (fans, likes, etc)
xhs whoami --json                     # Structured JSON envelope
xhs logout                            # Clear saved cookies

# ─── Search ───────────────────────────────────────
xhs search "美食"                      # Search notes
xhs search "旅行" --sort popular       # Sort: general, popular, latest
xhs search "穿搭" --type video         # Filter: all, video, image
xhs search "AI" --page 2              # Pagination
xhs search-user "用户名"               # Search users
xhs topics "美食"                      # Search hashtags/topics

# ─── Reading ──────────────────────────────────────
xhs read 1                             # Read the 1st result from the last list command
xhs read <note_id>                     # Read a note (API only)
xhs read "https://www.xiaohongshu.com/explore/xxx?xsec_token=yyy"  # Read by URL (uses URL token)
xhs comments 1                         # Read comments for the 1st result from the last list command
xhs comments "<url>"                   # View comments — paste URL to cache/reuse xsec_token
xhs comments "<url>" --all             # Fetch ALL comments (auto-paginate all pages)
xhs comments "<url>" --all --json      # All comments as JSON
xhs comments <note_id> --xsec-token T  # Use note_id + explicit xsec_token
xhs comments <note_id>                 # Reuse cached token if available
xhs sub-comments <note_id> <cmt_id>   # View replies to a comment
xhs user <user_id>                     # User profile
xhs user-posts <user_id>              # User's published notes
xhs user-posts <user_id> --cursor X   # Paginate with cursor

# ─── Feed & Discovery ────────────────────────────
xhs feed                              # Recommendation feed
xhs hot                               # Hot notes (default: food)
xhs hot -c fashion                    # Categories: fashion, food, cosmetics,
                                      #   movie, career, love, home, gaming,
                                      #   travel, fitness

# Short index works after list commands such as search/feed/hot/user-posts/favorites/my-notes
xhs search "黑丝"
xhs read 1
xhs comments 1
xhs like 1
xhs favorite 1

# ─── Social ───────────────────────────────────────
xhs favorites                          # My bookmarked notes (current user)
xhs favorites <user_id>                # Other user's bookmarked notes
xhs follow <user_id>                   # Follow a user
xhs unfollow <user_id>                 # Unfollow a user

# ─── Interactions ─────────────────────────────────
xhs like 1                             # Like the 1st result from the latest note listing
xhs like <note_id>                     # Like a note
xhs like <note_id> --undo             # Unlike
xhs favorite 1                         # Favorite the 1st result from the latest note listing
xhs favorite <note_id>                 # Favorite (bookmark)
xhs unfavorite 1                       # Unfavorite the 1st result from the latest note listing
xhs unfavorite <note_id>               # Unfavorite
xhs comment 1 -c "好赞！"              # Comment on the 1st result from the latest note listing
xhs comment <note_id> -c "好赞！"     # Post comment
xhs reply 1 --comment-id X -c "回复"   # Reply on the 1st result from the latest note listing
xhs reply <note_id> --comment-id X -c "回复"  # Reply to comment
xhs delete-comment <note_id> <cmt_id> # Delete own comment

# ─── Creator ─────────────────────────────────────
xhs my-notes                           # List own notes (v2 creator endpoint)
xhs my-notes --page 1                 # Next page
xhs post --title "标题" --body "正文" --images img.jpg  # Post note
xhs delete <note_id>                   # Delete note
xhs delete <note_id> -y               # Skip confirmation

# ─── Notifications ────────────────────────────────
xhs unread                             # Unread counts (likes, mentions, follows)
xhs notifications                      # 评论和@ notifications
xhs notifications --type likes        # 赞和收藏 notifications
xhs notifications --type connections   # 新增关注 notifications

```

## Authentication

xiaohongshu-cli supports multiple authentication methods:

1. **Saved cookies** — loads from `~/.xiaohongshu-cli/cookies.json`
2. **Browser cookies** — auto-detects installed browsers and extracts cookies (supports Chrome, Arc, Edge, Firefox, Safari, Brave, Chromium, Opera, Vivaldi, and more)
3. **QR code login** — browser-assisted login with terminal QR output (`xhs login --qrcode`)

`xhs login` automatically tries all installed browsers and uses the first one with valid cookies.
Use `--cookie-source <browser>` to specify a browser explicitly, or `--qrcode` for browser-assisted QR login.
Other authenticated commands automatically retry once with fresh browser cookies when the saved session has expired.

### Cookie TTL

Saved cookies are valid for **7 days** by default. After that, the client automatically attempts to refresh from the browser. If browser extraction fails, the existing cookies are used with a warning.

### Short-Index Navigation

After any listing command such as `search`, `feed`, `hot`, `user-posts`, `favorites`, or `my-notes`, the CLI stores the latest ordered note list in `~/.xiaohongshu-cli/index_cache.json`.

- `xhs read <N>` opens the Nth note from the latest listing
- `xhs comments <N>` opens comments for the Nth note from the latest listing
- `xhs like <N>`, `xhs favorite <N>`, `xhs unfavorite <N>`, `xhs comment <N>`, and `xhs reply <N>` reuse the same short index
- Empty listings clear the index cache, so old results are not reused by accident

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OUTPUT` | `auto` | Output format: `json`, `yaml`, `rich`, or `auto` (→ YAML when non-TTY) |
## Rate Limiting & Anti-Detection

xiaohongshu-cli includes comprehensive anti-risk-control measures designed to minimize detection:

### Request Timing
- **Gaussian jitter**: Delays between requests use a truncated Gaussian distribution (not fixed intervals) to mimic natural browsing patterns
- **Random long pauses**: ~5% of requests include an additional 2-5 second delay simulating reading behavior
- **Auto-retry**: Exponential backoff on HTTP 429/5xx and network errors (up to 3 retries)

### Browser Fingerprint Consistency
- **UA/Platform alignment**: User-Agent, `sec-ch-ua`, `sec-ch-ua-platform`, and fingerprint fields are all consistent (macOS Chrome 145)
- **Session-stable identity**: GPU, screen resolution, CPU cores, and other hardware fingerprint values are generated once per session and reused across all requests (real browsers don't change hardware mid-session)
- **macOS-native values**: GPU vendors (Apple M1/M2/M3, Intel Iris), Retina screen resolutions, `MacIntel` platform — all matching a real macOS browser

### Captcha Cooldown
- **Progressive backoff**: On captcha trigger (HTTP 461/471), automatically sleeps 5→10→20→30 seconds with increasing delays
- **Adaptive rate limiting**: Request delay is permanently doubled after a captcha event to reduce future risk

### Signed Requests
- All API calls use `x-s` / `x-s-common` / `x-t` signatures (reverse-engineered from web client)
- `x-b3-traceid` and `x-xray-traceid` for distributed tracing consistency

## Structured Output

All `--json` / `--yaml` output uses the shared envelope from [SCHEMA.md](./SCHEMA.md):
```yaml
ok: true
schema_version: "1"
data: { ... }
```

When stdout is not a TTY (e.g., piped or invoked by an AI agent), output defaults to YAML.
Use `OUTPUT=yaml|json|rich|auto` to override.

## Use as AI Agent Skill

xiaohongshu-cli ships with a [`SKILL.md`](./SKILL.md) that teaches AI agents how to use it.

### Claude Code / Antigravity

```bash
# Clone into your project's skills directory
mkdir -p .agents/skills
git clone git@github.com:jackwener/xiaohongshu-cli.git .agents/skills/xiaohongshu-cli

# Or just copy the SKILL.md
curl -o .agents/skills/xiaohongshu-cli/SKILL.md \
  https://raw.githubusercontent.com/jackwener/xiaohongshu-cli/main/SKILL.md
```

### OpenClaw / ClawHub

```bash
clawhub install xiaohongshu-cli
```

## Project Structure

```text
xhs_cli/
├── __init__.py
├── cli.py              # Click entry point & command registration
├── client.py           # XHS API client (signing, retry, rate-limit, anti-detection)
├── cookies.py          # Cookie extraction, TTL management, auto-refresh, token cache
├── signing.py          # Main API x-s / x-s-common signature generation
├── creator_signing.py  # Creator API AES-128-CBC signature
├── constants.py        # URLs, User-Agent, Chrome version, SDK config
├── exceptions.py       # Structured exception hierarchy (6 error types)
├── qr_login.py         # QR code login (browser-assisted terminal QR + HTTP fallback)
├── formatter.py        # Output formatting, schema envelope, Rich rendering
└── commands/
    ├── _common.py      # Shared CLI helpers (structured_output_options, etc.)
    ├── auth.py         # login/logout/status/whoami
    ├── reading.py      # search/read/comments/user/feed/hot/topics/search-user
    ├── interactions.py  # like/favorite/comment/reply/delete-comment
    ├── social.py       # follow/unfollow/favorites
    ├── creator.py      # post/my-notes/delete
    └── notifications.py # unread/notifications
```

## Development

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest tests/ -v

# Unit tests only (no network)
uv run pytest tests/ -v --ignore=tests/test_integration.py -m "not smoke"

# Smoke tests (need cookies)
uv run pytest tests/ -v -m smoke

# Integration tests (need cookies)
uv run pytest tests/test_integration.py -v

# Lint
uv run ruff check .
```

## Troubleshooting

**Q: `NoCookieError: No 'a1' cookie found`**

1. Open any browser and visit https://www.xiaohongshu.com/
2. Log in with your account
3. Run `xhs login` (auto-detects browser) or `xhs login --cookie-source <browser>`

**Q: `NeedVerifyError: Captcha required`**

XHS has triggered a captcha check. Open https://www.xiaohongshu.com/ in your browser, complete the captcha, then retry.

**Q: `IpBlockedError: IP blocked by XHS`**

Try a different network (e.g., mobile hotspot or VPN). XHS blocks IPs that make too many requests.

**Q: `SessionExpiredError: Session expired`**

Your cookies have expired. Run `xhs login` to refresh.

**Q: Requests are slow**

The built-in Gaussian jitter delay (~1-1.5s between requests) is intentional to mimic natural browsing and avoid triggering XHS's risk control. Aggressive request patterns may lead to captcha triggers or IP blocks.

---

## 推荐项目

- [bilibili-cli](https://github.com/jackwener/bilibili-cli) — Bilibili 视频、用户、搜索与动态 CLI
- [twitter-cli](https://github.com/jackwener/twitter-cli) — Twitter/X 时间线、书签和发推 CLI
- [discord-cli](https://github.com/jackwener/discord-cli) — Discord 本地优先同步、检索与导出 CLI
- [tg-cli](https://github.com/jackwener/tg-cli) — Telegram 本地优先同步、检索与导出 CLI

## 功能特性

- 🔐 **认证** — 自动提取浏览器 Cookie，browser-assisted 二维码扫码登录，状态检查，用户信息
- 🔍 **搜索** — 按关键词搜索笔记、用户、话题
- 📖 **阅读** — 笔记详情、评论、子评论、用户主页
- 📰 **发现** — 推荐 Feed、按分类浏览热门
- 👥 **社交** — 关注/取关、收藏夹
- 👍 **互动** — 点赞、收藏、评论、回复、删除
- ✍️ **创作者** — 发布图文笔记、我的笔记列表、删除
- 🔔 **通知** — 未读数、@、点赞、新关注
- 🛡️ **反风控** — macOS Chrome 指纹一致性、session 级浏览器身份持久化、高斯抖动延迟、验证码自动冷却、指数退避重试
- 📊 **结构化输出** — `--yaml` / `--json`，非 TTY 默认输出 YAML
- 📦 **稳定 envelope** — 参见 [SCHEMA.md](./SCHEMA.md)

## 安装

```bash
# 推荐：uv tool（快速、隔离环境）
uv tool install xiaohongshu-cli

# 或者：pipx
pipx install xiaohongshu-cli
```

升级到最新版本：

```bash
uv tool upgrade xiaohongshu-cli
# 或：pipx upgrade xiaohongshu-cli
```

> **提示：** 建议定期升级，避免因版本过旧导致的 API 调用异常。

从源码安装：

```bash
git clone git@github.com:jackwener/xiaohongshu-cli.git
cd xiaohongshu-cli
uv sync
```

## 使用示例

```bash
# 认证
xhs login                             # 从浏览器提取 Cookie
xhs login --qrcode                    # browser-assisted 二维码扫码登录（终端显示二维码）
xhs status                            # 检查登录状态
xhs whoami                            # 查看用户资料
xhs logout                            # 清除缓存的 Cookie

# 搜索
xhs search "美食"                      # 搜索笔记
xhs search "旅行" --sort popular       # 排序：general, popular, latest
xhs search-user "用户名"               # 搜索用户
xhs topics "美食"                      # 搜索话题

# 阅读
xhs read 1                             # 阅读最近一次列表里的第 1 条笔记
xhs read <note_id>                     # 阅读笔记（仅走 API）
xhs read "https://...?xsec_token=..."  # 粘贴网页 URL 直接阅读（使用 URL token）
xhs comments 1                         # 查看最近一次列表里的第 1 条笔记评论
xhs comments "<url>"                   # 查看评论 — 粘贴 URL 以缓存/复用 xsec_token
xhs comments "<url>" --all             # 获取全部评论（自动翻页）
xhs comments "<url>" --all --json      # 全部评论，JSON 格式
xhs comments <note_id> --xsec-token T  # 用 note_id + 显式 xsec_token
xhs comments <note_id>                 # 如果之前访问过 URL，会复用缓存 token
xhs sub-comments <note_id> <cmt_id>   # 查看评论的回复
xhs user <user_id>                     # 用户主页
xhs user-posts <user_id>              # 用户发布的笔记

# 发现
xhs feed                              # 推荐 Feed
xhs hot -c food                       # 热门笔记（按分类）
xhs hot -c travel                     # 分类: fashion, food, cosmetics, movie, career,
                                      #       love, home, gaming, travel, fitness

# 社交
xhs favorites                          # 我的收藏（自动识别当前用户）
xhs favorites <user_id>                # 其他用户的收藏
xhs follow <user_id>                   # 关注
xhs unfollow <user_id>                 # 取消关注

# 互动
xhs like 1                             # 给最近一次列表里的第 1 条笔记点赞
xhs like <note_id>                     # 点赞
xhs like <note_id> --undo              # 取消点赞
xhs favorite 1                         # 收藏最近一次列表里的第 1 条笔记
xhs favorite <note_id>                 # 收藏
xhs unfavorite 1                       # 取消收藏最近一次列表里的第 1 条笔记
xhs unfavorite <note_id>               # 取消收藏
xhs comment 1 -c "好棒！"              # 给最近一次列表里的第 1 条笔记发评论
xhs comment <note_id> -c "好棒！"      # 发评论
xhs reply 1 --comment-id X -c "谢谢"   # 给最近一次列表里的第 1 条笔记回复评论
xhs reply <note_id> --comment-id X -c "谢谢"  # 回复评论
xhs delete-comment <note_id> <cmt_id>  # 删除自己的评论

# 创作者
xhs my-notes                           # 我的笔记列表
xhs post --title "标题" --body "正文" --images img.jpg  # 发布笔记
xhs delete <note_id>                   # 删除笔记
xhs delete <note_id> -y                # 跳过确认

# 通知
xhs unread                             # 未读数
xhs notifications                      # 评论和 @ 通知
xhs notifications --type likes         # 赞和收藏通知
xhs notifications --type connections   # 新增关注通知
```

## 认证策略

xiaohongshu-cli 支持多种认证方式：

1. **已保存 Cookie** — 从 `~/.xiaohongshu-cli/cookies.json` 加载
2. **浏览器 Cookie** — 自动检测已安装浏览器并提取（支持 Chrome、Arc、Edge、Firefox、Safari、Brave、Chromium、Opera、Vivaldi 等）
3. **二维码扫码登录** — browser-assisted 登录，终端显示二维码，用小红书 App 扫码（`xhs login --qrcode`）

Cookie 保存后有效期 **7 天**，超时后自动尝试从浏览器刷新。

`xhs login` 会自动尝试所有已安装浏览器，使用第一个有有效 Cookie 的浏览器。也可用 `--cookie-source <browser>` 指定浏览器，或 `--qrcode` 使用 browser-assisted 二维码登录。其他需认证命令在 session 过期时会自动重试一次。

## 常见问题

- `NoCookieError: No 'a1' cookie found` — 请先在任意浏览器打开 https://www.xiaohongshu.com/ 并登录，然后执行 `xhs login`
- `NeedVerifyError` — 触发了验证码，请到浏览器中完成验证后重试
- `IpBlockedError` — IP 被限制，尝试切换网络（手机热点或 VPN）
- `SessionExpiredError` — Cookie 过期，执行 `xhs login` 刷新
- 请求较慢是正常的 — 内置高斯随机延迟（~1-1.5s）是为了模拟人类浏览行为，避免触发风控

## 作为 AI Agent Skill 使用

xiaohongshu-cli 自带 [`SKILL.md`](./SKILL.md)，让 AI Agent 能自动学习并使用本工具。

### Claude Code / Antigravity

```bash
mkdir -p .agents/skills
git clone git@github.com:jackwener/xiaohongshu-cli.git .agents/skills/xiaohongshu-cli
```

### OpenClaw / ClawHub

```bash
clawhub install xiaohongshu-cli
```

## License

Apache-2.0
