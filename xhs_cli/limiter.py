"""Cross-process write throttle for sensitive XHS operations.

The CLI is a fresh process per command, so a pure in-memory limiter would
reset every invocation and protect nothing.  This module keeps a rolling-window
token bucket on disk under the CLI config directory, shared by every process.

Default budget is one write per minute (matching the account-safety guidance
in the README).  Override with ``XHS_WRITE_RPM=<n>``; set ``XHS_WRITE_RPM=0``
to disable throttling entirely (tests, or callers that pace themselves).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .cookies import get_config_dir
from .exceptions import RateLimitedError

WINDOW_SECONDS = 60.0
DEFAULT_WRITE_RPM = 1
STATE_FILE = "limiter.json"


def _write_rpm() -> int:
    raw = os.environ.get("XHS_WRITE_RPM")
    if raw is None:
        return DEFAULT_WRITE_RPM
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_WRITE_RPM


def _state_path() -> Path:
    return get_config_dir() / STATE_FILE


def _load() -> dict[str, list[float]]:
    try:
        state = json.loads(_state_path().read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return state if isinstance(state, dict) else {}


def _save(state: dict[str, list[float]]) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp")
    tmp.write_text(json.dumps(state))
    tmp.replace(path)


def check_write_budget(bucket: str) -> None:
    """Consume one token from ``bucket``; raise ``RateLimitedError`` if full.

    The check is a read-modify-write of a small JSON file, so two truly
    concurrent processes can race by one token.  That is acceptable for a
    human-paced CLI and avoids pulling in a file-locking dependency.
    """
    rpm = _write_rpm()
    if rpm <= 0:
        return

    now = time.time()
    state = _load()
    raw_hits = state.get(bucket, [])
    hits: list[float] = []
    if isinstance(raw_hits, list):
        for entry in raw_hits:
            try:
                stamp = float(entry)
            except (TypeError, ValueError):
                continue
            if now - stamp < WINDOW_SECONDS:
                hits.append(stamp)
    if len(hits) >= rpm:
        wait = WINDOW_SECONDS - (now - hits[0])
        raise RateLimitedError(
            f"写入限流：bucket={bucket} 每 {WINDOW_SECONDS:.0f}s 最多 {rpm} 次，"
            f"请 {wait:.1f}s 后再试（XHS_WRITE_RPM=0 可关闭）"
        )

    hits.append(now)
    state[bucket] = hits
    _save(state)


def reset(bucket: str | None = None) -> None:
    """Clear throttling state; mainly for tests and manual troubleshooting."""
    state = _load()
    if bucket is None:
        state = {}
    else:
        state.pop(bucket, None)
    _save(state)
