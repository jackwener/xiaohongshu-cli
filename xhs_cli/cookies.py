"""Cookie extraction and management for XHS API client."""

from __future__ import annotations

import base64
import functools
import hashlib
import json
import logging
import os
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from .constants import CONFIG_DIR_NAME, COOKIE_FILE, INDEX_CACHE_FILE, TOKEN_CACHE_FILE

logger = logging.getLogger(__name__)

# Cookie TTL: warn and attempt browser refresh after 7 days
COOKIE_TTL_DAYS = 7
_COOKIE_TTL_SECONDS = COOKIE_TTL_DAYS * 86400
COOKIECLOUD_TIMEOUT_SECONDS = 10.0
_TOKEN_CACHE_LOCK = threading.RLock()
_TOKEN_CACHE_MEMORY: OrderedDict[str, dict[str, Any]] | None = None
_TOKEN_CACHE_PATH: Path | None = None
NOTE_CONTEXT_TTL_SECONDS = 86400



def get_config_dir() -> Path:
    """Get or create config directory."""
    config_dir = Path.home() / CONFIG_DIR_NAME
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_cookie_path() -> Path:
    """Get cookie file path."""
    return get_config_dir() / COOKIE_FILE


def get_token_cache_path() -> Path:
    """Get xsec token cache file path."""
    return get_config_dir() / TOKEN_CACHE_FILE


def get_index_cache_path() -> Path:
    """Get note index cache file path."""
    return get_config_dir() / INDEX_CACHE_FILE


def load_saved_cookies() -> dict[str, str] | None:
    """Load cookies from local storage."""
    cookie_path = get_cookie_path()
    if not cookie_path.exists():
        return None
    try:
        data = json.loads(cookie_path.read_text())
        if data.get("a1"):
            logger.debug("Loaded saved cookies from %s", cookie_path)
            return data
    except (OSError, json.JSONDecodeError) as e:
        logger.debug("Failed to load saved cookies: %s", e)
    return None


def save_cookies(cookies: dict[str, str]) -> None:
    """Save cookies to local storage with restricted permissions and TTL timestamp."""
    cookie_path = get_cookie_path()
    payload = {**cookies, "saved_at": time.time()}
    cookie_path.write_text(json.dumps(payload, indent=2))
    cookie_path.chmod(0o600)
    logger.debug("Saved cookies to %s", cookie_path)


def clear_cookies() -> None:
    """Remove saved cookies."""
    cookie_path = get_cookie_path()
    if cookie_path.exists():
        cookie_path.unlink()
        logger.debug("Cleared cookies from %s", cookie_path)


def _normalize_token_entry(value: Any) -> dict[str, Any] | None:
    if isinstance(value, str):
        return {"token": value, "source": "", "ts": time.time()}
    if not isinstance(value, dict):
        return None

    token = str(value.get("token", "")).strip()
    if not token:
        return None

    source = str(value.get("source", "")).strip()
    context = str(value.get("context", "")).strip()
    ts = value.get("ts", 0)
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        ts = 0.0

    entry = {"token": token, "source": source, "ts": ts}
    if context:
        entry["context"] = context
    return entry


def _load_token_cache_from_disk(cache_path: Path) -> OrderedDict[str, dict[str, Any]]:
    if not cache_path.exists():
        return OrderedDict()
    try:
        data = json.loads(cache_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        logger.debug("Failed to load token cache: %s", exc)
        return OrderedDict()
    if not isinstance(data, dict):
        return OrderedDict()

    normalized: list[tuple[str, dict[str, Any]]] = []
    for key, value in data.items():
        if not key:
            continue
        entry = _normalize_token_entry(value)
        if entry:
            normalized.append((str(key), entry))
    normalized.sort(key=lambda item: float(item[1].get("ts", 0)))
    return OrderedDict(normalized)


def _prune_token_cache(
    cache: OrderedDict[str, dict[str, Any]],
    now: float | None = None,
) -> OrderedDict[str, dict[str, Any]]:
    now = now or time.time()
    pruned = OrderedDict(
        (key, value)
        for key, value in cache.items()
        if now - float(value.get("ts", 0)) <= NOTE_CONTEXT_TTL_SECONDS
    )
    while len(pruned) > TOKEN_CACHE_MAX_SIZE:
        pruned.popitem(last=False)
    return pruned


def load_token_cache() -> dict[str, dict[str, Any]]:
    """Load cached note_id -> token context mappings."""
    cache_path = get_token_cache_path()
    global _TOKEN_CACHE_MEMORY, _TOKEN_CACHE_PATH

    with _TOKEN_CACHE_LOCK:
        if _TOKEN_CACHE_MEMORY is None or _TOKEN_CACHE_PATH != cache_path:
            _TOKEN_CACHE_MEMORY = _prune_token_cache(_load_token_cache_from_disk(cache_path))
            _TOKEN_CACHE_PATH = cache_path
        return {
            key: dict(value)
            for key, value in _TOKEN_CACHE_MEMORY.items()
        }


def save_token_cache(cache: dict[str, dict[str, Any]]) -> None:
    """Persist xsec token cache with restricted permissions."""
    cache_path = get_token_cache_path()
    global _TOKEN_CACHE_MEMORY, _TOKEN_CACHE_PATH

    normalized = _prune_token_cache(OrderedDict(
        sorted(
            (
                (str(key), dict(value))
                for key, value in cache.items()
                if key and isinstance(value, dict)
            ),
            key=lambda item: float(item[1].get("ts", 0)),
        )
    ))

    with _TOKEN_CACHE_LOCK:
        cache_path.write_text(json.dumps(normalized, indent=2))
        cache_path.chmod(0o600)
        _TOKEN_CACHE_MEMORY = normalized
        _TOKEN_CACHE_PATH = cache_path


TOKEN_CACHE_MAX_SIZE = 500


def cache_note_context(
    note_id: str,
    xsec_token: str,
    xsec_source: str = "",
    *,
    context: str = "",
) -> None:
    """Store a resolved note token and source for later access.

    Maintains an LRU-style cache capped at TOKEN_CACHE_MAX_SIZE entries.
    Each entry stores token/source/timestamp metadata; overflow evicts the
    oldest entries.
    """
    if not note_id or not xsec_token:
        return
    cache = load_token_cache()

    existing = cache.get(note_id)
    if (
        isinstance(existing, dict)
        and existing.get("token") == xsec_token
        and existing.get("source", "") == xsec_source
        and existing.get("context", "") == context
    ):
        existing["ts"] = time.time()
        save_token_cache(cache)
        return

    entry = {
        "token": xsec_token,
        "source": xsec_source,
        "ts": time.time(),
    }
    if context:
        entry["context"] = context
    cache[note_id] = entry

    # Evict oldest entries if over limit
    if len(cache) > TOKEN_CACHE_MAX_SIZE:
        sorted_keys = sorted(
            cache.keys(),
            key=lambda k: cache[k].get("ts", 0) if isinstance(cache[k], dict) else 0,
        )
        for key in sorted_keys[: len(cache) - TOKEN_CACHE_MAX_SIZE]:
            del cache[key]

    save_token_cache(cache)
    logger.debug("Cached xsec_token for note %s", note_id)


def invalidate_note_context(note_id: str) -> None:
    """Remove cached token/source metadata for a note ID."""
    if not note_id:
        return
    cache = load_token_cache()
    if note_id not in cache:
        return
    del cache[note_id]
    save_token_cache(cache)
    logger.debug("Invalidated cached note context for %s", note_id)


def _normalize_index_entry(value: Any) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None

    note_id = str(value.get("note_id", "")).strip()
    if not note_id:
        return None

    return {
        "note_id": note_id,
        "xsec_token": str(value.get("xsec_token", "")).strip(),
        "xsec_source": str(value.get("xsec_source", "")).strip(),
    }


def save_note_index(items: list[dict[str, str]]) -> None:
    """Persist the latest ordered note index for short-index navigation."""
    path = get_index_cache_path()
    normalized = [
        entry
        for entry in (_normalize_index_entry(item) for item in items)
        if entry
    ]
    path.write_text(json.dumps(normalized, indent=2, ensure_ascii=False))
    path.chmod(0o600)
    logger.debug("Saved note index with %d entries", len(normalized))


def get_note_by_index(index: int) -> dict[str, str] | None:
    """Resolve a 1-based short index to a cached note reference."""
    if index <= 0:
        return None

    path = get_index_cache_path()
    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None

    if not isinstance(data, list) or index > len(data):
        return None

    return _normalize_index_entry(data[index - 1])


def cache_xsec_token(note_id: str, xsec_token: str) -> None:
    """Backwards-compatible wrapper for token-only caching."""
    cache_note_context(note_id, xsec_token)


def get_cached_note_context(note_id: str) -> dict[str, Any]:
    """Get cached token/source metadata for a note ID."""
    entry = load_token_cache().get(note_id)
    if not isinstance(entry, dict):
        return {}
    return {
        "token": str(entry.get("token", "")),
        "source": str(entry.get("source", "")),
        "context": str(entry.get("context", "")),
        "ts": entry.get("ts", 0.0),
    }


def get_cached_xsec_token(note_id: str) -> str:
    """Get a cached xsec token for a note ID."""
    return get_cached_note_context(note_id).get("token", "")


def _load_cookiecloud_config() -> dict[str, str | float]:
    from .exceptions import XhsApiError

    host = os.getenv("COOKIECLOUD_HOST", "").strip().rstrip("/")
    uuid = os.getenv("COOKIECLOUD_UUID", "").strip()
    password = os.getenv("COOKIECLOUD_PASSWORD", "").strip()

    missing = [
        name
        for name, value in (
            ("COOKIECLOUD_HOST", host),
            ("COOKIECLOUD_UUID", uuid),
            ("COOKIECLOUD_PASSWORD", password),
        )
        if not value
    ]
    if missing:
        raise XhsApiError(
            "CookieCloud requires environment variables: "
            f"{', '.join(missing)}. Try: xhs login --cookie-source cookiecloud"
        )

    timeout = COOKIECLOUD_TIMEOUT_SECONDS
    timeout_raw = os.getenv("COOKIECLOUD_TIMEOUT", "").strip()
    if timeout_raw:
        try:
            timeout = float(timeout_raw)
        except ValueError as exc:
            raise XhsApiError("COOKIECLOUD_TIMEOUT must be a positive number of seconds.") from exc
        if timeout <= 0:
            raise XhsApiError("COOKIECLOUD_TIMEOUT must be a positive number of seconds.")

    return {
        "host": host,
        "uuid": uuid,
        "password": password,
        "timeout": timeout,
    }


def _fetch_cookiecloud_payload(config: dict[str, str | float]) -> dict[str, Any]:
    from .exceptions import XhsApiError

    url = f"{config['host']}/get/{config['uuid']}"
    try:
        response = httpx.get(url, timeout=float(config["timeout"]), follow_redirects=True)
        response.raise_for_status()
    except httpx.TimeoutException as exc:
        raise XhsApiError("CookieCloud request timed out. Check COOKIECLOUD_HOST and try again.") from exc
    except httpx.HTTPStatusError as exc:
        raise XhsApiError(
            f"CookieCloud request failed with HTTP {exc.response.status_code}. "
            "Check COOKIECLOUD_HOST and try again."
        ) from exc
    except httpx.HTTPError as exc:
        raise XhsApiError("CookieCloud request failed. Check COOKIECLOUD_HOST and try again.") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise XhsApiError("CookieCloud returned invalid JSON.") from exc

    if not isinstance(payload, dict):
        raise XhsApiError("CookieCloud returned an invalid response payload.")

    encrypted = payload.get("encrypted")
    if not isinstance(encrypted, str) or not encrypted.strip():
        raise XhsApiError("CookieCloud response did not include an encrypted payload.")

    return payload


def _evp_bytes_to_key(password: bytes, salt: bytes, *, key_len: int = 32, iv_len: int = 16) -> tuple[bytes, bytes]:
    derived = b""
    block = b""
    while len(derived) < key_len + iv_len:
        block = hashlib.md5(block + password + salt).digest()
        derived += block
    return derived[:key_len], derived[key_len : key_len + iv_len]


def _cookiecloud_passphrases(uuid: str, password: str) -> tuple[str, ...]:
    candidates = [
        hashlib.md5(f"{uuid}-{password}".encode()).hexdigest()[:16],
        hashlib.md5(f"{uuid}{password}".encode()).hexdigest()[:16],
    ]

    unique: list[str] = []
    for candidate in candidates:
        if candidate not in unique:
            unique.append(candidate)
    return tuple(unique)


def _decrypt_cookiecloud_payload(payload: dict[str, Any], uuid: str, password: str) -> dict[str, Any]:
    from .exceptions import XhsApiError

    encrypted = payload.get("encrypted")
    if not isinstance(encrypted, str) or not encrypted.strip():
        raise XhsApiError("CookieCloud response did not include an encrypted payload.")

    for passphrase in _cookiecloud_passphrases(uuid, password):
        try:
            raw_encrypted = base64.b64decode(encrypted, validate=True)
            if (
                len(raw_encrypted) <= 16
                or len(raw_encrypted) % AES.block_size != 0
                or raw_encrypted[:8] != b"Salted__"
            ):
                continue

            salt = raw_encrypted[8:16]
            ciphertext = raw_encrypted[16:]
            key, iv = _evp_bytes_to_key(passphrase.encode(), salt)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            parsed = json.loads(decrypted.decode())
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            continue

        if isinstance(parsed, dict):
            return parsed

    raise XhsApiError(
        "Failed to decrypt CookieCloud payload. Check COOKIECLOUD_UUID and COOKIECLOUD_PASSWORD."
    )


def _extract_xhs_cookiecloud_cookies(payload: dict[str, Any]) -> dict[str, str] | None:
    from .exceptions import XhsApiError

    cookie_data = payload.get("cookie_data", payload)
    if not isinstance(cookie_data, dict):
        raise XhsApiError("CookieCloud payload did not include a valid cookie_data object.")

    cookies: dict[str, str] = {}
    for domain in ("xiaohongshu.com", ".xiaohongshu.com"):
        entries = cookie_data.get(domain, [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name", "")).strip()
            value = str(entry.get("value", "")).strip()
            if name and value:
                cookies[name] = value

    if not cookies.get("a1"):
        return None
    return cookies


def extract_cookiecloud_cookies() -> tuple[str, dict[str, str]] | None:
    """Fetch, decrypt, and normalize CookieCloud cookies for xiaohongshu.com."""
    config = _load_cookiecloud_config()
    payload = _fetch_cookiecloud_payload(config)
    decrypted = _decrypt_cookiecloud_payload(payload, str(config["uuid"]), str(config["password"]))
    cookies = _extract_xhs_cookiecloud_cookies(decrypted)
    if not cookies:
        logger.debug("No usable Xiaohongshu cookies found in CookieCloud payload")
        return None

    logger.debug("Loaded XHS cookies from CookieCloud")
    return "cookiecloud", cookies


@functools.lru_cache(maxsize=1)
def _available_browsers() -> tuple[str, ...]:
    """List all browser names supported by browser_cookie3 (cached)."""
    import inspect

    import browser_cookie3 as bc3

    return tuple(sorted(
        name
        for name in dir(bc3)
        if not name.startswith("_")
        and name != "load"  # 'load' tries all browsers; skip in auto-detect
        and callable(getattr(bc3, name))
        and hasattr(getattr(bc3, name), "__code__")
        and "domain_name" in inspect.signature(getattr(bc3, name)).parameters
    ))


def _get_browser_loader(source: str):
    """Get browser cookie loader from browser_cookie3 by name."""
    import browser_cookie3 as bc3

    loader = getattr(bc3, source, None)
    if loader is None or not callable(loader):
        available = _available_browsers()
        raise ValueError(
            f"Unknown browser: {source!r}. Available: {', '.join(available)}"
        )
    return loader


def _extract_in_process(source: str) -> dict[str, str] | None:
    """Extract cookies in-process for macOS Keychain compatibility."""
    try:
        loader = _get_browser_loader(source)
    except ImportError:
        logger.debug("browser_cookie3 not installed, skipping in-process extraction")
        return None
    except ValueError as exc:
        logger.debug("%s", exc)
        return None

    try:
        jar = loader(domain_name=".xiaohongshu.com")
    except Exception as exc:
        logger.debug("%s in-process extraction failed: %s", source, exc)
        return None

    cookies = {cookie.name: cookie.value for cookie in jar if "xiaohongshu.com" in (cookie.domain or "")}
    if cookies.get("a1"):
        logger.debug("Loaded XHS cookies from %s in-process", source)
        return cookies

    logger.debug("No usable a1 cookie found in %s in-process extraction", source)
    return None


def _extract_via_subprocess(source: str) -> dict[str, str] | None:
    """Extract cookies via subprocess to avoid browser SQLite locks."""
    extract_script = '''
import json, sys
try:
    import browser_cookie3 as bc3
except ImportError:
    print(json.dumps({"error": "browser-cookie3 not installed"}))
    sys.exit(0)

source = sys.argv[1]
loader = getattr(bc3, source, None)
if not loader or not callable(loader):
    print(json.dumps({"error": f"Unknown browser: {source}"}))
    sys.exit(0)

try:
    cj = loader(domain_name=".xiaohongshu.com")
    cookies = {c.name: c.value for c in cj if "xiaohongshu.com" in (c.domain or "")}
    if cookies.get("a1"):
        print(json.dumps({"browser": source, "cookies": cookies}))
    else:
        print(json.dumps({"error": "no_a1_cookie"}))
except Exception as e:
    print(json.dumps({"error": str(e)}))
'''

    try:
        result = subprocess.run(
            [sys.executable, "-c", extract_script, source],
            capture_output=True,
            text=True,
            timeout=15,
        )

        if result.returncode != 0:
            logger.debug("Cookie extraction subprocess failed: %s", result.stderr)
            return None

        data = json.loads(result.stdout.strip())
        if "error" in data:
            logger.debug("Cookie extraction error: %s", data["error"])
            return None

        return data["cookies"]

    except subprocess.TimeoutExpired:
        logger.debug("Cookie extraction timed out")
        return None
    except (json.JSONDecodeError, KeyError) as e:
        logger.debug("Cookie extraction parse error: %s", e)
        return None


def extract_browser_cookies(source: str = "auto") -> tuple[str, dict[str, str]] | None:
    """
    Extract XHS cookies from browser using browser-cookie3.

    When *source* is ``"auto"``, tries supported browsers with a small
    thread pool and returns the first one that has valid cookies.

    Returns ``(browser_name, cookies)`` on success, or ``None``.
    """
    if source != "auto":
        cookies = _extract_in_process(source)
        if cookies:
            return source, cookies
        cookies = _extract_via_subprocess(source)
        if cookies:
            return source, cookies
        return None

    # Auto-detect: try all available browsers
    try:
        browsers = _available_browsers()
    except ImportError:
        logger.debug("browser_cookie3 not installed")
        return None

    from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

    def _try_browser(browser: str) -> tuple[str, dict[str, str]] | None:
        logger.debug("Auto-detect: trying %s …", browser)
        cookies = _extract_in_process(browser)
        if cookies:
            return browser, cookies
        cookies = _extract_via_subprocess(browser)
        if cookies:
            return browser, cookies
        return None

    with ThreadPoolExecutor(max_workers=min(4, len(browsers) or 1)) as pool:
        pending = {pool.submit(_try_browser, browser) for browser in browsers}
        while pending:
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                result = future.result()
                if result:
                    for rest in pending:
                        rest.cancel()
                    return result

    return None


def get_cookies(
    cookie_source: str = "auto", *, force_refresh: bool = False
) -> tuple[str, dict[str, str]]:
    """
    Multi-strategy cookie acquisition with TTL-based auto-refresh.

    Returns ``(source_name, cookies)``.

    1. Load saved cookies (skip if stale > 7 days)
    2. Extract from the selected cookie source
    3. Raise error if all fail
    """
    def _extract_selected_cookies() -> tuple[str, dict[str, str]] | None:
        if cookie_source == "cookiecloud":
            return extract_cookiecloud_cookies()
        return extract_browser_cookies(cookie_source)

    # 1. Try saved cookies first
    if not force_refresh:
        saved = load_saved_cookies()
        if saved:
            saved = dict(saved)
            saved_at = saved.pop("saved_at", 0)
            if saved_at and (time.time() - float(saved_at)) > _COOKIE_TTL_SECONDS:
                logger.info(
                    "Cookies older than %d days, attempting refresh from %s",
                    COOKIE_TTL_DAYS,
                    cookie_source,
                )
                result = _extract_selected_cookies()
                if result:
                    save_cookies(result[1])
                    return result
                logger.warning(
                    "Cookie refresh failed; using existing cookies (age: %d+ days)",
                    COOKIE_TTL_DAYS,
                )
            return "saved", saved

    # 2. Try browser extraction
    from .exceptions import NoCookieError

    result = _extract_selected_cookies()
    if result:
        save_cookies(result[1])
        return result

    raise NoCookieError(cookie_source)


def cookies_to_string(cookies: dict[str, str]) -> str:
    """Format cookies as a cookie header string."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())
