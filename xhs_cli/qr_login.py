"""QR login in CloakBrowser. Library calls return verified credentials, never save them."""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .browser import BrowserUnavailable, browser_page
from .client import XhsClient
from .exceptions import XhsApiError

LOGIN_URL = "https://www.xiaohongshu.com/login"
QR_CREATE_ENDPOINT = "/api/sns/web/v1/login/qrcode/create"
QR_USERINFO_ENDPOINT = "/api/qrcode/userinfo"
QR_STATUS_ENDPOINT = "/api/sns/web/v1/login/qrcode/status"
POLL_TIMEOUT_S = 240
COOKIE_NAMES = frozenset(
    {
        "a1",
        "webId",
        "web_session",
        "web_session_sec",
        "id_token",
        "websectiga",
        "sec_poison_id",
        "xsecappid",
        "gid",
        "abRequestId",
        "webBuild",
        "loadts",
    }
)


class QrLoginError(XhsApiError):
    """Safe structured diagnostics: never include response bodies, QR secrets or cookies."""

    def __init__(self, stage: str, message: str, code: int | str | None = None):
        self.stage = stage
        super().__init__(f"QR login failed during {stage}: {message}", code=code)


@dataclass(frozen=True)
class QrLoginResult:
    cookies: dict[str, str] = field(repr=False)
    user: dict[str, Any] = field(repr=False)


def _payload(response: Any, stage: str) -> dict[str, Any]:
    if response.status >= 400:
        code = "verification_required" if response.status in (461, 471) else response.status
        raise QrLoginError(stage, f"HTTP {response.status}", code=code)
    try:
        payload = response.json()
    except Exception:
        raise QrLoginError(stage, "invalid JSON response") from None
    if not isinstance(payload, dict):
        raise QrLoginError(stage, "invalid response shape")
    if payload.get("success") is False:
        raise QrLoginError(stage, "platform rejected the request")
    data = payload.get("data", payload)
    if not isinstance(data, dict):
        raise QrLoginError(stage, "invalid response data")
    return data


def _user_id(info: dict[str, Any]) -> str:
    basic = info.get("basic_info", {})
    value = info.get("user_id") or info.get("userid") or (basic.get("user_id") if isinstance(basic, dict) else None)
    return value if isinstance(value, str) else ""


def _cookies(raw: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    result = {}
    for entry in raw:
        raw_domain = entry.get("domain")
        if not isinstance(raw_domain, str):
            continue
        domain = raw_domain.lstrip(".")
        name, value = entry.get("name"), entry.get("value")
        if (domain == "xiaohongshu.com" or domain.endswith(".xiaohongshu.com")) and name in COOKIE_NAMES:
            if isinstance(value, str) and value:
                result[name] = value
    return result


def _render_qr(url: str) -> None:
    import qrcode

    qr = qrcode.QRCode(border=4)
    qr.add_data(url)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    for row in range(0, len(matrix), 2):
        print(
            "".join(
                " ▄▀█"[int(matrix[row][col]) * 2 + int(row + 1 < len(matrix) and matrix[row + 1][col])]
                for col in range(len(matrix))
            )
        )


def qrcode_login(
    *,
    timeout_s: float = POLL_TIMEOUT_S,
    on_qr: Callable[[str], None] | None = None,
    on_status: Callable[[str], None] | None = None,
) -> QrLoginResult:
    """Run one QR attempt, verify its account, and return without touching credential files.

    Callbacks run synchronously. ``on_qr`` owns rendering; default output is a
    compact terminal QR. Phone confirmation alone is never authentication.
    """
    if (
        isinstance(timeout_s, bool)
        or not isinstance(timeout_s, (int, float))
        or not math.isfinite(timeout_s)
        or timeout_s <= 0
    ):
        raise ValueError("timeout_s must be a positive finite number")
    emit = on_status or print
    render = on_qr or _render_qr
    deadline = time.monotonic() + timeout_s
    stage = "browser startup"
    created: dict[str, Any] | None = None
    completed: dict[str, Any] | None = None
    error: QrLoginError | None = None
    confirmed_id = ""
    last_status = None

    def remaining_ms() -> float:
        remaining = (deadline - time.monotonic()) * 1000
        if remaining <= 0:
            raise QrLoginError(stage, "timed out; retry explicitly")
        return remaining

    def response_received(response: Any) -> None:
        nonlocal created, completed, error, confirmed_id, last_status
        url = urlsplit(response.url)
        host = url.hostname or ""
        if url.scheme != "https" or not (host == "xiaohongshu.com" or host.endswith(".xiaohongshu.com")):
            return
        path, method = url.path, response.request.method
        try:
            if path == QR_CREATE_ENDPOINT and method == "POST":
                candidate = _payload(response, "QR creation")
                if created is not None and candidate != created:
                    raise QrLoginError("QR creation", "QR was replaced; retry explicitly")
                created = candidate
            elif path == QR_STATUS_ENDPOINT and method == "GET":
                completed = _payload(response, "session completion")
            elif path == QR_USERINFO_ENDPOINT:
                data = _payload(response, "phone confirmation")
                status = data.get("codeStatus")
                if status not in (0, 1, 2):
                    raise QrLoginError("phone confirmation", "QR expired, rejected or returned an unknown status")
                if status == 2:
                    value = data.get("userId")
                    confirmed_id = value if isinstance(value, str) else ""
                last_status = status
        except QrLoginError as exc:
            error = exc

    try:
        with browser_page() as page:
            # Register before navigation so fast completion cannot race a later waiter.
            page.on("response", response_received)
            stage = "login page"
            page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=min(30_000, remaining_ms()))
            shown = False
            reported_status = None
            while True:
                if error is not None:
                    raise error
                if created is not None and not shown:
                    url = created.get("url")
                    if not isinstance(url, str) or not url:
                        raise QrLoginError("QR creation", "QR URL missing")
                    emit("Scan the QR code with the Xiaohongshu app:")
                    render(url)
                    emit("Waiting for QR code scan...")
                    shown = True
                    stage = "phone confirmation"
                if last_status != reported_status:
                    reported_status = last_status
                    if last_status == 1:
                        emit("Scanned; waiting for phone confirmation...")
                    elif last_status == 2:
                        stage = "session completion"
                        emit("Phone confirmed; completing authenticated session (not logged in yet)...")
                if shown and completed is not None:
                    break
                page.wait_for_timeout(min(100, remaining_ms()))
            stage = "cookie export"
            cookies = _cookies(page.context.cookies())
            login_info = completed.get("login_info", {})
            if not isinstance(login_info, dict):
                raise QrLoginError(stage, "invalid completion identity")
            for source, target in (("session", "web_session"), ("secure_session", "web_session_sec")):
                value = login_info.get(source) or completed.get(source)
                if isinstance(value, str) and value:
                    cookies[target] = value
            if not all(cookies.get(key) for key in ("a1", "webId", "web_session")):
                raise QrLoginError(stage, "incomplete authenticated cookies")
            expected_id = login_info.get("user_id") or _user_id(completed) or confirmed_id
            if not isinstance(expected_id, str) or not expected_id or (confirmed_id and expected_id != confirmed_id):
                raise QrLoginError("account verification", "missing or inconsistent confirmed account")
        stage = "account verification"
        timeout = remaining_ms() / 1000
        with XhsClient(cookies, timeout=min(30, timeout), max_retries=1, request_delay=0) as client:
            user = client.get_self_info()
        if not isinstance(user, dict) or user.get("guest") or _user_id(user) != expected_id:
            raise QrLoginError(stage, "session does not match the confirmed account")
        remaining_ms()
        emit("Authenticated session verified.")
        return QrLoginResult(cookies, user)
    except (QrLoginError, BrowserUnavailable):
        raise
    except XhsApiError:
        raise QrLoginError(stage, "API/browser operation failed; inspect verification before retrying") from None
    except Exception:
        raise QrLoginError(stage, "browser/network operation failed") from None
