"""QR code login for Xiaohongshu.

Generates a QR code in the terminal using half-block Unicode characters,
polls for scan completion, and extracts cookies via the login/activate API.

Flow discovered through reverse engineering:
1. Generate temporary a1 / webId cookies.
2. Call ``/api/sns/web/v1/login/activate`` to obtain a *guest* session.
3. Call ``/api/sns/web/v1/login/qrcode/create`` to create a QR code.
4. Render the QR URL in the terminal.
5. Poll ``/api/qrcode/userinfo`` until ``codeStatus == 2``.
6. After confirmation, call ``activate`` **again** to get the real session.
7. Save the final ``web_session`` cookie.
"""

from __future__ import annotations

import logging
import random
import time

from .client import XhsClient
from .cookies import save_cookies

logger = logging.getLogger(__name__)

# QR code status values
QR_WAITING = 0      # Waiting for scan
QR_SCANNED = 1      # Scanned, awaiting confirmation
QR_CONFIRMED = 2    # Login confirmed

# Poll config
POLL_INTERVAL_S = 2.0
POLL_TIMEOUT_S = 240  # 4 minutes


# ── Helpers ────────────────────────────────────────────────────────────────

def _generate_a1() -> str:
    """Generate a fresh a1 cookie value (52 hex chars with embedded timestamp)."""
    prefix = "".join(random.choices("0123456789abcdef", k=24))
    ts = str(int(time.time() * 1000))
    suffix = "".join(random.choices("0123456789abcdef", k=15))
    return prefix + ts + suffix


def _generate_webid() -> str:
    """Generate a webId cookie value (32 hex chars)."""
    return "".join(random.choices("0123456789abcdef", k=32))


def _render_qr_half_blocks(matrix: list[list[bool]]) -> str:
    """Render QR matrix using half-block characters (▀▄█ and space).

    Two rows of the QR matrix merge into one terminal line, halving
    the vertical footprint while keeping cells square.
    """
    if not matrix:
        return ""

    size = len(matrix)
    lines: list[str] = []

    for row_idx in range(0, size, 2):
        line = ""
        for col_idx in range(size):
            top = matrix[row_idx][col_idx]
            bot = matrix[row_idx + 1][col_idx] if row_idx + 1 < size else False

            if top and bot:
                line += "█"
            elif top and not bot:
                line += "▀"
            elif not top and bot:
                line += "▄"
            else:
                line += " "

        lines.append(line)

    return "\n".join(lines)


def _display_qr_in_terminal(data: str) -> bool:
    """Display *data* as a QR code in the terminal.  Returns True on success."""
    try:
        import qrcode  # type: ignore[import-untyped]
    except ImportError:
        return False

    qr = qrcode.QRCode(border=4)
    qr.add_data(data)
    qr.make(fit=True)

    modules = qr.get_matrix()
    print(_render_qr_half_blocks(modules))
    return True


# ── Main flow ──────────────────────────────────────────────────────────────

def qrcode_login(
    *,
    on_status: "callable[[str], None] | None" = None,
    timeout_s: int = POLL_TIMEOUT_S,
) -> dict[str, str]:
    """Run the QR code login flow.

    Returns:
        Cookie dict with ``a1``, ``webId``, ``web_session``.

    Raises:
        XhsApiError on timeout or failure.
    """
    from .exceptions import XhsApiError

    def _print(msg: str) -> None:
        if on_status:
            on_status(msg)
        else:
            print(msg)

    # 1. Generate temporary cookies
    a1 = _generate_a1()
    webid = _generate_webid()
    tmp_cookies = {"a1": a1, "webId": webid}

    _print("🔑 Starting QR code login...")

    with XhsClient(tmp_cookies, request_delay=0) as client:

        # 2. Activate guest session (this gives us an initial web_session)
        try:
            activate_data = client.login_activate()
            guest_session = activate_data.get("session", "")
            logger.debug(
                "Initial activate: session=%s user_id=%s",
                guest_session, activate_data.get("user_id"),
            )
        except Exception as exc:
            logger.debug("Initial activate failed (non-fatal): %s", exc)
            guest_session = ""

        # 3. Create QR code
        qr_data = client.create_qr_login()

        qr_id = qr_data["qr_id"]
        code = qr_data["code"]
        qr_url = qr_data["url"]

        logger.debug("QR created: qr_id=%s, code=%s", qr_id, code)

        # 4. Display QR in terminal
        _print("\n📱 Scan the QR code below with the Xiaohongshu app:\n")
        if not _display_qr_in_terminal(qr_url):
            _print(f"⚠️  Install 'qrcode' for terminal rendering: pip install qrcode")
            _print(f"QR URL: {qr_url}")
        _print("\n⏳ Waiting for QR code scan...")

        # 5. Poll for confirmation
        start = time.time()
        last_status = -1

        while (time.time() - start) < timeout_s:
            time.sleep(POLL_INTERVAL_S)

            try:
                status_data = client.check_qr_status(qr_id, code)
            except Exception as exc:
                logger.debug("QR status check error: %s", exc)
                continue

            code_status = status_data.get("codeStatus", -1)
            logger.debug("QR poll: codeStatus=%s data=%s", code_status, status_data)

            if code_status != last_status:
                last_status = code_status
                if code_status == QR_SCANNED:
                    _print("📲 Scanned! Waiting for confirmation...")
                elif code_status == QR_CONFIRMED:
                    _print("✅ Login confirmed!")

            if code_status == QR_CONFIRMED:
                # 6. Activate again — now we get the REAL session
                try:
                    activate_data = client.login_activate()
                    session = activate_data.get("session", "")
                    user_id = activate_data.get("user_id", "")
                    logger.debug(
                        "Post-confirm activate: session=%s user_id=%s",
                        session, user_id,
                    )
                except Exception as exc:
                    logger.debug("Post-confirm activate failed: %s", exc)
                    session = ""

                if not session:
                    raise XhsApiError(
                        "QR login confirmed but activate returned no session. "
                        "Please try: xhs login (browser cookie extraction)"
                    )

                # 7. Save cookies
                cookies = {
                    "a1": a1,
                    "webId": webid,
                    "web_session": session,
                }
                save_cookies(cookies)

                # Verify it works
                try:
                    with XhsClient(cookies, request_delay=0) as verify:
                        info = verify.get_self_info()
                    nickname = info.get("nickname", "")
                    if nickname:
                        _print(f"👤 Logged in as: {nickname}")
                except Exception as exc:
                    logger.debug("Post-login verify failed (non-fatal): %s", exc)

                return cookies

            elapsed = time.time() - start
            if int(elapsed) % 30 == 0 and int(elapsed) > 0:
                _print("  Still waiting...")

    raise XhsApiError("QR code login timed out after 4 minutes")
