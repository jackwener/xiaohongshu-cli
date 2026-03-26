"""Authentication commands: login, status, logout."""

import time

import click

from ..client import XhsClient
from ..command_normalizers import normalize_xhs_user_payload
from ..cookies import clear_cookies, get_cookies
from ..exceptions import XhsApiError
from ..formatter import (
    console,
    maybe_print_structured,
    print_success,
    render_user_info,
    success_payload,
)
from ._common import handle_errors, run_client_action, structured_output_options


def _emit_payload(data: dict[str, object], *, as_json: bool, as_yaml: bool) -> bool:
    """Emit a structured success payload when requested."""
    return maybe_print_structured(success_payload(data), as_json=as_json, as_yaml=as_yaml)


def _is_valid_login(user: dict[str, object]) -> bool:
    """Check whether the normalized user payload represents a real logged-in session."""
    if user.get("guest"):
        return False
    nickname = user.get("nickname", "")
    return bool(nickname and nickname != "Unknown")


def _print_login_success(user: dict[str, object]) -> None:
    """Print a concise login success message."""
    print_success(f"Logged in as: {user['nickname']} (ID: {user['red_id']})")


def _print_status_summary(user: dict[str, object]) -> None:
    """Render a short authenticated-user summary."""
    console.print("[bold green]✓ Logged in[/bold green]")
    console.print(f"  昵称: [bold]{user['nickname']}[/bold]")
    if user["red_id"]:
        console.print(f"  小红书号: {user['red_id']}")
    if user["ip_location"]:
        console.print(f"  IP 属地: {user['ip_location']}")
    if user["desc"]:
        console.print(f"  简介: {user['desc']}")

@click.command()
@click.option(
    "--cookie-source",
    type=str,
    default=None,
    help=(
        "Cookie provider/source to read cookies from "
        "(default: auto-detect installed browsers; use 'cookiecloud' explicitly)"
    ),
)
@structured_output_options
@click.option("--qrcode", "use_qrcode", is_flag=True, default=False,
              help="Login via QR code (scan with Xiaohongshu app)")
@click.pass_context
def login(ctx, cookie_source: str | None, as_json: bool, as_yaml: bool, use_qrcode: bool):
    """Log in by extracting cookies from browser, or via QR code."""

    if use_qrcode:
        def _login_with_qrcode() -> None:
            from ..qr_login import qrcode_login

            cookies = qrcode_login(prefer_browser_assisted=True)

            # Verify by fetching user info (may return guest=true briefly)
            import time
            time.sleep(1)  # brief delay for session propagation
            with XhsClient(cookies) as client:
                info = client.get_self_info()
            user = normalize_xhs_user_payload(info)

            if user["guest"]:
                # Session not yet propagated; still valid
                if not _emit_payload(
                    {"authenticated": True, "user": {"id": user["id"]}},
                    as_json=as_json,
                    as_yaml=as_yaml,
                ):
                    print_success("Logged in (session saved)")
            else:
                if not _emit_payload({"authenticated": True, "user": user}, as_json=as_json, as_yaml=as_yaml):
                    _print_login_success(user)

        handle_errors(
            _login_with_qrcode,
            as_json=as_json,
            as_yaml=as_yaml,
            prefix="QR login failed",
        )
        return

    # Cookie provider/source extraction (default)
    if cookie_source is None:
        cookie_source = ctx.obj.get("cookie_source", "auto") if ctx.obj else "auto"

    def _login_with_cookie_source() -> None:
        source_name, cookies = get_cookies(cookie_source, force_refresh=True)
        if not (as_json or as_yaml):
            print_success(f"Cookies extracted from {source_name}")

        # Verify by fetching user info, retry once if session not yet propagated
        with XhsClient(cookies) as client:
            info = client.get_self_info()
        user = normalize_xhs_user_payload(info)

        if not _is_valid_login(user):
            time.sleep(2.5)
            with XhsClient(cookies) as client:
                info = client.get_self_info()
            user = normalize_xhs_user_payload(info)

        if not _is_valid_login(user):
            raise XhsApiError(
                f"Cookies were extracted from {source_name}, but the session appears invalid "
                "(guest or incomplete profile). Try: xhs login --qrcode"
            )

        if not _emit_payload({"authenticated": True, "user": user}, as_json=as_json, as_yaml=as_yaml):
            _print_login_success(user)

    handle_errors(
        _login_with_cookie_source,
        as_json=as_json,
        as_yaml=as_yaml,
        prefix="Login verification failed",
    )


@click.command()
@structured_output_options
@click.pass_context
def status(ctx, as_json: bool, as_yaml: bool):
    """Check current login status and user info."""
    def _show_status() -> None:
        info = run_client_action(ctx, lambda client: client.get_self_info())
        user = normalize_xhs_user_payload(info)

        if not _emit_payload({"authenticated": True, "user": user}, as_json=as_json, as_yaml=as_yaml):
            _print_status_summary(user)

    handle_errors(_show_status, as_json=as_json, as_yaml=as_yaml, prefix="Status check failed")


@click.command()
@structured_output_options
@click.pass_context
def logout(ctx, as_json: bool, as_yaml: bool):
    """Clear saved cookies and log out."""
    clear_cookies()
    if not _emit_payload({"logged_out": True}, as_json=as_json, as_yaml=as_yaml):
        print_success("Logged out — cookies cleared")


@click.command()
@structured_output_options
@click.pass_context
def whoami(ctx, as_json: bool, as_yaml: bool):
    """Show detailed profile of current user (level, fans, likes)."""
    def _show_profile() -> None:
        info = run_client_action(ctx, lambda client: client.get_self_info())
        user = normalize_xhs_user_payload(info)

        if not _emit_payload({"user": user}, as_json=as_json, as_yaml=as_yaml):
            render_user_info(info)

    handle_errors(_show_profile, as_json=as_json, as_yaml=as_yaml, prefix="Failed to get profile")
