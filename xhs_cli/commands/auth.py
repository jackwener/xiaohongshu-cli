"""Authentication commands: login, status, logout."""

import click

from ..client import XhsClient
from ..cookies import clear_cookies, get_cookies
from ..formatter import (
    console,
    maybe_print_structured,
    print_success,
    render_user_info,
    success_payload,
)
from ._common import exit_for_error, run_client_action, structured_output_options


def _xhs_user_payload(info: dict) -> dict[str, object]:
    """Normalize Xiaohongshu user info for structured agent output."""
    return {
        "id": info.get("user_id") or info.get("userid") or info.get("red_id") or "",
        "name": info.get("nickname", "Unknown"),
        "username": info.get("red_id", ""),
        "nickname": info.get("nickname", "Unknown"),
        "red_id": info.get("red_id", ""),
        "ip_location": info.get("ip_location", ""),
        "desc": info.get("desc", ""),
    }


@click.command()
@click.option(
    "--cookie-source",
    type=str,
    default=None,
    help="Browser to read cookies from (default: auto-detect all installed browsers)",
)
@structured_output_options
@click.option("--qrcode", "use_qrcode", is_flag=True, default=False,
              help="Login via QR code (scan with Xiaohongshu app)")
@click.pass_context
def login(ctx, cookie_source: str | None, as_json: bool, as_yaml: bool, use_qrcode: bool):
    """Log in by extracting cookies from browser, or via QR code."""

    if use_qrcode:
        # QR code login flow
        try:
            from ..qr_login import qrcode_login

            cookies = qrcode_login()

            # Verify by fetching user info
            with XhsClient(cookies) as client:
                info = client.get_self_info()

            payload = success_payload({"authenticated": True, "user": _xhs_user_payload(info)})
            if not maybe_print_structured(payload, as_json=as_json, as_yaml=as_yaml):
                nickname = info.get("nickname", "Unknown")
                red_id = info.get("red_id", "")
                print_success(f"Logged in as: {nickname} (ID: {red_id})")

        except Exception as exc:
            exit_for_error(exc, as_json=as_json, as_yaml=as_yaml, prefix="QR login failed")
        return

    # Browser cookie extraction (default)
    if cookie_source is None:
        cookie_source = ctx.obj.get("cookie_source", "auto") if ctx.obj else "auto"
    try:
        browser, cookies = get_cookies(cookie_source, force_refresh=True)
        print_success(f"Cookies extracted from {browser}")

        # Verify by fetching user info
        with XhsClient(cookies) as client:
            info = client.get_self_info()

        payload = success_payload({"authenticated": True, "user": _xhs_user_payload(info)})
        if not maybe_print_structured(payload, as_json=as_json, as_yaml=as_yaml):
            nickname = info.get("nickname", "Unknown")
            red_id = info.get("red_id", "")
            print_success(f"Logged in as: {nickname} (ID: {red_id})")

    except Exception as exc:
        exit_for_error(exc, as_json=as_json, as_yaml=as_yaml, prefix="Login verification failed")


@click.command()
@structured_output_options
@click.pass_context
def status(ctx, as_json: bool, as_yaml: bool):
    """Check current login status and user info."""
    try:
        info = run_client_action(ctx, lambda client: client.get_self_info())

        if not maybe_print_structured(
            success_payload({"authenticated": True, "user": _xhs_user_payload(info)}),
            as_json=as_json,
            as_yaml=as_yaml,
        ):
            nickname = info.get("nickname", "Unknown")
            red_id = info.get("red_id", "")
            ip_location = info.get("ip_location", "")
            desc = info.get("desc", "")

            console.print("[bold green]✓ Logged in[/bold green]")
            console.print(f"  昵称: [bold]{nickname}[/bold]")
            if red_id:
                console.print(f"  小红书号: {red_id}")
            if ip_location:
                console.print(f"  IP 属地: {ip_location}")
            if desc:
                console.print(f"  简介: {desc}")

    except Exception as exc:
        exit_for_error(exc, as_json=as_json, as_yaml=as_yaml, prefix="Status check failed")


@click.command()
@structured_output_options
def logout(as_json: bool, as_yaml: bool):
    """Clear saved cookies and log out."""
    clear_cookies()
    payload = success_payload({"logged_out": True})
    if not maybe_print_structured(payload, as_json=as_json, as_yaml=as_yaml):
        print_success("Logged out — cookies cleared")


@click.command()
@structured_output_options
@click.pass_context
def whoami(ctx, as_json: bool, as_yaml: bool):
    """Show detailed profile of current user (level, fans, likes)."""
    try:
        info = run_client_action(ctx, lambda client: client.get_self_info())

        if not maybe_print_structured(
            success_payload({"user": _xhs_user_payload(info)}),
            as_json=as_json,
            as_yaml=as_yaml,
        ):
            render_user_info(info)

    except Exception as exc:
        exit_for_error(exc, as_json=as_json, as_yaml=as_yaml, prefix="Failed to get profile")
