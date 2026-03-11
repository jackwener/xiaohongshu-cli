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


def _basic_user_info(info: dict) -> dict[str, object]:
    """Return the basic user profile block regardless of response shape."""
    basic = info.get("basic_info", info)
    return basic if isinstance(basic, dict) else info


def _xhs_user_payload(info: dict) -> dict[str, object]:
    """Normalize Xiaohongshu user info for structured agent output."""
    basic = _basic_user_info(info)
    return {
        "id": (
            basic.get("user_id")
            or info.get("user_id")
            or info.get("userid")
            or basic.get("red_id")
            or info.get("red_id")
            or ""
        ),
        "name": basic.get("nickname", basic.get("nick_name", "Unknown")),
        "username": basic.get("red_id", info.get("red_id", "")),
        "nickname": basic.get("nickname", basic.get("nick_name", "Unknown")),
        "red_id": basic.get("red_id", info.get("red_id", "")),
        "ip_location": basic.get("ip_location", info.get("ip_location", "")),
        "desc": basic.get("desc", info.get("desc", "")),
    }


def _has_resolved_profile(info: dict) -> bool:
    """Check whether the response already contains usable profile fields."""
    basic = _basic_user_info(info)
    return bool(
        basic.get("nickname")
        or basic.get("nick_name")
        or basic.get("red_id")
        or basic.get("desc")
        or basic.get("ip_location")
    )


def _fetch_current_user_profile(client: XhsClient) -> dict:
    """Fetch current user identity, then enrich it with the profile endpoint."""
    info = client.get_self_info()
    if not isinstance(info, dict):
        return info

    if _has_resolved_profile(info):
        return info

    user_id = info.get("user_id", "")
    if not user_id:
        return info

    try:
        detailed = client.get_user_info(user_id)
    except Exception:
        return info

    if not isinstance(detailed, dict):
        return info

    merged = dict(detailed)
    for key, value in info.items():
        merged.setdefault(key, value)

    basic = merged.get("basic_info")
    if isinstance(basic, dict):
        normalized_basic = dict(basic)
        normalized_basic.setdefault("user_id", user_id)
        merged["basic_info"] = normalized_basic

    merged.setdefault("user_id", user_id)
    return merged


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

            # Verify by fetching user info (may return guest=true briefly)
            import time
            time.sleep(1)  # brief delay for session propagation
            with XhsClient(cookies) as client:
                info = _fetch_current_user_profile(client)

            if info.get("guest") and not _has_resolved_profile(info):
                # Session not yet propagated; still valid
                payload = success_payload({"authenticated": True, "user": {"id": info.get("user_id", "")}})
                if not maybe_print_structured(payload, as_json=as_json, as_yaml=as_yaml):
                    print_success("Logged in (session saved)")
            else:
                user = _xhs_user_payload(info)
                payload = success_payload({"authenticated": True, "user": user})
                if not maybe_print_structured(payload, as_json=as_json, as_yaml=as_yaml):
                    nickname = user["nickname"]
                    red_id = user["red_id"]
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
            info = _fetch_current_user_profile(client)

        user = _xhs_user_payload(info)
        payload = success_payload({"authenticated": True, "user": user})
        if not maybe_print_structured(payload, as_json=as_json, as_yaml=as_yaml):
            nickname = user["nickname"]
            red_id = user["red_id"]
            print_success(f"Logged in as: {nickname} (ID: {red_id})")

    except Exception as exc:
        exit_for_error(exc, as_json=as_json, as_yaml=as_yaml, prefix="Login verification failed")


@click.command()
@structured_output_options
@click.pass_context
def status(ctx, as_json: bool, as_yaml: bool):
    """Check current login status and user info."""
    try:
        info = run_client_action(ctx, _fetch_current_user_profile)
        user = _xhs_user_payload(info)

        if not maybe_print_structured(
            success_payload({"authenticated": True, "user": user}),
            as_json=as_json,
            as_yaml=as_yaml,
        ):
            nickname = user["nickname"]
            red_id = user["red_id"]
            ip_location = user["ip_location"]
            desc = user["desc"]

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
        info = run_client_action(ctx, _fetch_current_user_profile)

        if not maybe_print_structured(
            success_payload({"user": _xhs_user_payload(info)}),
            as_json=as_json,
            as_yaml=as_yaml,
        ):
            render_user_info(info)

    except Exception as exc:
        exit_for_error(exc, as_json=as_json, as_yaml=as_yaml, prefix="Failed to get profile")
