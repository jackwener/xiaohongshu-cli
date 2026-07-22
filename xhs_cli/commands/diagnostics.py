"""Privacy-safe environment diagnostics and support bundles."""

from __future__ import annotations

import json
import os
import platform
import stat
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

import click

from .. import __version__
from ..client import XhsClient
from ..constants import CONFIG_DIR_NAME, COOKIE_FILE
from ..cookies import _available_browsers, load_saved_cookies
from ..error_codes import error_code_for_exception
from ..formatter import console, maybe_print_structured, print_success, success_payload
from ..signing import sign_main_api
from ._common import structured_output_options


def _dependency_versions() -> dict[str, str]:
    packages = ("httpx", "click", "browser-cookie3", "xhshow")
    result = {}
    for package in packages:
        try:
            result[package] = version(package)
        except PackageNotFoundError:
            result[package] = "missing"
    return result


def _cookie_check() -> dict[str, Any]:
    path = Path.home() / CONFIG_DIR_NAME / COOKIE_FILE
    result: dict[str, Any] = {"status": "missing", "exists": path.exists()}
    if not path.exists():
        return result

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        mode = stat.S_IMODE(path.stat().st_mode)
        saved_at = payload.get("saved_at") if isinstance(payload, dict) else None
        result.update({
            "status": "ok" if isinstance(payload, dict) and bool(payload.get("a1")) else "invalid",
            "valid_json": isinstance(payload, dict),
            "has_required_cookie": isinstance(payload, dict) and bool(payload.get("a1")),
            "permissions": oct(mode),
            "permissions_restricted": mode & 0o077 == 0,
            "age_days": round((time.time() - float(saved_at)) / 86400, 1) if saved_at else None,
        })
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        result.update({"status": "invalid", "error_type": type(exc).__name__})
    return result


def _signing_check() -> dict[str, Any]:
    try:
        headers = sign_main_api("GET", "/api/sns/web/v2/user/me", {"a1": "0" * 52})
        return {"status": "ok", "headers_generated": all(key in headers for key in ("x-s", "x-t"))}
    except Exception as exc:
        return {"status": "error", "error_type": type(exc).__name__}


def collect_diagnostics(*, check_api: bool = False) -> dict[str, Any]:
    """Collect diagnostics without returning secrets or user profile data."""
    api: dict[str, Any] = {"status": "skipped", "reason": "use --network to check"}
    if check_api:
        cookies = load_saved_cookies()
        if not cookies:
            api = {"status": "skipped", "reason": "no saved credentials"}
        else:
            from ..qr_login import BROWSER_EXPORT_COOKIE_NAMES

            cookies = {
                name: value
                for name, value in cookies.items()
                if name in BROWSER_EXPORT_COOKIE_NAMES and isinstance(value, str)
            }
            try:
                with XhsClient(cookies) as client:
                    client.get_self_info()
                api = {"status": "ok"}
            except Exception as exc:
                api = {
                    "status": "error",
                    "error_code": error_code_for_exception(exc),
                    "error_type": type(exc).__name__,
                }

    try:
        browser_sources = list(_available_browsers())
        browser_check = {"status": "ok", "supported_sources": browser_sources}
    except Exception as exc:
        browser_check = {"status": "error", "error_type": type(exc).__name__}

    return {
        "generated_at": int(time.time()),
        "cli_version": __version__,
        "runtime": {"python": platform.python_version(), "system": platform.system()},
        "dependencies": _dependency_versions(),
        "checks": {
            "cookies": _cookie_check(),
            "signing": _signing_check(),
            "browser_cookie_sources": browser_check,
            "api": api,
        },
        "privacy": {
            "contains_cookie_values": False,
            "contains_tokens": False,
            "contains_user_profile": False,
        },
    }


def _render_report(report: dict[str, Any]) -> None:
    console.print(f"[bold]xiaohongshu-cli {report['cli_version']} diagnostics[/bold]")
    for name, check in report["checks"].items():
        status_value = check["status"]
        marker = "[green]✓[/green]" if status_value == "ok" else "[yellow]•[/yellow]"
        console.print(f"{marker} {name}: {status_value}")


@click.command()
@click.option("--network", is_flag=True, help="Validate the API with saved credentials.")
@structured_output_options
def doctor(network: bool, as_json: bool, as_yaml: bool):
    """Diagnose local auth, signing, browser support, and API compatibility."""
    report = collect_diagnostics(check_api=network)
    if not maybe_print_structured(report, as_json=as_json, as_yaml=as_yaml):
        _render_report(report)


@click.command("support-bundle")
@click.argument("output", type=click.Path(path_type=Path), default=Path("xhs-support-bundle.json"))
@click.option("--network", is_flag=True, help="Validate the API with saved credentials.")
@structured_output_options
def support_bundle(output: Path, network: bool, as_json: bool, as_yaml: bool):
    """Write a redacted diagnostic report for bug reports."""
    report = success_payload(collect_diagnostics(check_api=network))
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(report, file, ensure_ascii=False, indent=2)
        file.write("\n")
    output.chmod(0o600)

    result = {"path": str(output), "redacted": True}
    if not maybe_print_structured(result, as_json=as_json, as_yaml=as_yaml):
        print_success(f"Redacted support bundle written to {output}")
