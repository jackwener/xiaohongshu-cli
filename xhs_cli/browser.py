"""One browser boundary: Python CloakBrowser with visible, humanized Playwright control."""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

from .exceptions import XhsApiError

if TYPE_CHECKING:
    from playwright.sync_api import Page


class BrowserUnavailable(XhsApiError):
    """The optional CloakBrowser dependency or its configured runtime is unavailable."""


def _startup_diagnostic(exc: Exception) -> str:
    """Classify an actual SDK failure without echoing commands, keys or raw logs."""
    kind = type(exc).__name__
    details = str(exc)
    prefix = "CloakBrowser could not start: "
    if kind == "CloakBrowserLicenseError":
        return prefix + "the SDK rejected license validation; run cloakbrowser login."
    if isinstance(exc, TimeoutError) or kind == "TimeoutError":
        return prefix + "the SDK browser launch timed out."
    if any(marker in details for marker in ("Missing X server", "cannot open display", "Could not open display")):
        return prefix + "Chromium reported that it could not connect to the graphical display."
    if any(
        marker in details for marker in ("Authorization required", "No protocol specified", "Invalid MIT-MAGIC-COOKIE")
    ):
        return prefix + "Chromium reported a graphical-session authorization failure."
    if kind == "TargetClosedError" or "Target page, context or browser has been closed" in details:
        suffix = ""
        code = re.search(r"exitCode=(-?\d{1,3})(?:,|\s|$)", details)
        signal = re.search(r"signal=(SIG[A-Z0-9]{1,12})(?:,|\s|$)", details)
        if code:
            suffix += f" exitCode={code[1]}."
        if signal:
            suffix += f" signal={signal[1]}."
        return prefix + "the browser exited before Playwright connected." + suffix
    known = {"RuntimeError", "Error", "OSError", "FileNotFoundError", "PermissionError"}
    reason = f"the SDK raised {kind}" if kind in known else "an unexpected SDK error occurred"
    return prefix + reason + "; no raw launch command or credentials were printed."


@contextmanager
def browser_page() -> Iterator[Page]:
    """Own one temporary browser/context/page, without borrowing a personal profile."""
    try:
        from cloakbrowser import launch
    except ImportError:
        raise BrowserUnavailable(
            "Browser login requires the optional dependency: install xiaohongshu-cli[browser]."
        ) from None
    try:
        browser = launch(headless=False, humanize=True)
    except Exception as exc:
        raise BrowserUnavailable(_startup_diagnostic(exc)) from None
    try:
        context = browser.new_context()
        try:
            yield context.new_page()
        finally:
            context.close()
    finally:
        browser.close()
