"""Integration smoke tests for xiaohongshu-cli.

These tests invoke the real CLI commands with ``--yaml`` against the live
Xiaohongshu API using your local browser cookies.  They are **skipped by
default** and only run when explicitly requested::

    uv run pytest -m smoke -v

Only read-only operations are tested — no writes.
"""

from __future__ import annotations

import pytest
import yaml
from click.testing import CliRunner

from xhs_cli.cli import cli

smoke = pytest.mark.smoke

runner = CliRunner()


def _invoke(*args: str):
    """Run a CLI command with --yaml and return parsed payload."""
    result = runner.invoke(cli, [*args, "--yaml"])
    if result.output:
        payload = yaml.safe_load(result.output)
    else:
        payload = None
    return result, payload


# ── Auth ────────────────────────────────────────────────────────────────


@smoke
class TestAuth:
    """Verify authentication is working end-to-end."""

    def test_status(self):
        result, payload = _invoke("status")
        assert result.exit_code == 0, f"status failed: {result.output}"
        assert payload["ok"] is True
        assert payload["data"]["authenticated"] is True
        assert payload["data"]["user"]["nickname"] != "Unknown"

    def test_whoami(self):
        result, payload = _invoke("whoami")
        assert result.exit_code == 0, f"whoami failed: {result.output}"
        assert payload["ok"] is True
        assert payload["data"]["user"]["nickname"] != "Unknown"


# ── Read-only queries ───────────────────────────────────────────────────


@smoke
class TestReadOnly:
    """Read-only CLI smoke tests."""

    def test_search(self):
        result, payload = _invoke("search", "美食")
        assert result.exit_code == 0, f"search failed: {result.output}"
        assert payload["ok"] is True

    def test_feed(self):
        result, payload = _invoke("feed")
        assert result.exit_code == 0, f"feed failed: {result.output}"
        assert payload["ok"] is True

    def test_hot(self):
        result, payload = _invoke("hot", "-c", "food")
        assert result.exit_code == 0, f"hot failed: {result.output}"
        assert payload["ok"] is True

    def test_topics(self):
        result, payload = _invoke("topics", "旅行")
        assert result.exit_code == 0, f"topics failed: {result.output}"
        assert payload["ok"] is True
