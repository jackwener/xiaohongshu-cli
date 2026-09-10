"""Tests for the cross-process write throttle (no network)."""

from __future__ import annotations

import json
import time

import pytest

from xhs_cli import limiter
from xhs_cli.exceptions import RateLimitedError


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(limiter, "get_config_dir", lambda: tmp_path)
    monkeypatch.setenv("XHS_WRITE_RPM", "1")
    limiter.reset()
    return tmp_path


class TestWriteBudget:
    def test_first_write_passes_second_is_throttled(self, state_dir):
        limiter.check_write_budget("dm")
        with pytest.raises(RateLimitedError, match="写入限流"):
            limiter.check_write_budget("dm")

    def test_buckets_are_independent(self, state_dir):
        limiter.check_write_budget("dm")
        # A different bucket has its own budget.
        limiter.check_write_budget("other")

    def test_zero_rpm_disables_throttle(self, state_dir, monkeypatch):
        monkeypatch.setenv("XHS_WRITE_RPM", "0")
        for _ in range(5):
            limiter.check_write_budget("dm")

    def test_invalid_rpm_falls_back_to_default(self, state_dir, monkeypatch):
        monkeypatch.setenv("XHS_WRITE_RPM", "not-a-number")
        limiter.check_write_budget("dm")
        with pytest.raises(RateLimitedError):
            limiter.check_write_budget("dm")

    def test_window_expiry_releases_token(self, state_dir, monkeypatch):
        limiter.check_write_budget("dm")
        real_time = time.time
        monkeypatch.setattr(limiter.time, "time", lambda: real_time() + limiter.WINDOW_SECONDS + 1)
        limiter.check_write_budget("dm")

    def test_state_file_is_valid_json(self, state_dir):
        limiter.check_write_budget("dm")
        payload = json.loads((state_dir / limiter.STATE_FILE).read_text())
        assert payload["dm"]

    def test_reset_clears_bucket(self, state_dir):
        limiter.check_write_budget("dm")
        limiter.reset("dm")
        limiter.check_write_budget("dm")
