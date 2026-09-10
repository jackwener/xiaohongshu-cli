from __future__ import annotations

import os

os.environ.setdefault("OUTPUT", "rich")
# Keep the on-disk DM write throttle out of unit tests; the limiter itself is
# exercised in test_limiter.py against a temporary state directory.
os.environ.setdefault("XHS_WRITE_RPM", "0")
