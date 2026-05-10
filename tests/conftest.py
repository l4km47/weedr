"""Pytest defaults so importing app does not require production secrets."""

from __future__ import annotations

import os

os.environ.setdefault("FLASK_DEBUG", "1")
os.environ.setdefault("DASHBOARD_PASSWORD", "pytest-secret-do-not-use")
