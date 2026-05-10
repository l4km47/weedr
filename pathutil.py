"""Path containment helpers (shared by app and tests)."""

from __future__ import annotations

from pathlib import Path


def safe_under_root(root: Path, candidate: Path) -> Path | None:
    """Return resolved candidate if it lies under root; else None."""
    try:
        resolved = candidate.resolve()
        root_resolved = root.resolve()
        resolved.relative_to(root_resolved)
        return resolved
    except (OSError, ValueError):
        return None
