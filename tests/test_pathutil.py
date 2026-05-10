from pathlib import Path

import pytest

from pathutil import safe_under_root


def test_safe_under_root_ok(tmp_path):
    root = tmp_path / "dl"
    root.mkdir()
    sub = root / "a" / "b"
    sub.mkdir(parents=True)
    assert safe_under_root(root, sub) == sub.resolve()


def test_safe_under_root_traversal(tmp_path):
    root = tmp_path / "dl"
    root.mkdir()
    outside = tmp_path / "other"
    outside.mkdir()
    assert safe_under_root(root, outside) is None


def test_safe_under_root_symlink_escape(tmp_path):
    root = tmp_path / "dl"
    root.mkdir()
    outside = tmp_path / "secret"
    outside.mkdir()
    link = root / "evil"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink not supported")
    assert safe_under_root(root, link.resolve()) is None
