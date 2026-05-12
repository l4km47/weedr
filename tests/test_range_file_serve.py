"""Tests for explicit Range file responses."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from flask import Flask

from range_file_serve import range_file_download_response


@pytest.fixture()
def app_ctx():
    app = Flask(__name__)
    with app.app_context():
        with app.test_request_context():
            yield app


def test_full_get(app_ctx, tmp_path: Path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"abcdef")
    etag, lm = "1-2", datetime(1994, 11, 6, tzinfo=timezone.utc)
    r = range_file_download_response(
        p,
        download_name="a.bin",
        mimetype="application/octet-stream",
        etag=etag,
        last_modified=lm,
        method="GET",
        range_header=None,
        if_range_header=None,
    )
    assert r.status_code == 200
    assert r.get_data() == b"abcdef"
    assert r.headers.get("Accept-Ranges") == "bytes"


def test_partial_206(app_ctx, tmp_path: Path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"0123456789")
    etag, lm = "1-2", datetime(1994, 11, 6, tzinfo=timezone.utc)
    r = range_file_download_response(
        p,
        download_name="a.bin",
        mimetype="application/octet-stream",
        etag=etag,
        last_modified=lm,
        method="GET",
        range_header="bytes=2-5",
        if_range_header=None,
    )
    assert r.status_code == 206
    assert r.get_data() == b"2345"
    assert r.headers.get("Content-Range") == "bytes 2-5/10"


def test_head_no_body(app_ctx, tmp_path: Path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"xyz")
    etag, lm = "1-2", datetime(1994, 11, 6, tzinfo=timezone.utc)
    r = range_file_download_response(
        p,
        download_name="a.bin",
        mimetype="application/octet-stream",
        etag=etag,
        last_modified=lm,
        method="HEAD",
        range_header="bytes=0-1",
        if_range_header=None,
    )
    assert r.status_code == 206
    assert r.get_data() == b""
    assert r.headers.get("Content-Length") == "2"


def test_empty_file_200(app_ctx, tmp_path: Path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    etag, lm = "1-2", datetime(1994, 11, 6, tzinfo=timezone.utc)
    r = range_file_download_response(
        p,
        download_name="empty.bin",
        mimetype="application/octet-stream",
        etag=etag,
        last_modified=lm,
        method="GET",
        range_header=None,
        if_range_header=None,
    )
    assert r.status_code == 200
    assert r.get_data() == b""
