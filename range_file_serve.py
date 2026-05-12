"""
Explicit HTTP byte-range responses (RFC 7233-style) for file downloads.

Used for /files/… and zip downloads so external download managers get stable
206 + Content-Range + Accept-Ranges behavior without relying only on send_file.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from flask import Response, stream_with_context
from werkzeug.http import http_date, parse_if_range_header, parse_range_header, quote_etag

_CHUNK = 256 * 1024


def _if_range_allows_partial(
    if_range_hdr: str | None,
    *,
    etag: str,
    last_modified: datetime,
) -> bool:
    if not if_range_hdr or not if_range_hdr.strip():
        return True
    ir = parse_if_range_header(if_range_hdr.strip())
    if ir is None:
        return True
    if ir.etag is not None:
        return ir.etag == etag
    if ir.date is not None:
        lm = last_modified
        if lm.tzinfo is None:
            lm = lm.replace(tzinfo=timezone.utc)
        lm = lm.replace(microsecond=0)
        d = ir.date
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        d = d.replace(microsecond=0)
        return lm <= d
    return True


def _content_disposition_attachment(filename: str) -> str:
    safe = "".join(c if 32 <= ord(c) < 127 and c not in '\\"' else "_" for c in filename) or "download"
    return f'attachment; filename="{safe}"'


def _file_body_iterator(path: Path, start: int, end_inclusive: int) -> Iterator[bytes]:
    length = end_inclusive - start + 1
    try:
        with path.open("rb") as f:
            f.seek(start)
            remaining = length
            while remaining > 0:
                chunk = f.read(min(_CHUNK, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk
    except OSError:
        return


def range_file_download_response(
    path: Path,
    *,
    download_name: str,
    mimetype: str,
    etag: str,
    last_modified: datetime,
    method: str,
    range_header: str | None,
    if_range_header: str | None,
) -> Response:
    """
    Build a Flask Response for GET/HEAD download with optional single-range 206.

    Multipart byte ranges (multiple ranges in one header) are answered with a
    full 200 body (client may retry with single ranges).
    """
    method_u = (method or "GET").upper()
    if method_u not in ("GET", "HEAD"):
        return Response("Method Not Allowed", status=405)

    try:
        st = path.stat()
    except OSError:
        return Response("Not Found", status=404)

    size = int(st.st_size)
    etag_q = quote_etag(etag)
    lm_hdr = http_date(last_modified)

    # Avoid no-store: some download managers (IDM/FDM) treat it as non-resumable
    # and refuse multi-connection Range downloads.
    base_headers = [
        ("Accept-Ranges", "bytes"),
        ("Cache-Control", "private, max-age=0, must-revalidate"),
        ("ETag", etag_q),
        ("Last-Modified", lm_hdr),
        ("Content-Disposition", _content_disposition_attachment(download_name)),
        ("X-Accel-Buffering", "no"),
    ]

    range_hdr = (range_header or "").strip()
    parsed = parse_range_header(range_hdr) if range_hdr else None

    use_partial = False
    start = 0
    end_excl = size

    if (
        method_u in ("GET", "HEAD")
        and parsed
        and parsed.units == "bytes"
        and len(parsed.ranges) == 1
        and size > 0
        and _if_range_allows_partial(if_range_header, etag=etag, last_modified=last_modified)
    ):
        span = parsed.range_for_length(size)
        if span is None:
            r = Response(status=416)
            r.headers["Content-Range"] = f"bytes */{size}"
            for k, v in base_headers:
                r.headers[k] = v
            return r
        start, end_excl = span
        use_partial = True

    if use_partial and end_excl > start:
        clen = end_excl - start
        status = 206
        cr = f"bytes {start}-{end_excl - 1}/{size}"
        headers = list(base_headers) + [
            ("Content-Length", str(clen)),
            ("Content-Range", cr),
            ("Content-Type", mimetype),
        ]
        if method_u == "HEAD":
            r = Response(status=status)
            for k, v in headers:
                r.headers[k] = v
            return r

        @stream_with_context
        def gen() -> Iterator[bytes]:
            yield from _file_body_iterator(path, start, end_excl - 1)

        return Response(gen(), status=status, headers=headers)

    status = 200
    headers = list(base_headers) + [
        ("Content-Length", str(size)),
        ("Content-Type", mimetype),
    ]
    if method_u == "HEAD":
        r = Response(status=status)
        for k, v in headers:
            r.headers[k] = v
        return r

    if size == 0:
        return Response(b"", status=status, headers=headers)

    @stream_with_context
    def gen_full() -> Iterator[bytes]:
        yield from _file_body_iterator(path, 0, size - 1)

    return Response(gen_full(), status=status, headers=headers)
