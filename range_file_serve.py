"""
HTTP Range downloads compatible with download managers (IDM/FDM).

Behaviour is aligned with danvk/RangeHTTPServer (Range + Content-Length + end
headers) — see https://github.com/danvk/RangeHTTPServer — plus Werkzeug parsing
for suffix / open-ended ranges. Flask/Werkzeug send_file alone is often flaky
for segmented tools behind proxies.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Literal

from flask import Response, stream_with_context
from werkzeug.http import http_date, parse_if_range_header, parse_range_header, quote_etag

_CHUNK = 256 * 1024

# Strict single-range form many download managers send first (danvk-style).
_DANVK_BYTES_RANGE = re.compile(r"^bytes\s*=\s*(\d+)\s*-\s*(\d*)\s*$", re.IGNORECASE)


def _danvk_single_range(
    range_hdr: str,
    size: int,
) -> tuple[int, int] | Literal["416"] | None:
    """
    Parse first `bytes=start-end` line like RangeHTTPServer.

    Returns inclusive (start, end), None to fall back to Werkzeug, or "416".
    """
    if not range_hdr or size <= 0:
        return None
    val = range_hdr.strip()
    if val.lower().startswith("bytes="):
        spec = val[6:].strip()
        if "," in spec:
            return None
    first_line = val.split(",")[0].strip()
    if first_line.lower().startswith("bytes=-"):
        return None
    m = _DANVK_BYTES_RANGE.match(first_line)
    if not m:
        return None
    first = int(m.group(1))
    last_s = (m.group(2) or "").strip()
    if first >= size:
        return "416"
    if last_s == "":
        last = size - 1
    else:
        last = int(last_s)
    last = min(last, size - 1)
    if first > last:
        return "416"
    return (first, last)


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


def _finalize_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Accept-Ranges last (same idea as RangeHTTPServer.end_headers)."""
    out = [(k, v) for k, v in headers if k.lower() != "accept-ranges"]
    out.append(("Accept-Ranges", "bytes"))
    return out


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
    GET/HEAD with optional single-range 206 (RFC 7233).

    Multipart byte ranges get a full 200 body so clients can retry one range.
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

    core_headers = [
        ("Cache-Control", "private"),
        ("ETag", etag_q),
        ("Last-Modified", lm_hdr),
        ("Content-Disposition", _content_disposition_attachment(download_name)),
        ("X-Accel-Buffering", "no"),
    ]

    range_hdr = (range_header or "").strip()
    use_partial = False
    start = 0
    end_inclusive = max(0, size - 1)

    if method_u in ("GET", "HEAD") and range_hdr and size > 0:
        if _if_range_allows_partial(if_range_header, etag=etag, last_modified=last_modified):
            dan = _danvk_single_range(range_hdr, size)
            if dan == "416":
                h = _finalize_headers(
                    core_headers + [("Content-Range", f"bytes */{size}"), ("Content-Type", mimetype)]
                )
                r = Response(status=416)
                for k, v in h:
                    r.headers[k] = v
                return r
            if isinstance(dan, tuple):
                start, end_inclusive = dan
                use_partial = True
            else:
                parsed = parse_range_header(range_hdr)
                if (
                    parsed
                    and parsed.units == "bytes"
                    and len(parsed.ranges) == 1
                ):
                    span = parsed.range_for_length(size)
                    if span is None:
                        h = _finalize_headers(
                            core_headers
                            + [("Content-Range", f"bytes */{size}"), ("Content-Type", mimetype)]
                        )
                        r = Response(status=416)
                        for k, v in h:
                            r.headers[k] = v
                        return r
                    start_excl, end_excl = span
                    start = start_excl
                    end_inclusive = end_excl - 1
                    use_partial = True

    if use_partial and end_inclusive >= start >= 0:
        clen = end_inclusive - start + 1
        status = 206
        cr = f"bytes {start}-{end_inclusive}/{size}"
        headers = _finalize_headers(
            core_headers
            + [
                ("Content-Type", mimetype),
                ("Content-Range", cr),
                ("Content-Length", str(clen)),
            ]
        )
        if method_u == "HEAD":
            r = Response(status=status)
            for k, v in headers:
                r.headers[k] = v
            return r

        @stream_with_context
        def gen() -> Iterator[bytes]:
            yield from _file_body_iterator(path, start, end_inclusive)

        return Response(gen(), status=status, headers=headers)

    status = 200
    headers = _finalize_headers(
        core_headers + [("Content-Type", mimetype), ("Content-Length", str(size))]
    )
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
