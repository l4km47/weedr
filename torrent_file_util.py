"""Parse .torrent metainfo (bencode) for display name and v1 info-hash."""

from __future__ import annotations

import hashlib
from typing import Any

from werkzeug.utils import secure_filename


class TorrentFileError(ValueError):
    """Invalid or unsupported .torrent metainfo; optional parse_log for UI."""

    def __init__(self, message: str, *, parse_log: list[str] | None = None) -> None:
        super().__init__(message)
        self.parse_log = list(parse_log or [])


def _bencode_decode(data: bytes, i: int = 0) -> tuple[Any, int]:
    if i >= len(data):
        raise TorrentFileError("truncated bencode")
    c = data[i : i + 1]
    if c == b"i":
        j = data.index(b"e", i + 1)
        body = data[i + 1 : j]
        if body.startswith(b"-"):
            n = -int(body[1:])
        else:
            n = int(body or "0")
        return n, j + 1
    if c == b"l":
        out: list[Any] = []
        i += 1
        while data[i : i + 1] != b"e":
            v, i = _bencode_decode(data, i)
            out.append(v)
        return out, i + 1
    if c == b"d":
        out: dict[bytes, Any] = {}
        i += 1
        while data[i : i + 1] != b"e":
            k, i = _bencode_decode(data, i)
            if not isinstance(k, bytes):
                raise TorrentFileError("dict keys must be byte strings")
            v, i = _bencode_decode(data, i)
            out[k] = v
        return out, i + 1
    if c in b"0123456789":
        colon = data.index(b":", i)
        ln = int(data[i:colon])
        start = colon + 1
        end = start + ln
        if end > len(data):
            raise TorrentFileError("truncated string")
        return data[start:end], end
    raise TorrentFileError("invalid bencode")


def _bencode_encode(obj: Any) -> bytes:
    if isinstance(obj, int):
        return b"i" + str(obj).encode("ascii") + b"e"
    if isinstance(obj, bytes):
        return str(len(obj)).encode("ascii") + b":" + obj
    if isinstance(obj, list):
        return b"l" + b"".join(_bencode_encode(x) for x in obj) + b"e"
    if isinstance(obj, dict):
        parts = []
        for k in sorted(obj.keys()):
            if not isinstance(k, bytes):
                raise TorrentFileError("dict keys must be bytes")
            parts.append(_bencode_encode(k))
            parts.append(_bencode_encode(obj[k]))
        return b"d" + b"".join(parts) + b"e"
    raise TorrentFileError(f"unsupported type {type(obj)!r}")


def _torrent_display_name(info: dict[bytes, Any]) -> str:
    name = info.get(b"name")
    if isinstance(name, bytes) and name:
        raw = name.decode("utf-8", "replace").strip()
        if raw:
            return secure_filename(raw.replace("/", "_").replace("\\", "_")) or raw[:120]
    files = info.get(b"files")
    if isinstance(files, list) and files:
        first = files[0]
        if isinstance(first, dict):
            path = first.get(b"path")
            if isinstance(path, list) and path:
                leaf = path[-1]
                if isinstance(leaf, bytes) and leaf:
                    raw = leaf.decode("utf-8", "replace").strip()
                    if raw:
                        return secure_filename(raw) or raw[:120]
    return "torrent"


def _dict_keys_preview(d: dict[bytes, Any], *, limit: int = 12) -> str:
    labels = sorted(k.decode("utf-8", "replace") for k in d if isinstance(k, bytes))
    if len(labels) <= limit:
        return ", ".join(labels) if labels else "(empty)"
    return ", ".join(labels[:limit]) + f", … (+{len(labels) - limit} more)"


def parse_torrent_metainfo(data: bytes) -> dict[str, Any]:
    """
    Decode a .torrent file and return v1 info-hash (40 hex), folder label, and parse_log.
    Supports classic v1 metainfo only (no v2-only torrents).
    """
    log: list[str] = []

    def L(msg: str) -> None:
        log.append(msg)

    def fail(msg: str) -> TorrentFileError:
        return TorrentFileError(msg, parse_log=log)

    n = len(data)
    L(f"Read {n} bytes ({n / 1024.0:.1f} KiB).")
    if n > 64 * 1024 * 1024:
        L("Rejected: exceeds parser safety limit (64 MiB).")
        raise fail("torrent file too large")
    if not data.startswith(b"d"):
        L("First byte is not 'd': not a bencode root dictionary.")
        raise fail("not a torrent (expected bencode dict)")
    L("Decoding root bencode dictionary…")
    try:
        meta, end = _bencode_decode(data, 0)
    except TorrentFileError as e:
        L(f"bencode decode error: {e}")
        raise fail(str(e)) from e
    if end != len(data):
        L(f"Trailing data after metainfo: {len(data) - end} extra bytes (not allowed).")
        raise fail("trailing junk after metainfo")
    if not isinstance(meta, dict):
        L(f"Root value type is {type(meta).__name__}, expected dict.")
        raise fail("root must be a dict")
    L(f"Root dict has {len(meta)} keys: {_dict_keys_preview(meta)}.")
    if b"announce" in meta and isinstance(meta[b"announce"], bytes):
        alen = len(meta[b"announce"])
        L(f"announce: present ({alen} bytes).")
    else:
        L("announce: absent (allowed).")
    info = meta.get(b"info")
    if not isinstance(info, dict):
        L("Missing or invalid 'info' key (must be a dict).")
        raise fail("missing info dict")
    L(f"info dict has {len(info)} keys: {_dict_keys_preview(info)}.")
    if info.get(b"meta version") == 2 or b"piece layers" in info or meta.get(b"piece layers"):
        L("Detected v2 / hybrid markers (meta version, piece layers): not supported here.")
        raise fail("v2-only / hybrid torrent metainfo is not supported; use a magnet link instead")
    if isinstance(info.get(b"files"), list):
        nfiles = len(info[b"files"])
        L(f"Mode: multi-file torrent ({nfiles} file entries in info.files).")
    elif b"length" in info:
        L("Mode: single-file torrent (info.length + info.name).")
    else:
        L("Mode: unclear (no info.files list and no info.length).")
    try:
        info_raw = _bencode_encode(info)
    except TorrentFileError as e:
        L(f"Could not re-encode info dict for SHA1: {e}")
        raise fail(f"cannot encode info: {e}") from e
    L(f"Canonical info dict bencode length: {len(info_raw)} bytes.")
    ih = hashlib.sha1(info_raw).hexdigest()
    L(f"SHA1(info) → info_hash (v1): {ih}")
    label = _torrent_display_name(info)
    L(f"Resolved save label / display name: {label!r}")
    L("Parse finished successfully (v1 metainfo).")
    return {"info_hash_hex": ih, "display_name": label or "torrent", "parse_log": log}
