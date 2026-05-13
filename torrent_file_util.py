"""Parse .torrent metainfo (bencode) for display name and v1 info-hash."""

from __future__ import annotations

import hashlib
from typing import Any

from werkzeug.utils import secure_filename


class TorrentFileError(ValueError):
    pass


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


def parse_torrent_metainfo(data: bytes) -> dict[str, str]:
    """
    Decode a .torrent file and return v1 info-hash (40 hex) and a folder label.
    Supports classic v1 metainfo only (no v2-only torrents).
    """
    if len(data) > 64 * 1024 * 1024:
        raise TorrentFileError("torrent file too large")
    if not data.startswith(b"d"):
        raise TorrentFileError("not a torrent (expected bencode dict)")
    meta, end = _bencode_decode(data, 0)
    if end != len(data):
        raise TorrentFileError("trailing junk after metainfo")
    if not isinstance(meta, dict):
        raise TorrentFileError("root must be a dict")
    info = meta.get(b"info")
    if not isinstance(info, dict):
        raise TorrentFileError("missing info dict")
    if info.get(b"meta version") == 2 or b"piece layers" in info or meta.get(b"piece layers"):
        raise TorrentFileError("v2-only / hybrid torrent metainfo is not supported; use a magnet link instead")
    try:
        info_raw = _bencode_encode(info)
    except TorrentFileError as e:
        raise TorrentFileError(f"cannot encode info: {e}") from e
    ih = hashlib.sha1(info_raw).hexdigest()
    label = _torrent_display_name(info)
    return {"info_hash_hex": ih, "display_name": label or "torrent"}
