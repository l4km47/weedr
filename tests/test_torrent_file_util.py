"""Tests for .torrent metainfo parsing."""

import hashlib

import pytest

from torrent_file_util import TorrentFileError, _bencode_encode, parse_torrent_metainfo


def test_parse_torrent_metainfo_v1_info_hash():
    info = {
        b"name": b"hello.txt",
        b"length": 7,
        b"piece length": 256,
        b"pieces": b"\x00" * 20,
    }
    meta = {b"announce": b"http://127.0.0.1:1/a", b"info": info}
    raw = _bencode_encode(meta)
    want = hashlib.sha1(_bencode_encode(info)).hexdigest()
    p = parse_torrent_metainfo(raw)
    assert p["info_hash_hex"] == want
    assert p["display_name"]


def test_parse_torrent_metainfo_rejects_v2_meta_version():
    info = {b"meta version": 2, b"name": b"x", b"piece length": 16384, b"pieces": b"\x00" * 20}
    meta = {b"announce": b"http://127.0.0.1:1/a", b"info": info}
    raw = _bencode_encode(meta)
    with pytest.raises(TorrentFileError, match="v2"):
        parse_torrent_metainfo(raw)


def test_parse_torrent_metainfo_rejects_junk():
    with pytest.raises(TorrentFileError):
        parse_torrent_metainfo(b"not a torrent")
