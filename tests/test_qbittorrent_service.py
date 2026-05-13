"""Unit tests for qBittorrent client helpers (no live daemon)."""

from qbittorrent_service import (
    enrich_global_stat,
    normalize_qbt_torrent,
    parse_rate_to_bytes_per_sec,
)


def test_parse_rate_to_bytes_per_sec():
    assert parse_rate_to_bytes_per_sec("0") == 0
    assert parse_rate_to_bytes_per_sec("4M") == 4 * 1024 * 1024
    assert parse_rate_to_bytes_per_sec("1G") == 1024**3


def test_normalize_qbt_torrent_shape():
    raw = {
        "hash": "A" * 40,
        "name": "Test",
        "state": "downloading",
        "progress": 0.5,
        "size": 1000,
        "total_size": 1000,
        "downloaded": 500,
        "dlspeed": 100,
        "upspeed": 0,
        "num_seeds": 10,
        "num_leechs": 3,
        "save_path": "/tmp/dl",
    }
    n = normalize_qbt_torrent(raw)
    assert n["gid"] == ("a" * 40)
    assert n["status"] == "active"
    assert n["total_length"] == 1000
    assert n["download_speed"] == 100
    assert n["dir"] == "/tmp/dl"


def test_enrich_global_stat():
    s = enrich_global_stat({"downloadSpeed": "1024", "uploadSpeed": "0"})
    assert s["downloadSpeed_bps"] == 1024
    assert "download_speed_human" in s
