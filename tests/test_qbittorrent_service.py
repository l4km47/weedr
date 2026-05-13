"""Unit tests for qBittorrent client helpers (no live daemon)."""

import os
from unittest.mock import patch

from qbittorrent_service import (
    _set_share_limits_payload,
    _torrent_options_ui_prefill,
    enrich_global_stat,
    normalize_qbt_torrent,
    parse_rate_to_bytes_per_sec,
    throughput_preferences_from_env,
)


def test_torrent_options_ui_prefill():
    raw = {
        "dl_limit": 1048576,
        "up_limit": -1,
        "ratio_limit": 2.0,
        "max_seeding_time": 3660,
    }
    d = _torrent_options_ui_prefill(raw)
    assert d["opt_max_download_limit"] == "1048576"
    assert d["opt_max_upload_limit"] == ""
    assert d["opt_seed_ratio"] == "2"
    assert d["opt_seed_time"] == "61"


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


def test_throughput_preferences_from_env_defaults():
    with patch.dict(os.environ, {"PATH": os.environ.get("PATH", "")}, clear=True):
        d = throughput_preferences_from_env()
    assert d["max_connec"] == 5000
    assert d["max_connec_per_torrent"] == 800
    assert d["max_active_downloads"] == 50
    assert d["scheduler_enabled"] is False
    assert d["limit_utp_rate"] is False
    assert d["dl_limit"] == 0 and d["up_limit"] == 0
    assert "bittorrent_protocol" not in d
    assert d["max_ratio_enabled"] is True
    assert d["max_ratio"] == 0.0
    assert d["max_ratio_act"] == 0


def test_throughput_preferences_from_env_overrides():
    with patch.dict(
        os.environ,
        {
            "PATH": os.environ.get("PATH", ""),
            "QBITTORRENT_MAX_CONNEC": "1200",
            "QBITTORRENT_BT_PROTOCOL": "tcp",
        },
        clear=True,
    ):
        d = throughput_preferences_from_env()
    assert d["max_connec"] == 1200
    assert d["bittorrent_protocol"] == 1


def test_throughput_prefs_allow_seeding_omits_ratio_limit():
    with patch.dict(
        os.environ,
        {"PATH": os.environ.get("PATH", ""), "QBITTORRENT_ALLOW_SEEDING": "1"},
        clear=True,
    ):
        d = throughput_preferences_from_env()
    assert "max_ratio_enabled" not in d


def test_set_share_limits_payload_includes_api212_fields():
    d = _set_share_limits_payload(
        ratio_limit="0",
        seeding_time_limit="0",
        inactive_seeding_time_limit="-1",
        share_limit_action="Stop",
        share_limits_mode="MatchAny",
    )
    assert d["shareLimitAction"] == "Stop"
    assert d["shareLimitsMode"] == "MatchAny"
    assert set(d.keys()) >= {
        "ratioLimit",
        "seedingTimeLimit",
        "inactiveSeedingTimeLimit",
        "shareLimitAction",
        "shareLimitsMode",
    }


def test_throughput_prefs_ratio_limit_action_remove():
    with patch.dict(
        os.environ,
        {"PATH": os.environ.get("PATH", ""), "QBITTORRENT_RATIO_LIMIT_ACTION": "1"},
        clear=True,
    ):
        d = throughput_preferences_from_env()
    assert d["max_ratio_act"] == 1
