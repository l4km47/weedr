"""Shared BitTorrent tracker list (trackers_best) for qBittorrent and tooling."""

from __future__ import annotations

import logging
import threading
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

_TRACKERS_BEST_URL = (
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt"
)

_DEFAULT_TRACKERS_BAKED = ",".join(
    [
        "udp://tracker.opentrackr.org:1337/announce",
        "udp://open.demonii.com:1337/announce",
        "udp://open.stealth.si:80/announce",
        "udp://wepzone.net:6969/announce",
        "udp://vito-tracker.space:6969/announce",
        "udp://vito-tracker.duckdns.org:6969/announce",
        "udp://udp.tracker.projectk.org:23333/announce",
        "udp://tracker.tryhackx.org:6969/announce",
        "udp://tracker.torrent.eu.org:451/announce",
        "udp://tracker.theoks.net:6969/announce",
        "udp://tracker.t-1.org:6969/announce",
        "udp://tracker.srv00.com:6969/announce",
        "udp://tracker.qu.ax:6969/announce",
        "udp://tracker.plx.im:6969/announce",
        "udp://tracker.opentorrent.top:6969/announce",
        "udp://tracker.gmi.gd:6969/announce",
        "udp://tracker.fnix.net:6969/announce",
        "udp://tracker.flatuslifir.is:6969/announce",
        "udp://tracker.filemail.com:6969/announce",
        "udp://tracker.ducks.party:1984/announce",
    ]
)

_default_trackers_memo: str | None = None
_trackers_fetch_lock = threading.Lock()

# Backwards-compatible name for callers expecting DEFAULT_TRACKERS.
DEFAULT_TRACKERS = _DEFAULT_TRACKERS_BAKED


def default_bt_trackers() -> str:
    """Comma-separated trackers_best list; fetch once per process, fallback if offline."""
    global _default_trackers_memo
    with _trackers_fetch_lock:
        if _default_trackers_memo is not None:
            return _default_trackers_memo
        try:
            req = Request(
                _TRACKERS_BEST_URL,
                headers={"User-Agent": "torrent-server (trackerslist consumer)"},
                method="GET",
            )
            with urlopen(req, timeout=10) as resp:
                text = resp.read().decode("utf-8", errors="replace")
            lines = [
                ln.strip()
                for ln in text.splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
            _default_trackers_memo = ",".join(lines) if lines else _DEFAULT_TRACKERS_BAKED
        except (OSError, HTTPError, URLError, ValueError) as e:
            logger.warning("trackers_best fetch failed, using baked list: %s", e)
            _default_trackers_memo = _DEFAULT_TRACKERS_BAKED
        return _default_trackers_memo


def trackers_for_qbittorrent() -> str:
    """qBittorrent `torrents/add` trackers field: newline-separated announce URLs."""
    return "\n".join(t.strip() for t in default_bt_trackers().split(",") if t.strip())
