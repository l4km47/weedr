"""Experimental RSS poll: extract magnet links from feed XML/HTML text."""

from __future__ import annotations

import re
import urllib.error
import urllib.request

_MAGNET_RE = re.compile(r"magnet:\?[^\s<>'\"]+", re.I)


def fetch_magnets_from_feed_url(url: str, timeout: float = 45.0) -> list[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "weedr-rss/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.URLError:
        return []
    text = raw.decode("utf-8", errors="ignore")
    out: list[str] = []
    seen: set[str] = set()
    for m in _MAGNET_RE.finditer(text):
        mag = m.group(0).rstrip('.,);\'"')
        if mag not in seen:
            seen.add(mag)
            out.append(mag)
    return out
