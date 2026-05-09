"""Parse magnet URIs and build safe per-torrent download subfolders."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import parse_qsl, unquote

from werkzeug.utils import secure_filename

_BTIH_IN_XT = re.compile(r"urn:btih:([a-fA-F0-9]{40}|[a-z2-7]{32})", re.I)


def parse_magnet(uri: str) -> dict[str, str | int | None]:
    """Return btih (lowercase hex / base32), optional dn, optional xl size in bytes."""
    uri = uri.strip()
    if not uri.lower().startswith("magnet:"):
        raise ValueError("Not a magnet URI")
    qmark = uri.find("?")
    qs = uri[qmark + 1 :] if qmark >= 0 else ""
    params = dict(parse_qsl(qs, keep_blank_values=True))

    xt = params.get("xt") or ""
    m = _BTIH_IN_XT.search(xt)
    btih = (m.group(1).lower() if m else "") or ""

    dn = unquote(params.get("dn") or "").strip()
    xl: int | None = None
    if "xl" in params and params["xl"]:
        try:
            xl = int(params["xl"])
        except ValueError:
            xl = None

    return {"btih": btih, "dn": dn if dn else None, "xl": xl}


def auto_subfolder_name(dn: str | None, btih: str) -> str:
    """Human-readable folder under downloads; falls back to btih prefix."""
    if dn:
        raw = dn.replace("/", "_").replace("\\", "_")
        name = secure_filename(raw) or ""
        name = name.replace(" ", "_")
        if not name:
            name = "torrent-" + hashlib.sha256(dn.encode("utf-8")).hexdigest()[:12]
    else:
        name = ""
    if not name and btih:
        name = f"torrent-{btih[:12]}"
    if not name:
        name = "torrent"
    return name[:120]


def pick_unique_dir(parent: Path, base_name: str) -> Path:
    """Return parent/base_name, or parent/base_name-2, etc. if needed."""
    parent.mkdir(parents=True, exist_ok=True)
    safe = base_name.strip() or "torrent"
    candidate = parent / safe
    if not candidate.exists():
        return candidate
    n = 2
    while True:
        c = parent / f"{safe}-{n}"
        if not c.exists():
            return c
        n += 1
