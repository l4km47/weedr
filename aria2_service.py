"""
Launch a local aria2 daemon (JSON-RPC) and normalize download stats for the UI.
Requires `aria2c` on PATH or ARIA2_BIN.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import shutil
import socket
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

# Upstream: https://github.com/ngosang/trackerslist/blob/master/trackers_best.txt
_TRACKERS_BEST_URL = (
    "https://raw.githubusercontent.com/ngosang/trackerslist/master/trackers_best.txt"
)

# Baked copy of trackers_best (used if fetch fails). Refresh periodically from upstream.
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

# Backwards-compatible name: same as baked fallback (see default_bt_trackers()).
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


def _parse_positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        n = int(raw)
        return n if n > 0 else default
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in ("0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    return default


def aria2_upload_limit_string() -> str:
    """Upload cap for aria2 (0 = unlimited)."""
    raw = (
        os.environ.get("ARIA2_MAX_UPLOAD_LIMIT")
        or os.environ.get("ARIA2_MAX_OVERALL_UPLOAD_LIMIT")
        or "0"
    ).strip()
    return raw if raw else "0"


def aria2_download_limit_string() -> str:
    """Download cap for aria2 (0 = unlimited)."""
    raw = (os.environ.get("ARIA2_MAX_DOWNLOAD_LIMIT") or "0").strip()
    return raw if raw else "0"


def aria2_throughput_rpc_options() -> dict[str, str]:
    """Per-download options for aria2.addUri (string values per RPC)."""
    max_conn = str(_parse_positive_int("ARIA2_MAX_CONNECTION_PER_SERVER", 16))
    split = str(_parse_positive_int("ARIA2_SPLIT", 16))
    min_split = (os.environ.get("ARIA2_MIN_SPLIT_SIZE") or "1M").strip() or "1M"
    ul = aria2_upload_limit_string()
    dl = aria2_download_limit_string()
    return {
        "max-connection-per-server": max_conn,
        "split": split,
        "min-split-size": min_split,
        "max-upload-limit": ul,
        "max-download-limit": dl,
    }


def _aria2_file_allocation_arg() -> str:
    fa = (os.environ.get("ARIA2_FILE_ALLOCATION") or "falloc").strip().lower()
    if fa not in ("none", "prealloc", "trunc", "falloc"):
        fa = "falloc"
    return f"--file-allocation={fa}"


def _aria2_throughput_args() -> list[str]:
    """
    Default throughput matches a typical high-performance aria2.conf
    (split / connections / disk cache). Override via env; restart aria2 after changes.
    """
    max_conn = _parse_positive_int("ARIA2_MAX_CONNECTION_PER_SERVER", 16)
    split = _parse_positive_int("ARIA2_SPLIT", 16)
    min_split = (os.environ.get("ARIA2_MIN_SPLIT_SIZE") or "1M").strip() or "1M"
    bt_peers = _parse_positive_int("ARIA2_BT_MAX_PEERS", 100)
    bt_open = _parse_positive_int("ARIA2_BT_MAX_OPEN_FILES", 1000)
    disk_raw = (os.environ.get("ARIA2_DISK_CACHE") or "64M").strip()
    upl = aria2_upload_limit_string()
    dl = aria2_download_limit_string()

    out = [
        f"--max-connection-per-server={max_conn}",
        f"--split={split}",
        f"--min-split-size={min_split}",
        f"--bt-max-peers={bt_peers}",
        f"--bt-max-open-files={bt_open}",
        "--bt-request-peer-speed-limit=0",
        f"--max-overall-download-limit={dl}",
        f"--max-download-limit={dl}",
        f"--max-overall-upload-limit={upl}",
        f"--max-upload-limit={upl}",
    ]
    if disk_raw.lower() not in ("", "0", "none", "off"):
        out.append(f"--disk-cache={disk_raw}")
    return out


def _aria2_bt_daemon_flags() -> list[str]:
    """DHT/LPD, listen port, optional encryption for the managed daemon."""
    listen = (os.environ.get("ARIA2_LISTEN_PORT") or "6881-6999").strip() or "6881-6999"
    dht_port = (os.environ.get("ARIA2_DHT_LISTEN_PORT") or listen).strip() or listen
    flags: list[str] = [
        f"--listen-port={listen}",
        f"--dht-listen-port={dht_port}",
        f"--bt-enable-lpd={str(_env_bool('ARIA2_BT_ENABLE_LPD', True)).lower()}",
        f"--bt-force-encryption={str(_env_bool('ARIA2_BT_FORCE_ENCRYPTION', True)).lower()}",
    ]
    return flags


class Aria2RPCError(RuntimeError):
    pass


def _which_aria2() -> Path | None:
    env_bin = os.environ.get("ARIA2_BIN")
    if env_bin:
        p = Path(env_bin).expanduser().resolve()
        if p.is_file() and os.access(p, os.X_OK):
            return p
    path = shutil.which("aria2c")
    return Path(path).resolve() if path else None


def _pick_port() -> int:
    base = int(os.environ.get("ARIA2_RPC_PORT_BASE", "16800"))
    for delta in range(0, 40):
        port = base + delta
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise Aria2RPCError("Could not bind a local RPC port for aria2")


def _read_secret(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def _write_secret(path: Path, secret: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(secret, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


class Aria2Service:
    """Manage one aria2 daemon bound to localhost."""

    def __init__(
        self,
        download_dir: Path,
        state_dir: Path,
        rpc_port: int | None = None,
        rpc_secret: str | None = None,
        max_concurrent_downloads: int | None = None,
    ) -> None:
        self.download_dir = Path(download_dir).expanduser().resolve()
        self.state_dir = Path(state_dir).expanduser().resolve()
        self.rpc_port = rpc_port or int(os.environ.get("ARIA2_RPC_PORT", "0")) or 0
        self._rpc_secret_override = rpc_secret
        self.max_concurrent_downloads = max_concurrent_downloads or int(
            os.environ.get("ARIA2_MAX_CONCURRENT", "5")
        )
        self._secret_file = self.state_dir / "aria2.rpc.secret"
        self._pid_file = self.state_dir / "aria2.pid"
        self._daemon_proc: subprocess.Popen[str] | None = None
        self._start_lock = threading.Lock()
        self._upload_limit_sync_ts: float | None = None

    def rpc_url(self) -> str:
        port = self.rpc_port if self.rpc_port else int(os.environ.get("ARIA2_RPC_PORT", "6800"))
        return f"http://127.0.0.1:{port}/jsonrpc"

    def secret(self) -> str:
        if self._rpc_secret_override:
            return self._rpc_secret_override
        if self._secret_file.is_file():
            return _read_secret(self._secret_file)
        sec = secrets.token_urlsafe(32)
        _write_secret(self._secret_file, sec)
        return sec

    def call(self, method: str, params: list[Any] | None = None) -> Any:
        params = params or []
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": [f"token:{self.secret()}"] + params,
        }
        body = json.dumps(payload).encode("utf-8")
        req = Request(
            self.rpc_url(),
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=60) as resp:
                raw = json.loads(resp.read().decode("utf-8"))
        except HTTPError as e:
            raise Aria2RPCError(f"RPC HTTP error: {e}") from e
        except URLError as e:
            raise Aria2RPCError(f"RPC connection failed: {e}") from e

        if "error" in raw:
            err = raw["error"]
            raise Aria2RPCError(str(err))
        return raw.get("result")

    def ping(self) -> bool:
        try:
            self.call("aria2.getVersion")
            return True
        except OSError:
            return False
        except Aria2RPCError:
            return False

    def _sync_upload_limits_to_daemon(self) -> None:
        """
        Push global download/upload caps and per-active-GID limits over RPC.

        When the daemon was started by an older app version, options may not
        match current env; this runs periodically so changes apply without
        manually killing aria2c.
        """
        now = time.time()
        if self._upload_limit_sync_ts is not None and now - self._upload_limit_sync_ts < 15.0:
            return
        self._upload_limit_sync_ts = now
        ul = aria2_upload_limit_string()
        dl = aria2_download_limit_string()
        gopts = {
            "max-overall-upload-limit": ul,
            "max-upload-limit": ul,
            "max-overall-download-limit": dl,
            "max-download-limit": dl,
        }
        try:
            self.call("aria2.changeGlobalOption", [gopts])
        except Aria2RPCError as e:
            logger.warning("aria2.changeGlobalOption speed limits: %s", e)
            return
        try:
            active = self.call("aria2.tellActive", [])
        except Aria2RPCError as e:
            logger.warning("aria2.tellActive during upload limit sync: %s", e)
            return
        if not isinstance(active, list):
            return
        for row in active:
            if not isinstance(row, dict):
                continue
            gid = row.get("gid")
            if not gid:
                continue
            try:
                self.call(
                    "aria2.changeOption",
                    [gid, {"max-upload-limit": ul, "max-download-limit": dl}],
                )
            except Aria2RPCError as e:
                logger.debug("aria2.changeOption speed limits %s: %s", gid, e)

    def ensure_daemon(self) -> None:
        with self._start_lock:
            if self.ping():
                self._sync_upload_limits_to_daemon()
                return
            aria2 = _which_aria2()
            if not aria2:
                raise Aria2RPCError(
                    "aria2c not found. Install aria2 or set ARIA2_BIN to the binary path."
                )

            if not self.rpc_port:
                self.rpc_port = _pick_port()

            self.download_dir.mkdir(parents=True, exist_ok=True)
            self.state_dir.mkdir(parents=True, exist_ok=True)
            session_file = self.state_dir / "aria2.session"
            session_file.touch(exist_ok=True)

            dht = self.state_dir / "dht.dat"
            dht6 = self.state_dir / "dht6.dat"
            trackers = (os.environ.get("ARIA2_BT_TRACKERS") or "").strip() or default_bt_trackers()
            seed_time = os.environ.get("ARIA2_SEED_TIME", "0")
            # 0 disables ratio-based seed stop; use with seed-time=0 so nothing seeds after complete.
            seed_ratio = os.environ.get("ARIA2_SEED_RATIO", "0")

            args = [
                str(aria2),
                "--daemon=true",
                "--no-conf=true",
                "--enable-rpc=true",
                "--rpc-listen-all=false",
                f"--rpc-listen-port={self.rpc_port}",
                f"--rpc-secret={self.secret()}",
                "--rpc-max-request-size=16M",
                "--disable-ipv6=false",
                f"--dir={self.download_dir}",
                "--continue=true",
                _aria2_file_allocation_arg(),
                f"--seed-time={seed_time}",
                f"--seed-ratio={seed_ratio}",
                "--bt-save-metadata=true",
                f"--bt-tracker={trackers}",
                "--enable-dht=true",
                "--enable-dht6=true",
                f"--dht-file-path={dht}",
                f"--dht-file-path6={dht6}",
                "--follow-torrent=mem",
                *_aria2_bt_daemon_flags(),
                *_aria2_throughput_args(),
                f"--max-concurrent-downloads={self.max_concurrent_downloads}",
                "--save-session-interval=30",
                f"--save-session={session_file}",
                f"--input-file={session_file}",
            ]

            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0

            subprocess.run(args, check=True, creationflags=creationflags)

            deadline = time.time() + 30
            while time.time() < deadline:
                if self.ping():
                    logger.info("aria2 daemon ready on port %s", self.rpc_port)
                    self._sync_upload_limits_to_daemon()
                    return
                time.sleep(0.2)

            raise Aria2RPCError("aria2 daemon did not respond to RPC in time")


_service: Aria2Service | None = None


def get_service(
    download_dir: Path | None = None,
    state_dir: Path | None = None,
) -> Aria2Service:
    global _service
    if _service is None:
        dd = Path(download_dir or os.environ.get("DOWNLOAD_DIR", Path.home() / "torrents")).expanduser()
        sd = Path(
            state_dir or os.environ.get("ARIA2_STATE_DIR", Path.home() / ".cache" / "torrent-server")
        ).expanduser()
        rp = os.environ.get("ARIA2_RPC_PORT", "").strip()
        port = int(rp) if rp.isdigit() else 0
        secret = os.environ.get("ARIA2_RPC_SECRET")
        _service = Aria2Service(dd, sd, rpc_port=port or None, rpc_secret=secret or None)
    return _service


def format_speed(bps: int) -> str:
    if bps >= 1 << 30:
        return f"{bps / (1 << 30):.2f} GiB/s"
    if bps >= 1 << 20:
        return f"{bps / (1 << 20):.2f} MiB/s"
    if bps >= 1024:
        return f"{bps / 1024:.1f} KiB/s"
    return f"{bps} B/s"


def format_size_bytes(n: int) -> str:
    n = max(0, int(n))
    for suf, div in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= div:
            return f"{n / div:.2f} {suf}"
    return f"{n} B"


def _parse_bps_value(v: Any) -> int:
    if v is None:
        return 0
    try:
        return int(str(v).strip())
    except ValueError:
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return 0


def enrich_global_stat(stats: dict[str, Any]) -> dict[str, Any]:
    """Add human-readable speeds; aria2 returns global speeds as string integers."""
    out = dict(stats)
    ds = _parse_bps_value(out.get("downloadSpeed"))
    us = _parse_bps_value(out.get("uploadSpeed"))
    out["downloadSpeed_bps"] = ds
    out["uploadSpeed_bps"] = us
    out["download_speed_human"] = format_speed(ds)
    out["upload_speed_human"] = format_speed(us)
    return out


def format_eta(seconds: int | None) -> str:
    if seconds is None:
        return "—"
    if seconds < 0:
        return "—"
    if seconds > 86400 * 7:
        return ">7d"
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h:d}:{m:02d}:{s:02d}"
    return f"{m:d}:{s:02d}"


def normalize_download(raw: dict[str, Any]) -> dict[str, Any]:
    gid = raw.get("gid") or ""
    status = raw.get("status") or ""
    total = int(raw.get("totalLength") or 0)
    completed = int(raw.get("completedLength") or 0)
    ds = int(raw.get("downloadSpeed") or 0)
    us = int(raw.get("uploadSpeed") or 0)
    connections = int(raw.get("connections") or 0)

    eta_sec: int | None = None
    if ds > 0 and total > completed and status == "active":
        eta_sec = max(0, (total - completed) // ds)

    progress = 0.0
    if total > 0:
        progress = round(100.0 * completed / total, 2)

    name = ""
    bt = raw.get("bittorrent")
    if isinstance(bt, dict):
        info = bt.get("info")
        if isinstance(info, dict):
            name = str(info.get("name") or "")
        if not name:
            name = str(bt.get("name") or "")
    files = raw.get("files")
    if not name and isinstance(files, list) and files:
        p0 = files[0].get("path") if isinstance(files[0], dict) else None
        if p0:
            name = Path(str(p0)).name
    if not name:
        name = gid[:12] if gid else "download"

    num_seeders = raw.get("numSeeders")
    num_leechers = raw.get("numLeechers")
    if num_seeders is None and isinstance(bt, dict):
        num_seeders = bt.get("numSeeders")
        num_leechers = bt.get("numLeechers")

    piece_length = raw.get("pieceLength")
    num_pieces = raw.get("numPieces")

    return {
        "gid": gid,
        "status": status,
        "name": name,
        "total_length": total,
        "completed_length": completed,
        "progress_percent": progress,
        "download_speed": ds,
        "download_speed_human": format_speed(ds),
        "upload_speed": us,
        "upload_speed_human": format_speed(us),
        "eta_seconds": eta_sec,
        "eta_human": format_eta(eta_sec),
        "connections": connections,
        "num_seeders": num_seeders,
        "num_leechers": num_leechers,
        "piece_length": piece_length,
        "num_pieces": num_pieces,
        "dir": raw.get("dir") or "",
        "error_code": raw.get("errorCode"),
        "error_message": raw.get("errorMessage"),
        "followed_by": raw.get("followedBy"),
        "following": raw.get("following"),
        "belongs_to": raw.get("belongsTo"),
    }


def fetch_all_downloads(svc: Aria2Service) -> dict[str, list[dict[str, Any]]]:
    keys = [
        "gid",
        "status",
        "totalLength",
        "completedLength",
        "downloadSpeed",
        "uploadSpeed",
        "connections",
        "errorCode",
        "errorMessage",
        "dir",
        "files",
        "bittorrent",
        "pieceLength",
        "numPieces",
        "followedBy",
        "following",
        "belongsTo",
        "numSeeders",
        "numLeechers",
    ]

    def fetch_list(method: str, params: list[Any]) -> list[dict[str, Any]]:
        try:
            result = svc.call(method, params)
        except Aria2RPCError:
            return []
        out: list[dict[str, Any]] = []
        if not isinstance(result, list):
            return out
        for item in result:
            if isinstance(item, dict) and item.get("gid"):
                out.append(normalize_download(item))
        return out

    active = fetch_list("aria2.tellActive", [keys])
    waiting = fetch_list("aria2.tellWaiting", [0, 1000, keys])
    stopped = fetch_list("aria2.tellStopped", [0, 1000, keys])
    return {
        "active": _hide_metadata_placeholders(active),
        "waiting": _hide_metadata_placeholders(waiting),
        "stopped": _hide_metadata_placeholders(stopped),
    }


def _hide_metadata_placeholders(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    aria2 creates a separate BitTorrent download named '[METADATA]…' while resolving magnets.
    Hide those rows in the UI so each torrent appears once.
    """
    out: list[dict[str, Any]] = []
    for d in rows:
        name = (d.get("name") or "").lstrip()
        if name.upper().startswith("[METADATA]"):
            continue
        out.append(d)
    return out


def fetch_download_detail(svc: Aria2Service, gid: str) -> dict[str, Any] | None:
    """Full tellStatus + per-file progress for the transfers detail pane."""
    detail_keys = [
        "gid",
        "status",
        "totalLength",
        "completedLength",
        "downloadSpeed",
        "uploadSpeed",
        "connections",
        "errorCode",
        "errorMessage",
        "dir",
        "files",
        "bittorrent",
        "pieceLength",
        "numPieces",
        "numSeeders",
        "numLeechers",
        "followedBy",
        "following",
        "belongsTo",
    ]
    try:
        raw = svc.call("aria2.tellStatus", [gid, detail_keys])
    except Aria2RPCError:
        return None
    if not isinstance(raw, dict) or not raw.get("gid"):
        return None

    torrent = normalize_download(raw)
    files_out: list[dict[str, Any]] = []
    for f in raw.get("files") or []:
        if not isinstance(f, dict):
            continue
        try:
            idx = int(str(f.get("index") or "0"))
        except ValueError:
            idx = 0
        path = str(f.get("path") or "")
        tl = int(f.get("length") or 0)
        cl = int(f.get("completedLength") or 0)
        selected_raw = f.get("selected")
        sel = str(selected_raw).lower() in ("true", "1")
        pct = round(100.0 * cl / tl, 2) if tl > 0 else 0.0
        disp = Path(path).name if path else ""
        files_out.append(
            {
                "index": idx,
                "path": path,
                "path_display": disp or path,
                "length": tl,
                "length_human": format_size_bytes(tl),
                "completed_length": cl,
                "progress_percent": pct,
                "selected": sel,
            }
        )
    files_out.sort(key=lambda x: x["index"])
    return {"torrent": torrent, "files": files_out}


def global_stat(svc: Aria2Service) -> dict[str, Any]:
    try:
        stats = svc.call("aria2.getGlobalStat") or {}
    except Aria2RPCError:
        stats = {}
    stats = enrich_global_stat(stats) if stats else stats
    try:
        ver = svc.call("aria2.getVersion") or {}
    except Aria2RPCError:
        ver = {}
    return {"global": stats, "version": ver.get("version"), "enabled_features": ver.get("enabledFeatures")}
