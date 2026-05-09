"""
Launch a local aria2 daemon (JSON-RPC) and normalize download stats for the UI.
Requires `aria2c` on PATH or ARIA2_BIN.
"""

from __future__ import annotations

import json
import logging
import os
import random
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

DEFAULT_TRACKERS = (
    "udp://tracker.opentrackr.org:1337/announce,"
    "udp://open.stealth.si:80/announce,"
    "udp://tracker.torrent.eu.org:451/announce,"
    "udp://exodus.desync.com:6969/announce,"
    "udp://tracker.openbittorrent.com:6969/announce,"
    "udp://tracker.internetwarriors.net:1337/announce"
)


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
            os.environ.get("ARIA2_MAX_CONCURRENT", "8")
        )
        self._secret_file = self.state_dir / "aria2.rpc.secret"
        self._pid_file = self.state_dir / "aria2.pid"
        self._daemon_proc: subprocess.Popen[str] | None = None
        self._start_lock = threading.Lock()

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

    def ensure_daemon(self) -> None:
        with self._start_lock:
            if self.ping():
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

            dht = self.state_dir / "dht.dat"
            dht6 = self.state_dir / "dht6.dat"
            trackers = os.environ.get("ARIA2_BT_TRACKERS", DEFAULT_TRACKERS)
            seed_time = os.environ.get("ARIA2_SEED_TIME", "0")

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
                "--file-allocation=falloc",
                f"--seed-time={seed_time}",
                "--bt-save-metadata=true",
                f"--bt-tracker={trackers}",
                "--enable-dht=true",
                "--enable-dht6=true",
                f"--dht-file-path={dht}",
                f"--dht-file-path6={dht6}",
                "--follow-torrent=mem",
                "--max-connection-per-server=16",
                "--split=16",
                "--min-split-size=1M",
                f"--max-concurrent-downloads={self.max_concurrent_downloads}",
                "--save-session-interval=30",
                f"--save-session={self.state_dir / 'aria2.session'}",
                "--input-file=" + str(self.state_dir / "aria2.session"),
            ]

            creationflags = 0
            if os.name == "nt":
                creationflags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]

            subprocess.run(args, check=True, creationflags=creationflags)

            deadline = time.time() + 30
            while time.time() < deadline:
                if self.ping():
                    logger.info("aria2 daemon ready on port %s", self.rpc_port)
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
        port = int(os.environ["ARIA2_RPC_PORT"]) if os.environ.get("ARIA2_RPC_PORT") else 0
        secret = os.environ.get("ARIA2_RPC_SECRET")
        _service = Aria2Service(dd, sd, rpc_port=port or None, rpc_secret=secret or None)
    return _service


def format_speed(bps: int) -> str:
    if bps >= 1_048_576:
        return f"{bps / 1_048_576:.2f} MiB/s"
    if bps >= 1024:
        return f"{bps / 1024:.1f} KiB/s"
    return f"{bps} B/s"


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
        "raw": raw,
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

    def fetch(method: str, *extra: Any) -> list[dict[str, Any]]:
        try:
            result = svc.call(method, list(extra))
        except Aria2RPCError:
            return []
        out: list[dict[str, Any]] = []
        if not isinstance(result, list):
            return out
        for item in result:
            if not isinstance(item, dict):
                continue
            gid = item.get("gid")
            if not gid:
                continue
            try:
                full = svc.call("aria2.tellStatus", [gid, keys])
            except Aria2RPCError:
                full = item
            if isinstance(full, dict):
                out.append(normalize_download(full))
        return out

    active = fetch("aria2.tellActive", keys)
    waiting = fetch("aria2.tellWaiting", 0, 1000, keys)
    stopped = fetch("aria2.tellStopped", 0, 1000, keys)
    return {"active": active, "waiting": waiting, "stopped": stopped}


def global_stat(svc: Aria2Service) -> dict[str, Any]:
    try:
        stats = svc.call("aria2.getGlobalStat") or {}
    except Aria2RPCError:
        stats = {}
    try:
        ver = svc.call("aria2.getVersion") or {}
    except Aria2RPCError:
        ver = {}
    return {"global": stats, "version": ver.get("version"), "enabled_features": ver.get("enabledFeatures")}
