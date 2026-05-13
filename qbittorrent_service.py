"""
qBittorrent-nox Web API v2 client: optional local daemon spawn, torrent ops, UI-shaped stats.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from pathutil import safe_under_root
from trackers_util import trackers_for_qbittorrent

logger = logging.getLogger(__name__)


class QBittorrentError(RuntimeError):
    pass


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in ("0", "false", "no", "off"):
        return False
    if raw in ("1", "true", "yes", "on"):
        return True
    return default


def _parse_positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        n = int(raw)
        return n if n > 0 else default
    except ValueError:
        return default


def _env_int(name: str, default: int, *, min_ok: int = 1) -> int:
    """Parse a positive int from env; invalid or missing returns default."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        n = int(raw)
    except ValueError:
        return default
    return n if n >= min_ok else default


def _env_int_allow_neg1(name: str, default: int) -> int:
    """Like _env_int but allows -1 (qBittorrent 'unlimited' for some slots)."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        n = int(raw)
    except ValueError:
        return default
    if n == -1:
        return -1
    return n if n > 0 else default


# Human-readable byte rate (e.g. 4M, 1G) -> bytes/sec for qBittorrent limits.
_RATE_RE = re.compile(
    r"^\s*(\d+(?:\.\d+)?)\s*([kmgt])?(i?b)?(/s)?\s*$",
    re.I,
)


def parse_rate_to_bytes_per_sec(s: str) -> int:
    """Parse aria2-style limit strings into bytes per second (0 = unlimited)."""
    s = (s or "").strip()
    if not s or s == "0":
        return 0
    m = _RATE_RE.match(s)
    if not m:
        try:
            return max(0, int(float(s)))
        except ValueError:
            return 0
    val = float(m.group(1))
    suf = (m.group(2) or "").lower()
    mult = 1.0
    if suf == "k":
        mult = 1024
    elif suf == "m":
        mult = 1024**2
    elif suf == "g":
        mult = 1024**3
    elif suf == "t":
        mult = 1024**4
    return max(0, int(val * mult))


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


def format_eta(seconds: int | None) -> str:
    if seconds is None or seconds < 0:
        return "—"
    if seconds > 86400 * 7:
        return ">7d"
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h:d}:{m:02d}:{s:02d}"
    return f"{m:d}:{s:02d}"


def _which_qbittorrent() -> Path | None:
    env_bin = os.environ.get("QBITTORRENT_BIN")
    if env_bin:
        p = Path(env_bin).expanduser().resolve()
        if p.is_file() and os.access(p, os.X_OK):
            return p
    for name in ("qbittorrent-nox", "qbittorrent"):
        path = shutil.which(name)
        if path:
            return Path(path).resolve()
    return None


def _pick_webui_port() -> int:
    base = int(os.environ.get("QBITTORRENT_PORT_BASE", "18080"))
    for delta in range(0, 80):
        port = base + delta
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise QBittorrentError("Could not bind a local port for qBittorrent WebUI")


def _write_qbt_conf(
    path: Path,
    *,
    download_dir: Path,
    webui_port: int,
    bypass_localhost_auth: bool,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    save = str(download_dir.resolve()).replace("\\", "/")
    bypass = "true" if bypass_localhost_auth else "false"
    # INI keys use backslashes per qBittorrent convention (one backslash in file).
    text = f"""[LegalNotice]
Accepted=true

[Preferences]
WebUI\\Address=127.0.0.1
WebUI\\Port={webui_port}
WebUI\\BypassLocalAuth={bypass}
WebUI\\LocalHostAuth=false
Downloads\\SavePath={save}
Session\\DefaultSavePath={save}
Bittorrent\\DHT=true
Bittorrent\\LSD=true
Bittorrent\\PeX=true
Connection\\PortRangeMin=6881
Connection\\PortRangeMax=6999
"""
    path.write_text(text, encoding="utf-8")


def _qbt_state_to_ui(state: str, progress: float, dlspeed: int, upspeed: int) -> str:
    """Map qBittorrent `state` to aria2-like status for the existing UI."""
    st = (state or "").lower()
    prog = float(progress or 0.0)
    _ = (dlspeed, upspeed)  # reserved for finer stalled vs active if needed
    if st in ("error", "missingfiles"):
        return "error"
    if st in ("stoppeddl", "stoppedup"):
        return "complete" if prog >= 0.999 else "stopped"
    if st in ("pauseddl", "pausedup") and prog >= 0.999:
        return "complete"
    if st in ("queueddl", "queuedup"):
        return "waiting"
    if st in ("pauseddl", "pausedup"):
        return "paused"
    if st in (
        "downloading",
        "stalleddl",
        "metadl",
        "allocating",
        "forceddl",
        "checkingdl",
        "uploading",
        "stalledup",
        "forcedup",
        "checkingup",
        "checkingresumedata",
        "moving",
    ):
        return "active"
    return "stopped"


def _list_bucket(state: str, progress: float) -> str:
    """Bucket for /api/torrents list: active | waiting | stopped."""
    ui = _qbt_state_to_ui(state, progress, 0, 0)
    st = (state or "").lower()
    if ui == "waiting" or st in ("queueddl", "queuedup"):
        return "waiting"
    if ui in ("error", "complete", "stopped") or st in ("stoppeddl", "stoppedup", "error", "missingfiles"):
        return "stopped"
    return "active"


def _pick_raw(raw: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in raw and raw[k] is not None:
            return raw[k]
    return None


def normalize_qbt_torrent(raw: dict[str, Any]) -> dict[str, Any]:
    gid = str(raw.get("hash") or "").lower()
    state = str(raw.get("state") or "")
    try:
        progress = float(raw.get("progress") or 0.0)
    except (TypeError, ValueError):
        progress = 0.0
    total = int(_pick_raw(raw, "total_size", "size") or 0)
    completed = int(_pick_raw(raw, "downloaded", "downloaded_session") or 0)
    if completed > total and total > 0:
        completed = total
    ds = int(_pick_raw(raw, "dlspeed", "dl_speed") or 0)
    us = int(_pick_raw(raw, "upspeed", "up_speed") or 0)
    connections = int(raw.get("num_leechs") or 0) + int(raw.get("num_seeds") or 0)

    eta_sec: int | None = None
    if ds > 0 and total > completed and progress < 1.0:
        eta_sec = max(0, (total - completed) // ds)

    pct = round(100.0 * progress, 2) if progress else round(100.0 * completed / total, 2) if total else 0.0

    name = str(raw.get("name") or gid[:16] or "download")
    err_msg = None
    if state.lower() in ("error", "missingfiles"):
        err_msg = str(raw.get("status_message") or raw.get("state") or "error")

    return {
        "gid": gid,
        "status": _qbt_state_to_ui(state, progress, ds, us),
        "name": name,
        "total_length": total,
        "completed_length": completed,
        "progress_percent": pct,
        "download_speed": ds,
        "download_speed_human": format_speed(ds),
        "upload_speed": us,
        "upload_speed_human": format_speed(us),
        "eta_seconds": eta_sec,
        "eta_human": format_eta(eta_sec),
        "connections": connections,
        "num_seeders": raw.get("num_seeds"),
        "num_leechers": raw.get("num_leechs"),
        "piece_length": raw.get("piece_size"),
        "num_pieces": None,
        "dir": str(_pick_raw(raw, "save_path", "savePath") or ""),
        "error_code": None,
        "error_message": err_msg,
        "followed_by": None,
        "following": None,
        "belongs_to": None,
        "_qbt_state": state,
        "_qbt_progress": progress,
    }


class QBittorrentService:
    def __init__(
        self,
        download_dir: Path,
        state_dir: Path,
        base_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        webui_port: int | None = None,
    ) -> None:
        self.download_dir = Path(download_dir).expanduser().resolve()
        self.state_dir = Path(state_dir).expanduser().resolve()
        self._base_url = (base_url or os.environ.get("QBITTORRENT_URL") or "").strip().rstrip("/")
        self._username = (username or os.environ.get("QBITTORRENT_USERNAME") or "admin").strip()
        self._password = password or os.environ.get("QBITTORRENT_PASSWORD") or ""
        rp = os.environ.get("QBITTORRENT_WEBUI_PORT", "").strip()
        self._webui_port = webui_port or (int(rp) if rp.isdigit() else 0)
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "torrent-server-qbt/1"})
        self._lock = threading.Lock()
        self._logged_in = False
        self._throughput_prefs_applied = False
        self._daemon_proc: subprocess.Popen[str] | None = None
        self._auto_started = False

    def base_url(self) -> str:
        if self._base_url:
            return self._base_url
        port = self._webui_port or int(os.environ.get("QBITTORRENT_WEBUI_PORT", "8080"))
        return f"http://127.0.0.1:{port}"

    def _api(self, path: str) -> str:
        return urljoin(self.base_url() + "/", path.lstrip("/"))

    def ping(self) -> bool:
        try:
            r = self._session.get(self._api("api/v2/app/version"), timeout=3)
            return r.status_code == 200 and bool(r.text)
        except OSError:
            return False

    def ensure_daemon(self) -> None:
        if self.ping():
            self._login_if_needed()
            return
        if self._base_url:
            raise QBittorrentError(
                f"qBittorrent Web API not reachable at {self._base_url}. "
                "Check QBITTORRENT_URL / credentials and that qbittorrent-nox is running."
            )
        if os.name == "nt" and not _env_bool("QBITTORRENT_AUTO_START", False):
            raise QBittorrentError(
                "qBittorrent Web API not reachable. On Windows run qbittorrent-nox or the GUI "
                "with Web UI enabled, set QBITTORRENT_URL, or set QBITTORRENT_AUTO_START=1 to try auto-start."
            )
        if not _env_bool("QBITTORRENT_AUTO_START", True):
            raise QBittorrentError(
                "qBittorrent Web API not reachable (QBITTORRENT_AUTO_START=0). "
                "Start qbittorrent-nox and set QBITTORRENT_URL / credentials."
            )
        with self._lock:
            if self.ping():
                self._login_if_needed()
                return
            self._spawn_daemon_locked()
            deadline = time.time() + 45
            while time.time() < deadline:
                if self.ping():
                    self._login_if_needed()
                    logger.info("qBittorrent WebUI ready at %s", self.base_url())
                    return
                time.sleep(0.35)
            raise QBittorrentError("qBittorrent did not become reachable in time")

    def _spawn_daemon_locked(self) -> None:
        if self._daemon_proc and self._daemon_proc.poll() is None:
            return
        binary = _which_qbittorrent()
        if not binary:
            raise QBittorrentError(
                "qbittorrent-nox not found. Install it (e.g. apt install qbittorrent-nox) "
                "or set QBITTORRENT_BIN / QBITTORRENT_URL."
            )
        profile = self.state_dir / "qbittorrent-profile"
        conf_dir = profile / "qBittorrent" / "config"
        if not self._webui_port:
            self._webui_port = _pick_webui_port()
        self._base_url = f"http://127.0.0.1:{self._webui_port}"
        bypass = _env_bool("QBITTORRENT_BYPASS_LOCAL_AUTH", True)
        _write_qbt_conf(
            conf_dir / "qBittorrent.conf",
            download_dir=self.download_dir,
            webui_port=self._webui_port,
            bypass_localhost_auth=bypass,
        )
        self.download_dir.mkdir(parents=True, exist_ok=True)
        args = [str(binary), f"--profile={profile}", "--daemon"]
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        subprocess.run(args, check=True, creationflags=creationflags)
        self._auto_started = True

    def _invalidate_auth(self) -> None:
        self._logged_in = False
        self._throughput_prefs_applied = False

    def _mark_logged_in(self) -> None:
        self._logged_in = True
        self._try_apply_throughput_preferences()

    def _try_apply_throughput_preferences(self) -> None:
        if self._throughput_prefs_applied:
            return
        if _env_bool("QBITTORRENT_SKIP_THROUGHPUT_PREFS", False):
            self._throughput_prefs_applied = True
            return
        try:
            self.apply_throughput_preferences()
            self._throughput_prefs_applied = True
            logger.info("Applied qBittorrent throughput session preferences (setPreferences)")
        except Exception as e:
            logger.warning("qBittorrent throughput preferences not applied: %s", e)

    def apply_throughput_preferences(self) -> None:
        """POST high-throughput-oriented app preferences (qBittorrent Web API setPreferences)."""
        payload = throughput_preferences_from_env()
        self._post(
            "api/v2/app/setPreferences",
            {"json": json.dumps(payload, separators=(",", ":"))},
        )

    def _login_if_needed(self) -> None:
        if self._logged_in:
            return
        bypass = _env_bool("QBITTORRENT_BYPASS_LOCAL_AUTH", True)
        if bypass:
            try:
                r = self._session.get(self._api("api/v2/transfer/info"), timeout=5)
                if r.status_code == 200:
                    self._mark_logged_in()
                    return
            except OSError:
                pass
        data = {"username": self._username, "password": self._password}
        r = self._session.post(self._api("api/v2/auth/login"), data=data, timeout=10)
        if r.status_code != 200 or (r.text or "").strip() != "Ok.":
            raise QBittorrentError(f"qBittorrent auth failed: HTTP {r.status_code} {r.text!r}")
        self._mark_logged_in()

    def _post(self, path: str, data: dict[str, Any] | None = None) -> requests.Response:
        self.ensure_daemon()
        self._login_if_needed()
        r = self._session.post(self._api(path), data=data or {}, timeout=120)
        if r.status_code == 403:
            self._invalidate_auth()
            self._login_if_needed()
            r = self._session.post(self._api(path), data=data or {}, timeout=120)
        if r.status_code == 404:
            raise QBittorrentError(f"API not found: {path}")
        if r.status_code >= 400:
            raise QBittorrentError(f"qBittorrent API error {r.status_code}: {r.text[:500]}")
        return r

    def _get(self, path: str, params: dict[str, Any] | None = None) -> requests.Response:
        self.ensure_daemon()
        self._login_if_needed()
        r = self._session.get(self._api(path), params=params or {}, timeout=120)
        if r.status_code == 403:
            self._invalidate_auth()
            self._login_if_needed()
            r = self._session.get(self._api(path), params=params or {}, timeout=120)
        if r.status_code >= 400:
            raise QBittorrentError(f"qBittorrent API error {r.status_code}: {r.text[:500]}")
        return r

    def app_version(self) -> str:
        r = self._get("api/v2/app/version")
        return (r.text or "").strip()

    def add_magnet(
        self,
        magnet_uri: str,
        save_path: Path,
        *,
        dl_limit_bps: int = 0,
        up_limit_bps: int = 0,
    ) -> None:
        data: dict[str, Any] = {
            "urls": magnet_uri,
            "savepath": str(save_path.resolve()),
            "paused": "false",
            "root_folder": "false",
            "skip_checking": "false",
        }
        if dl_limit_bps > 0:
            data["dlLimit"] = str(dl_limit_bps)
        if up_limit_bps > 0:
            data["upLimit"] = str(up_limit_bps)
        self._post("api/v2/torrents/add", data=data)

    def apply_no_seeding_share_limits(self, info_hash_hex: str) -> None:
        """When QBITTORRENT_ALLOW_SEEDING is unset/false, stop after download (ratio 0; see qBittorrent share limits)."""
        if _env_bool("QBITTORRENT_ALLOW_SEEDING", False):
            return
        h = info_hash_hex.lower()
        self._post(
            "api/v2/torrents/setShareLimits",
            {
                "hashes": h,
                "ratioLimit": "0",
                "seedingTimeLimit": "0",
                "inactiveSeedingTimeLimit": "-1",
            },
        )

    def add_extra_trackers(self, info_hash_hex: str) -> None:
        """Append default + env tracker list (magnet may already include some)."""
        lines = [ln for ln in trackers_for_qbittorrent().split("\n") if ln.strip()]
        custom = (os.environ.get("QBITTORRENT_BT_TRACKERS") or os.environ.get("ARIA2_BT_TRACKERS") or "").strip()
        if custom:
            for t in custom.split(","):
                t = t.strip()
                if t:
                    lines.append(t)
        if not lines:
            return
        self._post(
            "api/v2/torrents/addTrackers",
            {"hash": info_hash_hex.lower(), "urls": "\n".join(lines)},
        )

    def wait_for_torrent(self, info_hash_hex: str, timeout: float = 60.0) -> bool:
        """Poll until torrent appears in transfer list (metadata resolved)."""
        h = info_hash_hex.lower()
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = self._get("api/v2/torrents/info", params={"hashes": h})
            rows = r.json()
            if isinstance(rows, list) and rows:
                return True
            time.sleep(0.25)
        return False

    def fetch_all_downloads(self) -> dict[str, list[dict[str, Any]]]:
        r = self._get("api/v2/torrents/info", params={"filter": "all"})
        rows = r.json()
        if not isinstance(rows, list):
            return {"active": [], "waiting": [], "stopped": []}
        active: list[dict[str, Any]] = []
        waiting: list[dict[str, Any]] = []
        stopped: list[dict[str, Any]] = []
        for raw in rows:
            if not isinstance(raw, dict):
                continue
            try:
                prog = float(raw.get("progress") or 0)
            except (TypeError, ValueError):
                prog = 0.0
            st = str(raw.get("state") or "")
            row = normalize_qbt_torrent(raw)
            bucket = _list_bucket(st, prog)
            if bucket == "waiting":
                waiting.append(row)
            elif bucket == "stopped":
                stopped.append(row)
            else:
                active.append(row)
        return {"active": active, "waiting": waiting, "stopped": stopped}

    def fetch_download_detail(self, info_hash: str) -> dict[str, Any] | None:
        h = info_hash.strip().lower()
        if len(h) != 40:
            return None
        r = self._get("api/v2/torrents/info", params={"hashes": h})
        rows = r.json()
        if not isinstance(rows, list) or not rows:
            return None
        raw = rows[0]
        torrent = normalize_qbt_torrent(raw)
        fr = self._get("api/v2/torrents/files", params={"hash": h})
        files = fr.json()
        files_out: list[dict[str, Any]] = []
        if isinstance(files, list):
            for f in files:
                if not isinstance(f, dict):
                    continue
                idx = int(f.get("index", 0))
                path = str(f.get("name") or "")
                tl = int(f.get("size") or 0)
                prog = float(f.get("progress") or 0)
                cl = int(tl * prog)
                pct = round(100.0 * prog, 2) if tl > 0 else 0.0
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
                        "selected": True,
                    }
                )
        files_out.sort(key=lambda x: x["index"])
        return {"torrent": torrent, "files": files_out}

    def global_stat(self) -> dict[str, Any]:
        r = self._get("api/v2/transfer/info")
        info = r.json() if r.text else {}
        if not isinstance(info, dict):
            info = {}
        ds = int(info.get("dl_info_speed") or info.get("download_info_speed") or 0)
        us = int(info.get("up_info_speed") or info.get("upload_info_speed") or 0)
        dl_list = self.fetch_all_downloads()
        num_active = len(dl_list["active"])
        stats = {
            "downloadSpeed": str(ds),
            "uploadSpeed": str(us),
            "numActive": str(num_active),
        }
        stats = enrich_global_stat(stats)
        ver = self.app_version()
        return {"global": stats, "version": ver, "enabled_features": []}

    def pause(self, info_hash: str) -> None:
        self._post("api/v2/torrents/pause", {"hashes": info_hash.lower()})

    def resume(self, info_hash: str) -> None:
        self._post("api/v2/torrents/resume", {"hashes": info_hash.lower()})

    def top_priority(self, info_hash: str) -> None:
        self._post("api/v2/torrents/topPrio", {"hashes": info_hash.lower()})

    def delete(self, info_hash: str, *, delete_files: bool) -> None:
        self._post(
            "api/v2/torrents/delete",
            {"hashes": info_hash.lower(), "deleteFiles": "true" if delete_files else "false"},
        )

    def purge_finished(self) -> None:
        """Remove completed/stopped torrents from the client (keep files on disk)."""
        r = self._get("api/v2/torrents/info", params={"filter": "all"})
        rows = r.json()
        if not isinstance(rows, list):
            return
        to_remove: list[str] = []
        for raw in rows:
            if not isinstance(raw, dict):
                continue
            st = str(raw.get("state") or "").lower()
            h = str(raw.get("hash") or "").lower()
            if not h:
                continue
            try:
                prog = float(raw.get("progress") or 0)
            except (TypeError, ValueError):
                prog = 0.0
            if st in ("error", "missingfiles"):
                to_remove.append(h)
            elif prog >= 0.999 and st in ("stoppeddl", "stoppedup", "pauseddl", "pausedup"):
                to_remove.append(h)
        if to_remove:
            self._post(
                "api/v2/torrents/delete",
                {"hashes": "|".join(to_remove), "deleteFiles": "false"},
            )

    def set_torrent_options(self, info_hash: str, opts: dict[str, str]) -> None:
        h = info_hash.lower()
        if "max-download-limit" in opts:
            lim = parse_rate_to_bytes_per_sec(str(opts["max-download-limit"]))
            self._post(
                "api/v2/torrents/setDownloadLimit",
                {"hashes": h, "limit": str(lim if lim > 0 else -1)},
            )
        if "max-upload-limit" in opts:
            lim = parse_rate_to_bytes_per_sec(str(opts["max-upload-limit"]))
            self._post(
                "api/v2/torrents/setUploadLimit",
                {"hashes": h, "limit": str(lim if lim > 0 else -1)},
            )
        ratio_lim: float | None = None
        time_lim: int | None = None
        if "seed-ratio" in opts and str(opts["seed-ratio"]).strip():
            try:
                ratio_lim = float(str(opts["seed-ratio"]).strip())
            except ValueError:
                ratio_lim = None
        if "seed-time" in opts and str(opts["seed-time"]).strip():
            try:
                time_lim = int(float(str(opts["seed-time"]).strip()))
            except ValueError:
                time_lim = None
        if ratio_lim is not None or time_lim is not None:
            r_val = str(ratio_lim if ratio_lim is not None and ratio_lim >= 0 else -1)
            t_val = str(time_lim if time_lim is not None and time_lim >= 0 else -1)
            self._post(
                "api/v2/torrents/setShareLimits",
                {
                    "hashes": h,
                    "ratioLimit": r_val,
                    "seedingTimeLimit": t_val,
                    "inactiveSeedingTimeLimit": str(-1),
                },
            )

    def paths_for_delete_on_disk(self, info_hash: str, download_root: Path) -> list[Path]:
        """Resolve torrent payload paths under download_root (for manual delete after API remove)."""

        h = info_hash.strip().lower()
        if len(h) != 40:
            return []
        r = self._get("api/v2/torrents/info", params={"hashes": h})
        rows = r.json()
        if not isinstance(rows, list) or not rows:
            return []
        raw = rows[0]
        out: list[Path] = []
        cp = _pick_raw(raw, "content_path", "contentPath")
        if cp:
            p = Path(str(cp)).resolve()
            ok = safe_under_root(download_root, p)
            if ok:
                out.append(ok)
            return out
        save = _pick_raw(raw, "save_path", "savePath")
        name = str(raw.get("name") or "")
        if save and name:
            p = (Path(str(save)) / name).resolve()
            ok = safe_under_root(download_root, p)
            if ok:
                out.append(ok)
        elif save:
            p = Path(str(save)).resolve()
            ok = safe_under_root(download_root, p)
            if ok:
                out.append(ok)
        return out


def enrich_global_stat(stats: dict[str, Any]) -> dict[str, Any]:
    out = dict(stats)

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

    ds = _parse_bps_value(out.get("downloadSpeed"))
    us = _parse_bps_value(out.get("uploadSpeed"))
    out["downloadSpeed_bps"] = ds
    out["uploadSpeed_bps"] = us
    out["download_speed_human"] = format_speed(ds)
    out["upload_speed_human"] = format_speed(us)
    return out


def qbt_global_options_snapshot(svc: QBittorrentService) -> dict[str, Any]:
    """Subset of preferences for the overview card (string values)."""
    try:
        r = svc._get("api/v2/app/preferences")
        prefs = r.json()
    except QBittorrentError:
        return {}
    if not isinstance(prefs, dict):
        return {}
    keys = (
        "listen_port",
        "max_connec",
        "max_connec_per_torrent",
        "max_active_downloads",
        "max_active_uploads",
        "max_active_torrents",
        "dl_limit",
        "up_limit",
        "scheduler_enabled",
        "limit_utp_rate",
        "max_ratio_enabled",
        "max_ratio",
        "max_ratio_act",
    )
    return {k: prefs.get(k) for k in keys if k in prefs}


_service: QBittorrentService | None = None


def get_service(
    download_dir: Path | None = None,
    state_dir: Path | None = None,
) -> QBittorrentService:
    global _service
    if _service is None:
        dd = Path(download_dir or os.environ.get("DOWNLOAD_DIR", Path.home() / "torrents")).expanduser()
        sd = Path(
            os.environ.get("QBITTORRENT_STATE_DIR")
            or os.environ.get("ARIA2_STATE_DIR")
            or (Path.home() / ".cache" / "torrent-server")
        ).expanduser()
        rp = os.environ.get("QBITTORRENT_WEBUI_PORT", "").strip()
        port = int(rp) if rp.isdigit() else 0
        _service = QBittorrentService(dd.resolve(), sd.resolve(), webui_port=port or None)
    return _service


def throughput_limits_bps() -> tuple[int, int]:
    """Upload/download caps in bytes/sec from env (0 = unlimited)."""
    ul_raw = (
        os.environ.get("QBITTORRENT_MAX_UPLOAD_BPS")
        or os.environ.get("ARIA2_MAX_UPLOAD_LIMIT")
        or os.environ.get("ARIA2_MAX_OVERALL_UPLOAD_LIMIT")
        or "0"
    )
    dl_raw = os.environ.get("QBITTORRENT_MAX_DOWNLOAD_BPS") or os.environ.get("ARIA2_MAX_DOWNLOAD_LIMIT") or "0"
    return parse_rate_to_bytes_per_sec(str(dl_raw)), parse_rate_to_bytes_per_sec(str(ul_raw))


def throughput_preferences_from_env() -> dict[str, Any]:
    """Preferences for qBittorrent `app/setPreferences` — raises libtorrent ceilings (not swarm speed)."""
    dl_cap, up_cap = throughput_limits_bps()
    prefs: dict[str, Any] = {
        "scheduler_enabled": False,
        "dl_limit": int(dl_cap),
        "up_limit": int(up_cap),
        "alt_dl_limit": 0,
        "alt_up_limit": 0,
        "limit_utp_rate": False,
        "limit_lan_peers": False,
        "limit_tcp_overhead": False,
        "max_connec": _env_int("QBITTORRENT_MAX_CONNEC", 5000, min_ok=100),
        "max_connec_per_torrent": _env_int("QBITTORRENT_MAX_CONNEC_PER_TORRENT", 800, min_ok=20),
        "max_uploads": _env_int_allow_neg1("QBITTORRENT_MAX_UPLOAD_SLOTS", -1),
        "max_uploads_per_torrent": _env_int_allow_neg1("QBITTORRENT_MAX_UPLOAD_SLOTS_PER_TORRENT", -1),
        "max_active_downloads": _env_int("QBITTORRENT_MAX_ACTIVE_DOWNLOADS", 50, min_ok=1),
        "max_active_torrents": _env_int("QBITTORRENT_MAX_ACTIVE_TORRENTS", 200, min_ok=1),
        "max_active_uploads": _env_int("QBITTORRENT_MAX_ACTIVE_UPLOADS", 100, min_ok=1),
        "max_active_checking_torrents": _env_int("QBITTORRENT_MAX_ACTIVE_CHECKING", 32, min_ok=1),
        "queueing_enabled": _env_bool("QBITTORRENT_QUEUEING_ENABLED", True),
        "dont_count_slow_torrents": _env_bool("QBITTORRENT_DONT_COUNT_SLOW_TORRENTS", True),
        "slow_torrent_dl_rate_threshold": _env_int("QBITTORRENT_SLOW_TORRENT_DL_KIB", 50, min_ok=1),
        "utp_tcp_mixed_mode": _env_int("QBITTORRENT_UTP_TCP_MIXED_MODE", 0, min_ok=0),
        "async_io_threads": _env_int("QBITTORRENT_ASYNC_IO_THREADS", 8, min_ok=1),
        "file_pool_size": _env_int("QBITTORRENT_FILE_POOL_SIZE", 500, min_ok=40),
    }
    proto = (os.environ.get("QBITTORRENT_BT_PROTOCOL") or "").strip().lower()
    if proto in ("tcp", "tcp_only", "1"):
        prefs["bittorrent_protocol"] = 1
    elif proto in ("utp", "utp_only", "2"):
        prefs["bittorrent_protocol"] = 2
    sb = (os.environ.get("QBITTORRENT_SOCKET_SEND_BUFFER") or "").strip()
    if sb.isdigit():
        prefs["socket_send_buffer_size"] = int(sb)
    rb = (os.environ.get("QBITTORRENT_SOCKET_RECV_BUFFER") or "").strip()
    if rb.isdigit():
        prefs["socket_receive_buffer_size"] = int(rb)
    if not _env_bool("QBITTORRENT_ALLOW_SEEDING", False):
        # Ratio 0: pause/remove when download finishes (no post-complete seeding). max_ratio_act: 0=Pause, 1=Remove.
        act = _env_int("QBITTORRENT_RATIO_LIMIT_ACTION", 0, min_ok=0)
        prefs["max_ratio_enabled"] = True
        prefs["max_ratio"] = 0.0
        prefs["max_ratio_act"] = 1 if act >= 1 else 0
    return prefs
