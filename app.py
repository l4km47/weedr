"""
Torrent dashboard: qBittorrent-nox Web API for BitTorrent, concurrent downloads, live stats,
file management, hardened authentication (Argon2, CSRF, secure cookies, rate limits).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import mimetypes
import os
import secrets
import shutil
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

from magnet_util import auto_subfolder_name, btih_info_hash_v1_hex, parse_magnet, pick_unique_dir
from torrent_file_util import TorrentFileError, parse_torrent_metainfo
from qbittorrent_service import (
    QBittorrentError,
    get_service as get_qbittorrent_service,
    qbt_global_options_snapshot,
    throughput_limits_bps,
)
from pathutil import safe_under_root
from range_file_serve import range_file_download_response
from zip_jobs_store import ZipJobsStore

try:
    from flask_wtf.csrf import CSRFProtect
except ImportError as e:  # pragma: no cover
    raise RuntimeError("flask-wtf is required (pip install flask-wtf)") from e

_password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)

_ph_argon: str | None = None


def _init_password_store() -> None:
    global _ph_argon
    plain = os.environ.get("DASHBOARD_PASSWORD")
    env_hash = os.environ.get("DASHBOARD_PASSWORD_HASH")
    if env_hash and env_hash.strip():
        _ph_argon = env_hash.strip()
    elif plain:
        _ph_argon = _password_hasher.hash(plain)
    else:
        _ph_argon = None


_init_password_store()

DOWNLOAD_DIR = Path(os.environ.get("DOWNLOAD_DIR", Path.home() / "torrents")).expanduser().resolve()

ZIP_STORAGE_DIR = Path(
    os.environ.get("ZIP_STORAGE_DIR", str(DOWNLOAD_DIR.parent / ".weedr-zip-store"))
).expanduser().resolve()

ZIP_MAX_CONCURRENT = max(1, int(os.environ.get("ZIP_MAX_CONCURRENT", "2")))
_zip_worker_sem = threading.BoundedSemaphore(ZIP_MAX_CONCURRENT)

_file_download_lock = threading.Lock()
_active_http_downloads: dict[str, dict[str, Any]] = {}

_zip_store: ZipJobsStore | None = None

_torrent_status_prev: dict[str, str] = {}
_torrent_status_lock = threading.Lock()

_LOG = logging.getLogger("torrent_server")


def summarize_http_downloads(flat: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group parallel Range connections (IDM/FDM) by IP + path."""
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for x in flat:
        key = (str(x.get("ip") or ""), str(x.get("path") or ""))
        if key not in groups:
            groups[key] = {
                "ip": x["ip"],
                "path": x["path"],
                "filename": x.get("filename") or "",
                "connections": 0,
                "range_connections": 0,
                "since": x.get("since") or "",
            }
        g = groups[key]
        g["connections"] += 1
        if x.get("range_request"):
            g["range_connections"] += 1
    out = sorted(groups.values(), key=lambda z: z["connections"], reverse=True)
    return out


def get_client_ip() -> str:
    """
    Best-effort real client IP behind Cloudflare or reverse proxies.

    Cloudflare sets CF-Connecting-IP to the visitor address. Without reading it,
    request.remote_addr is often 127.0.0.1 (tunnel to nginx/gunicorn).

    Order: CF-Connecting-IP → True-Client-IP → X-Forwarded-For (if trusted) → remote_addr.

    Restrict origin access to Cloudflare (or your proxy) only; otherwise CF-* headers can be spoofed.
    """
    h = (request.headers.get("CF-Connecting-IP") or "").strip()
    if h:
        return h.split(",")[0].strip()

    h = (request.headers.get("True-Client-IP") or "").strip()
    if h:
        return h.split(",")[0].strip()

    if os.environ.get("TRUST_X_FORWARDED_FOR", "").lower() in ("1", "true", "yes"):
        xff = (request.headers.get("X-Forwarded-For") or "").strip()
        if xff:
            return xff.split(",")[0].strip()

    return (request.remote_addr or "").strip() or "unknown"


def _human_bytes(n: int) -> str:
    n = max(0, int(n))
    for suf, div in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= div:
            return f"{n / div:.2f} {suf}"
    return f"{n} B"


_allowed_cidr_cache: list[Any] | None = None


def _allowed_cidr_networks() -> list[Any]:
    global _allowed_cidr_cache
    if _allowed_cidr_cache is not None:
        return _allowed_cidr_cache
    raw = os.environ.get("DASHBOARD_ALLOWED_CIDRS", "").strip()
    if not raw:
        _allowed_cidr_cache = []
        return _allowed_cidr_cache
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    _allowed_cidr_cache = nets
    return _allowed_cidr_cache


def client_ip_allowed(ip: str) -> bool:
    nets = _allowed_cidr_networks()
    if not nets:
        return True
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return any(addr in n for n in nets)


def _audit(kind: str, **extra: Any) -> None:
    path = (os.environ.get("AUDIT_LOG_PATH") or "").strip()
    if not path:
        return
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(
            {"ts": datetime.now(timezone.utc).isoformat(), "kind": kind, **extra},
            default=str,
        )
        with p.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def _notify_webhook(event: str, payload: dict[str, Any]) -> None:
    url = (os.environ.get("NOTIFY_WEBHOOK_URL") or "").strip()
    if not url:
        return
    body = json.dumps({"event": event, **payload}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=12)
    except urllib.error.URLError:
        pass


def _verify_files_download_token(rel_path: str, token: str) -> bool:
    secret = (os.environ.get("FILES_DOWNLOAD_TOKEN_SECRET") or "").strip()
    if not secret:
        return False
    ser = URLSafeTimedSerializer(secret, salt="weedr-files-v1")
    try:
        max_age = int(os.environ.get("FILES_DOWNLOAD_TOKEN_MAX_AGE", str(7 * 86400)))
        data = ser.loads(token, max_age=max_age)
        return str(data.get("path") or "") == rel_path
    except (BadSignature, SignatureExpired):
        return False


def _verify_zip_download_token(job_id: str, token: str) -> bool:
    secret = (os.environ.get("FILES_DOWNLOAD_TOKEN_SECRET") or "").strip()
    if not secret:
        return False
    ser = URLSafeTimedSerializer(secret, salt="weedr-zip-v1")
    try:
        max_age = int(os.environ.get("FILES_DOWNLOAD_TOKEN_MAX_AGE", str(7 * 86400)))
        data = ser.loads(token, max_age=max_age)
        return str(data.get("job_id") or "") == job_id
    except (BadSignature, SignatureExpired):
        return False


def _files_anonymous_downloads_ok() -> bool:
    return os.environ.get("FILES_DOWNLOAD_ANONYMOUS", "").lower() in ("1", "true", "yes")


def _mint_zip_download_token(job_id: str) -> str | None:
    secret = (os.environ.get("FILES_DOWNLOAD_TOKEN_SECRET") or "").strip()
    if not secret:
        return None
    ser = URLSafeTimedSerializer(secret, salt="weedr-zip-v1")
    return ser.dumps({"job_id": job_id})


def _http_download_validators(full: Path) -> tuple[str, datetime]:
    """
    Validators for Range / resume on /files/… .

    Werkzeug's default ETag embeds mtime and size. While a torrent is still
    writing, those change between requests, so If-Range from an earlier chunk
    no longer matches and the server falls back to a full 200 response (broken
    resume in IDM/browsers). Use device + inode (stable for the same on-disk
    file) and a fixed Last-Modified anchor so If-Range stays valid until the
    path points at a different file (new inode).
    """
    st = full.stat()
    etag = f"{st.st_dev:x}-{st.st_ino:x}"
    lm = datetime(1994, 11, 6, tzinfo=timezone.utc)
    return etag, lm


def _zip_download_validators(full: Path) -> tuple[str, datetime]:
    """Finished archives: stable ETag + real Last-Modified (IDM-friendly)."""
    st = full.stat()
    etag = f"{st.st_size:x}-{st.st_ino:x}"
    lm = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).replace(microsecond=0)
    return etag, lm


def _disk_reserve(u: Any) -> int:
    """Bytes to treat as reserved (excluded from free_effective). Fixed floor + optional % of volume."""
    fixed = int(os.environ.get("DISK_RESERVE_BYTES", str(512 * 1024 * 1024)))
    pct = float(os.environ.get("DISK_RESERVE_PERCENT", "1.0"))
    return max(fixed, int(u.total * pct / 100.0))


def download_folder_usage_bytes(path: Path) -> int:
    total = 0
    if not path.is_dir():
        return 0
    try:
        for p in path.rglob("*"):
            try:
                if p.is_file() and not p.is_symlink():
                    total += p.stat().st_size
            except OSError:
                continue
    except OSError:
        pass
    return total


def _zip_blob_path(job_id: str) -> Path:
    return ZIP_STORAGE_DIR / f"{job_id}.zip"


def _zip_meta_path(job_id: str) -> Path:
    return ZIP_STORAGE_DIR / f"{job_id}.json"


def _delete_zip_artifacts(job_id: str) -> None:
    _zip_blob_path(job_id).unlink(missing_ok=True)
    _zip_meta_path(job_id).unlink(missing_ok=True)


def _read_zip_meta(job_id: str) -> dict[str, Any]:
    p = _zip_meta_path(job_id)
    if not p.is_file():
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _collect_zip_entries(folder: Path) -> tuple[list[tuple[Path, str]], int]:
    """Regular files under folder (no symlinks); returns (path, arcname) list and total raw bytes."""
    entries: list[tuple[Path, str]] = []
    total = 0
    try:
        for path in sorted(folder.rglob("*"), key=lambda p: str(p).lower()):
            if path.is_symlink():
                continue
            if not path.is_file():
                continue
            try:
                arcname = path.relative_to(folder).as_posix()
                sz = path.stat().st_size
            except (ValueError, OSError):
                continue
            entries.append((path, arcname))
            total += sz
    except OSError:
        pass
    return entries, total


def _run_zip_job_worker(job_id: str, rel_path: str, full: Path, download_name: str) -> None:
    global _zip_store
    store = _zip_store
    if store is None:
        return
    zip_path = _zip_blob_path(job_id)
    try:
        if store.get_job(job_id) is None:
            return
        entries, total_raw = _collect_zip_entries(full)
        store.update_totals(job_id, total_raw, 0, 0.0)

        if store.cancel_requested(job_id):
            zip_path.unlink(missing_ok=True)
            store.mark_cancelled(job_id)
            return

        if not entries:
            with zipfile.ZipFile(
                zip_path,
                "w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=6,
            ) as zf:
                dn = (full.name or "folder").strip("/") or "folder"
                zi = zipfile.ZipInfo(dn + "/")
                zi.external_attr = 0o40755 << 16
                zf.writestr(zi, b"")
        else:
            processed = 0
            with zipfile.ZipFile(
                zip_path,
                "w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=6,
            ) as zf:
                for abs_path, arcname in entries:
                    if store.cancel_requested(job_id):
                        zip_path.unlink(missing_ok=True)
                        store.mark_cancelled(job_id)
                        return
                    if store.get_job(job_id) is None:
                        zip_path.unlink(missing_ok=True)
                        return
                    zf.write(abs_path, arcname=arcname)
                    try:
                        processed += abs_path.stat().st_size
                    except OSError:
                        pass
                    pct = (processed / total_raw * 100.0) if total_raw > 0 else 100.0
                    store.update_progress(job_id, processed, min(99.99, pct))

        if store.cancel_requested(job_id):
            zip_path.unlink(missing_ok=True)
            store.mark_cancelled(job_id)
            return

        finished = datetime.now(timezone.utc).isoformat()
        meta = {
            "download_name": download_name,
            "rel_path": rel_path,
            "finished": finished,
        }
        _zip_meta_path(job_id).write_text(json.dumps(meta), encoding="utf-8")

        pb = total_raw if entries else 0
        store.mark_done(job_id, total_raw, pb, finished)
        _notify_webhook(
            "zip_done", {"job_id": job_id, "rel_path": rel_path, "download_name": download_name}
        )
    except Exception as e:
        _delete_zip_artifacts(job_id)
        store.mark_error(job_id, str(e))
        _notify_webhook("zip_error", {"job_id": job_id, "rel_path": rel_path, "error": str(e)})


def _zip_thread_entry(job_id: str, rel_path: str, full: Path, download_name: str) -> None:
    global _zip_store
    store = _zip_store
    if store is None:
        return
    with _zip_worker_sem:
        if store.get_job(job_id) is None:
            return
        store.set_running(job_id)
        if store.get_job(job_id) is None:
            return
        _run_zip_job_worker(job_id, rel_path, full, download_name)


def _apply_zip_retention() -> None:
    global _zip_store
    store = _zip_store
    if store is None:
        return
    max_days = float(os.environ.get("ZIP_MAX_AGE_DAYS", "0") or "0")
    max_total = int(os.environ.get("ZIP_MAX_TOTAL_BYTES", "0") or "0")
    now_ts = time.time()
    if max_days > 0:
        for row in store.list_all_jobs():
            if row.get("status") != "done":
                continue
            jid = row["job_id"]
            zp = _zip_blob_path(jid)
            if not zp.is_file():
                continue
            try:
                if (now_ts - zp.stat().st_mtime) / 86400.0 > max_days:
                    store.delete_job_row(jid)
                    _delete_zip_artifacts(jid)
            except OSError:
                continue
    if max_total > 0:
        done_rows = [r for r in store.list_all_jobs() if r.get("status") == "done"]
        items: list[tuple[float, str, int]] = []
        for r in done_rows:
            jid = r["job_id"]
            zp = _zip_blob_path(jid)
            if zp.is_file():
                try:
                    st = zp.stat()
                    items.append((st.st_mtime, jid, st.st_size))
                except OSError:
                    continue
        items.sort(key=lambda x: x[0])
        total_sz = sum(x[2] for x in items)
        while total_sz > max_total and items:
            _, jid, sz = items.pop(0)
            total_sz -= sz
            store.delete_job_row(jid)
            _delete_zip_artifacts(jid)


def _torrent_fire_notifications(data: dict[str, list[dict[str, Any]]]) -> None:
    """Detect transitions into terminal torrent states and emit webhooks / audit."""
    global _torrent_status_prev
    terminal = frozenset({"complete", "error"})
    flat: list[dict[str, Any]] = []
    for key in ("active", "waiting", "stopped"):
        flat.extend(data.get(key) or [])
    new_prev: dict[str, str] = {}
    for t in flat:
        gid = str(t.get("gid") or "")
        if not gid:
            continue
        st = str(t.get("status") or "")
        old = _torrent_status_prev.get(gid)
        if old is not None and old not in terminal and st in terminal:
            if st == "complete":
                _notify_webhook("torrent_complete", {"gid": gid, "name": t.get("name")})
                _audit("torrent_complete", gid=gid, name=t.get("name"))
            elif st == "error":
                err = t.get("error_message") or t.get("error_code")
                _notify_webhook(
                    "torrent_error",
                    {"gid": gid, "name": t.get("name"), "error": err},
                )
                _audit("torrent_error", gid=gid, error=err)
        new_prev[gid] = st
    with _torrent_status_lock:
        _torrent_status_prev.clear()
        _torrent_status_prev.update(new_prev)


def create_app() -> Flask:
    app = Flask(__name__)

    if os.environ.get("FLASK_DEBUG") == "1":
        app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(64)
    else:
        sk = os.environ.get("SECRET_KEY")
        if not sk:
            raise RuntimeError(
                "SECRET_KEY is required when FLASK_DEBUG is not 1. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(48))\""
            )
        app.secret_key = sk

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.environ.get("SESSION_HOURS", "10"))),
        WTF_CSRF_TIME_LIMIT=None,
        WTF_CSRF_SSL_STRICT=bool(os.environ.get("SESSION_COOKIE_SECURE")),
    )
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "").lower() in (
        "1",
        "true",
        "yes",
    )

    CSRFProtect(app)

    limiter = Limiter(
        key_func=get_client_ip,
        app=app,
        default_limits=[],
        storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
        headers_enabled=True,
    )

    if not logging.root.handlers:
        _lvl_name = os.environ.get("LOG_LEVEL", "INFO").upper()
        _lvl = getattr(logging, _lvl_name, logging.INFO)
        logging.basicConfig(
            level=_lvl,
            format=os.environ.get("LOG_FORMAT", "%(asctime)s %(levelname)s %(message)s"),
        )

    global _zip_store
    try:
        ZIP_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as _zip_mk_err:
        app.logger.warning("ZIP_STORAGE_DIR mkdir: %s", _zip_mk_err)
    _zip_store = ZipJobsStore(Path(os.environ.get("ZIP_JOB_DB", str(ZIP_STORAGE_DIR / "jobs.sqlite"))))

    def verify_password(pw: str) -> bool:
        if not _ph_argon:
            app.logger.error("Set DASHBOARD_PASSWORD or DASHBOARD_PASSWORD_HASH")
            return False
        if _ph_argon.startswith("$argon2"):
            try:
                _password_hasher.verify(_ph_argon, pw)
                if _password_hasher.check_needs_rehash(_ph_argon):
                    app.logger.warning("Password hash should be rehashed (upgrade params)")
                return True
            except VerifyMismatchError:
                return False
        return check_password_hash(_ph_argon, pw)

    def require_auth() -> bool:
        return session.get("auth") is True

    def ensure_qbittorrent():
        svc = get_qbittorrent_service(DOWNLOAD_DIR)
        svc.ensure_daemon()
        return svc

    @app.after_request
    def _security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return resp

    _log_http_json = os.environ.get("LOG_JSON", "").lower() in ("1", "true", "yes")

    @app.after_request
    def _access_log(resp):
        if request.endpoint == "static":
            return resp
        ip = get_client_ip()
        if _log_http_json:
            _LOG.info(
                json.dumps(
                    {
                        "event": "http_request",
                        "path": request.path,
                        "endpoint": request.endpoint,
                        "method": request.method,
                        "ip": ip,
                        "status": resp.status_code,
                    },
                    default=str,
                )
            )
        else:
            _LOG.info(
                "request path=%s endpoint=%s method=%s ip=%s status=%s",
                request.path,
                request.endpoint,
                request.method,
                ip,
                resp.status_code,
            )
        return resp

    @app.before_request
    def _require_config() -> None:
        if request.endpoint in ("static", "health", "login") or request.endpoint is None:
            return
        if not _ph_argon:
            if request.endpoint != "health":
                abort(
                    503,
                    "Misconfigured: set DASHBOARD_PASSWORD or DASHBOARD_PASSWORD_HASH",
                )

    @app.before_request
    def _dashboard_ip_allowlist() -> None:
        if request.endpoint in ("static", "health", "login") or request.endpoint is None:
            return
        if (
            request.endpoint == "download_file"
            and request.args.get("token")
            and (os.environ.get("FILES_DOWNLOAD_TOKEN_SECRET") or "").strip()
        ):
            return
        if not client_ip_allowed(get_client_ip()):
            abort(403)

    @app.route("/health")
    def health():
        deep = request.args.get("deep") in ("1", "true", "yes") or os.environ.get(
            "HEALTH_DEEP", ""
        ).lower() in ("1", "true", "yes")
        if not deep:
            return {"ok": True}
        checks: dict[str, str] = {}
        ok = True
        try:
            DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
            probe = DOWNLOAD_DIR / ".health_probe"
            probe.write_bytes(b"ok")
            probe.unlink(missing_ok=True)
            checks["download_dir"] = "ok"
        except OSError as e:
            checks["download_dir"] = str(e)
            ok = False
        try:
            ZIP_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
            checks["zip_storage_dir"] = "ok"
        except OSError as e:
            checks["zip_storage_dir"] = str(e)
            ok = False
        try:
            ensure_qbittorrent().app_version()
            checks["qbittorrent"] = "ok"
        except Exception as e:
            checks["qbittorrent"] = str(e)
            ok = False
        return {"ok": ok, "checks": checks}

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("12 per minute", methods=["POST"], error_message="Too many login attempts.")
    def login():
        if require_auth():
            return redirect(url_for("overview"))
        error = None
        if request.method == "POST":
            pw = request.form.get("password", "")
            if verify_password(pw):
                session.clear()
                session["auth"] = True
                session.permanent = True
                session["_fresh"] = secrets.token_hex(16)
                _audit("login_ok", ip=get_client_ip())
                return redirect(url_for("overview"))
            _audit("login_fail", ip=get_client_ip())
            error = "Invalid credentials."
        return render_template("login.html", error=error)

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    def overview():
        if not require_auth():
            return redirect(url_for("login"))
        return render_template(
            "overview.html",
            download_dir=str(DOWNLOAD_DIR),
            nav="overview",
        )

    @app.route("/torrents")
    def torrents_page():
        if not require_auth():
            return redirect(url_for("login"))
        return render_template(
            "torrents.html",
            download_dir=str(DOWNLOAD_DIR),
            nav="torrents",
        )

    @app.route("/files")
    def files_page():
        if not require_auth():
            return redirect(url_for("login"))
        rel = request.args.get("path", "").strip().strip("/")
        if rel and ".." in rel.split("/"):
            abort(400)
        entries = _list_files(DOWNLOAD_DIR, safe_under_root, rel)
        parent_rel = ""
        if rel:
            parent_rel = str(Path(rel).parent).replace("\\", "/")
            if parent_rel == ".":
                parent_rel = ""
        return render_template(
            "files.html",
            download_dir=str(DOWNLOAD_DIR),
            current_path=rel,
            parent_path=parent_rel,
            entries=entries,
            nav="files",
        )

    @app.route("/activity")
    def activity_page():
        if not require_auth():
            return redirect(url_for("login"))
        return render_template(
            "activity.html",
            download_dir=str(DOWNLOAD_DIR),
            nav="activity",
        )

    @app.route("/zips")
    def zips_page():
        if not require_auth():
            return redirect(url_for("login"))
        return render_template(
            "zips.html",
            download_dir=str(DOWNLOAD_DIR),
            zip_storage_dir=str(ZIP_STORAGE_DIR),
            nav="zips",
        )

    def _list_files(root: Path, safe_fn, rel: str) -> list[dict]:
        base = root
        if rel:
            sub = safe_fn(root, (root / rel).resolve())
            if sub is None or not sub.is_dir():
                return []
            base = sub
        out: list[dict] = []
        try:
            for p in sorted(base.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
                rel_path = str(p.relative_to(root)).replace("\\", "/")
                try:
                    stat = p.stat()
                    size = stat.st_size if p.is_file() else None
                    mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).strftime(
                        "%Y-%m-%d %H:%M UTC"
                    )
                except OSError:
                    size, mtime = None, ""
                row: dict[str, Any] = {
                        "name": p.name,
                        "rel_path": rel_path,
                        "is_dir": p.is_dir(),
                        "size": size,
                        "mtime": mtime,
                    }
                if not p.is_dir():
                    fsecret = (os.environ.get("FILES_DOWNLOAD_TOKEN_SECRET") or "").strip()
                    if fsecret:
                        ser = URLSafeTimedSerializer(fsecret, salt="weedr-files-v1")
                        row["download_url"] = url_for(
                            "download_file", rel_path=rel_path, token=ser.dumps({"path": rel_path})
                        )
                out.append(row)
        except OSError:
            pass
        return out

    def zip_download_public_url(job_id: str) -> str:
        base = url_for("api_fs_zip_download", job_id=job_id)
        tok = _mint_zip_download_token(job_id)
        if tok:
            return base + "?" + urlencode({"token": tok})
        return base

    def _auth_json():
        if not require_auth():
            abort(401)

    def _torrent_file_max_bytes() -> int:
        raw = (os.environ.get("TORRENT_FILE_MAX_BYTES") or "").strip()
        if raw.isdigit():
            return max(4096, min(int(raw), 256 * 1024 * 1024))
        return 32 * 1024 * 1024

    def _after_qbittorrent_add(svc, ih: str, waited: bool) -> None:
        if waited:
            svc.add_extra_trackers(ih)
        else:
            try:
                svc.add_extra_trackers(ih)
            except QBittorrentError:
                pass
        try:
            svc.apply_no_seeding_share_limits(ih)
        except QBittorrentError:
            if waited:
                raise

    def magnet_add_handler(magnet: str, parent_rel: str = "") -> tuple[dict[str, Any], int]:
        """Parse and queue a magnet in DOWNLOAD_DIR (optional parent subfolder). Used by UI and RSS."""
        if not magnet.lower().startswith("magnet:"):
            return {"error": "Invalid magnet URI"}, 400
        try:
            parsed = parse_magnet(magnet)
        except ValueError as e:
            return {"error": str(e)}, 400
        if not parsed.get("btih"):
            return {"error": "Could not parse info-hash (xt=urn:btih:…) from magnet"}, 400

        parent_rel = str(parent_rel).strip().strip("/")

        base = DOWNLOAD_DIR
        if parent_rel:
            if ".." in parent_rel.split("/"):
                return {"error": "Invalid parent path"}, 400
            p = (DOWNLOAD_DIR / parent_rel).resolve()
            parent_safe = safe_under_root(DOWNLOAD_DIR, p)
            if parent_safe is None:
                return {"error": "Invalid parent path"}, 400
            base = parent_safe
            base.mkdir(parents=True, exist_ok=True)

        folder_label = auto_subfolder_name(parsed.get("dn"), str(parsed["btih"]))
        final_dir = pick_unique_dir(base, folder_label)

        try:
            ih = btih_info_hash_v1_hex(str(parsed["btih"]))
        except ValueError as e:
            return {"error": str(e)}, 400

        dl_bps, ul_bps = throughput_limits_bps()
        try:
            svc = ensure_qbittorrent()
            svc.add_magnet(magnet, final_dir, dl_limit_bps=dl_bps, up_limit_bps=ul_bps)
            waited = svc.wait_for_torrent(ih, timeout=90.0)
            _after_qbittorrent_add(svc, ih, waited)
        except QBittorrentError as e:
            return {"error": str(e)}, 503

        rel_dir = str(final_dir.relative_to(DOWNLOAD_DIR)).replace("\\", "/")
        return {"ok": True, "gid": ih, "save_folder": rel_dir}, 200

    def torrent_file_add_handler(
        file_bytes: bytes, filename: str, parent_rel: str = ""
    ) -> tuple[dict[str, Any], int]:
        """Parse .torrent (v1 metainfo), pick save folder, add via qBittorrent multipart API."""
        max_b = _torrent_file_max_bytes()
        if len(file_bytes) > max_b:
            return {"error": f"Torrent file too large (max {max_b} bytes)"}, 400
        try:
            meta = parse_torrent_metainfo(file_bytes)
        except TorrentFileError as e:
            return {"error": str(e)}, 400
        ih = meta["info_hash_hex"]
        display = (meta.get("display_name") or "").strip() or "torrent"
        dn = display if display != "torrent" else None

        parent_rel = str(parent_rel).strip().strip("/")
        base = DOWNLOAD_DIR
        if parent_rel:
            if ".." in parent_rel.split("/"):
                return {"error": "Invalid parent path"}, 400
            p = (DOWNLOAD_DIR / parent_rel).resolve()
            parent_safe = safe_under_root(DOWNLOAD_DIR, p)
            if parent_safe is None:
                return {"error": "Invalid parent path"}, 400
            base = parent_safe
            base.mkdir(parents=True, exist_ok=True)

        folder_label = auto_subfolder_name(dn, ih)
        final_dir = pick_unique_dir(base, folder_label)

        safe_fn = secure_filename(filename or "") or "upload.torrent"
        if not safe_fn.lower().endswith(".torrent"):
            safe_fn = f"{safe_fn}.torrent"

        dl_bps, ul_bps = throughput_limits_bps()
        try:
            svc = ensure_qbittorrent()
            svc.add_torrent_file(file_bytes, safe_fn, final_dir, dl_limit_bps=dl_bps, up_limit_bps=ul_bps)
            waited = svc.wait_for_torrent(ih, timeout=90.0)
            _after_qbittorrent_add(svc, ih, waited)
        except QBittorrentError as e:
            return {"error": str(e)}, 503

        rel_dir = str(final_dir.relative_to(DOWNLOAD_DIR)).replace("\\", "/")
        return {"ok": True, "gid": ih, "save_folder": rel_dir}, 200

    @app.route("/api/torrents", methods=["GET"])
    @limiter.limit("120 per minute")
    def api_torrents_list():
        _auth_json()
        try:
            svc = ensure_qbittorrent()
            data = svc.fetch_all_downloads()
            gs = svc.global_stat()
        except QBittorrentError as e:
            return jsonify({"error": str(e)}), 503
        _torrent_fire_notifications(data)
        return jsonify({"downloads": data, "meta": gs})

    @app.route("/api/torrents/<gid>/detail", methods=["GET"])
    @limiter.limit("120 per minute")
    def api_torrent_detail(gid: str):
        """Per-torrent status + file list with byte progress (master–detail UI)."""
        _auth_json()
        gid = gid.strip()
        if not gid:
            return jsonify({"error": "Invalid gid"}), 400
        try:
            svc = ensure_qbittorrent()
            detail = svc.fetch_download_detail(gid)
        except QBittorrentError as e:
            return jsonify({"error": str(e)}), 503
        if detail is None:
            return jsonify({"error": "Not found"}), 404
        return jsonify(detail)

    @app.route("/api/fs/stats", methods=["GET"])
    @limiter.limit("120 per minute")
    def api_fs_stats():
        _auth_json()
        try:
            du = shutil.disk_usage(DOWNLOAD_DIR)
        except OSError as e:
            return jsonify({"error": str(e)}), 500
        reserve = _disk_reserve(du)
        free_eff = max(0, du.free - reserve)
        folder_used = download_folder_usage_bytes(DOWNLOAD_DIR)
        return jsonify(
            {
                "download_dir": str(DOWNLOAD_DIR),
                "volume": {
                    "total_bytes": du.total,
                    "used_bytes": du.used,
                    "free_bytes": du.free,
                    "total_human": _human_bytes(du.total),
                    "used_human": _human_bytes(du.used),
                    "free_human": _human_bytes(du.free),
                    "reserve_bytes": reserve,
                    "reserve_human": _human_bytes(reserve),
                    "free_effective_bytes": free_eff,
                    "free_effective_human": _human_bytes(free_eff),
                    "used_fraction": round(du.used / du.total, 4) if du.total else 0.0,
                },
                "folder": {
                    "used_bytes": folder_used,
                    "used_human": _human_bytes(folder_used),
                },
            }
        )

    @app.route("/api/activity/http-downloads", methods=["GET"])
    @limiter.limit("120 per minute")
    def api_activity_http_downloads():
        _auth_json()
        with _file_download_lock:
            conns = list(_active_http_downloads.values())
        return jsonify(
            {
                "count": len(conns),
                "connections": conns,
                "by_file": summarize_http_downloads(conns),
            }
        )

    @app.route("/api/torrents/add", methods=["POST"])
    @limiter.limit("60 per minute")
    def api_torrents_add():
        _auth_json()
        body = request.get_json(silent=True) or {}
        parent_rel = (
            body.get("parent")
            or body.get("subdir")
            or request.form.get("parent")
            or request.form.get("subdir")
            or ""
        )
        parent_rel = str(parent_rel).strip().strip("/")
        up = request.files.get("torrent")
        if up is not None and getattr(up, "filename", None):
            raw = up.read()
            payload, code = torrent_file_add_handler(raw, up.filename or "upload.torrent", parent_rel)
            return jsonify(payload), code
        magnet = (request.form.get("magnet") or body.get("magnet") or "").strip()
        payload, code = magnet_add_handler(magnet, parent_rel)
        return jsonify(payload), code

    @app.route("/api/torrents/<gid>/pause", methods=["POST"])
    def api_torrent_pause(gid: str):
        _auth_json()
        try:
            ensure_qbittorrent().pause(gid)
        except QBittorrentError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"ok": True})

    @app.route("/api/torrents/<gid>/resume", methods=["POST"])
    def api_torrent_resume(gid: str):
        _auth_json()
        try:
            ensure_qbittorrent().resume(gid)
        except QBittorrentError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"ok": True})

    @app.route("/api/torrents/<gid>/prioritize", methods=["POST"])
    def api_torrent_prioritize(gid: str):
        _auth_json()
        try:
            ensure_qbittorrent().top_priority(gid)
        except QBittorrentError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"ok": True})

    @app.route("/api/torrents/<gid>/options", methods=["POST"])
    def api_torrent_options(gid: str):
        _auth_json()
        body = request.get_json(silent=True) or {}
        opts = body.get("options")
        if not isinstance(opts, dict) or not opts:
            return jsonify({"error": "Body must be JSON {\"options\": {\"max-download-limit\": \"1M\"}}"}), 400
        allowed = {
            "max-download-limit",
            "max-upload-limit",
            "bt-request-peer-speed-limit",
            "seed-ratio",
            "seed-time",
        }
        filtered = {k: v for k, v in opts.items() if k in allowed}
        if not filtered:
            return jsonify({"error": f"Only these keys allowed: {sorted(allowed)}"}), 400
        try:
            ensure_qbittorrent().set_torrent_options(gid, filtered)
        except QBittorrentError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"ok": True})

    @app.route("/api/torrents/<gid>", methods=["DELETE"])
    def api_torrent_remove(gid: str):
        _auth_json()
        delete_files = request.args.get("delete_files", "0") in ("1", "true", "yes")
        try:
            ensure_qbittorrent().delete(gid, delete_files=delete_files)
        except QBittorrentError as e:
            return jsonify({"error": str(e)}), 400
        _audit("torrent_remove", gid=gid, delete_files=delete_files)
        _notify_webhook("torrent_remove", {"gid": gid, "delete_files": delete_files})
        return jsonify({"ok": True})

    @app.route("/api/torrents/purge-stopped", methods=["POST"])
    def api_purge_stopped():
        _auth_json()
        try:
            ensure_qbittorrent().purge_finished()
        except QBittorrentError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"ok": True})

    @app.route("/api/fs/delete", methods=["POST"])
    @limiter.limit("120 per minute")
    def api_fs_delete():
        _auth_json()
        body = request.get_json(silent=True) or {}
        rel = (body.get("path") or "").strip().strip("/")
        if not rel or ".." in rel.split("/"):
            return jsonify({"error": "Invalid path"}), 400
        full = safe_under_root(DOWNLOAD_DIR, (DOWNLOAD_DIR / rel).resolve())
        if full is None or not full.exists():
            return jsonify({"error": "Not found"}), 404
        try:
            if full.is_dir():
                shutil.rmtree(full)
            else:
                full.unlink()
        except OSError as e:
            return jsonify({"error": str(e)}), 400
        _audit("fs_delete", path=rel)
        return jsonify({"ok": True})

    @app.route("/api/fs/download-token", methods=["POST"])
    @limiter.limit("30 per minute")
    def api_fs_download_token():
        """Mint a time-limited signed URL token for GET /files/… (read-only file access)."""
        _auth_json()
        body = request.get_json(silent=True) or {}
        rel = (body.get("path") or "").strip().strip("/")
        if not rel or ".." in rel.split("/"):
            return jsonify({"error": "Invalid path"}), 400
        secret = (os.environ.get("FILES_DOWNLOAD_TOKEN_SECRET") or "").strip()
        if not secret:
            return jsonify({"error": "Set FILES_DOWNLOAD_TOKEN_SECRET to enable signed URLs."}), 501
        full = safe_under_root(DOWNLOAD_DIR, (DOWNLOAD_DIR / rel).resolve())
        if full is None or not full.is_file():
            return jsonify({"error": "Not found"}), 404
        ser = URLSafeTimedSerializer(secret, salt="weedr-files-v1")
        token = ser.dumps({"path": rel})
        dl_url = url_for("download_file", rel_path=rel, token=token)
        return jsonify({"token": token, "download_url": dl_url})

    @app.route("/api/torrent/global", methods=["GET"])
    @app.route("/api/aria2/global", methods=["GET"])
    @limiter.limit("60 per minute")
    def api_torrent_global():
        _auth_json()
        try:
            svc = ensure_qbittorrent()
            gs = svc.global_stat()
            prefs = qbt_global_options_snapshot(svc)
        except QBittorrentError as e:
            return jsonify({"error": str(e)}), 503
        return jsonify(
            {
                "global_stat": gs,
                "torrent_client": "qBittorrent",
                "torrent_client_version": gs.get("version"),
                "torrent_options": prefs,
                "aria2_version": None,
                "global_option": prefs,
            }
        )

    @app.route("/api/fs/zip/start", methods=["POST"])
    @limiter.limit("12 per minute")
    def api_fs_zip_start():
        """Queue a background zip of a folder; poll /api/fs/zip/status/<job_id> for progress."""
        _auth_json()
        body = request.get_json(silent=True) or {}
        rel = (body.get("path") or "").strip().strip("/")
        if not rel or ".." in rel.split("/"):
            return jsonify({"error": "Invalid path"}), 400
        full = safe_under_root(DOWNLOAD_DIR, (DOWNLOAD_DIR / rel).resolve())
        if full is None or not full.is_dir():
            return jsonify({"error": "Not found"}), 404

        max_raw = int(os.environ.get("ZIP_FOLDER_MAX_BYTES", str(10 * 1024 * 1024 * 1024)))
        total_raw = download_folder_usage_bytes(full)
        if total_raw > max_raw:
            return (
                jsonify(
                    {
                        "error": (
                            f"Folder is too large to zip ({_human_bytes(total_raw)} uncompressed). "
                            f"Limit is {_human_bytes(max_raw)} (ZIP_FOLDER_MAX_BYTES)."
                        )
                    }
                ),
                413,
            )

        try:
            ZIP_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return jsonify({"error": f"Cannot create zip storage: {e}"}), 500

        safe_dn = (full.name or "folder").replace("/", "_").replace("\\", "_") or "folder"
        download_name = safe_dn + ".zip"
        now = datetime.now(timezone.utc).isoformat()

        zs = _zip_store
        assert zs is not None

        aj0 = zs.active_job_for_path(rel)
        if aj0 and aj0.get("status") in ("queued", "running"):
            return jsonify(
                {
                    "job_id": aj0["job_id"],
                    "status": aj0.get("status"),
                    "dedup": True,
                    "message": "A zip for this folder is already in progress.",
                }
            )

        prev_done = zs.latest_done_for_path(rel)
        if prev_done:
            zs.delete_job_row(prev_done["job_id"])
            _delete_zip_artifacts(prev_done["job_id"])

        job_id = secrets.token_hex(12)
        zs.insert_job(
            job_id,
            rel,
            full.name or "folder",
            download_name,
            now,
            status="queued",
        )

        threading.Thread(
            target=_zip_thread_entry,
            args=(job_id, rel, full, download_name),
            daemon=True,
        ).start()

        _notify_webhook("zip_started", {"job_id": job_id, "rel_path": rel})
        _audit("zip_started", job_id=job_id, rel_path=rel)
        return jsonify({"job_id": job_id, "status": "queued"})

    @app.route("/api/fs/zip/status/<job_id>", methods=["GET"])
    @limiter.limit("120 per minute")
    def api_fs_zip_status(job_id: str):
        if not require_auth():
            abort(401)
        job_id = job_id.strip()
        if not job_id or len(job_id) > 48:
            abort(400)
        zs = _zip_store
        assert zs is not None
        j = zs.get_job(job_id)
        if j:
            out = dict(j)
            out["job_id"] = job_id
            out["processed_human"] = _human_bytes(int(out.get("processed_bytes") or 0))
            out["total_human"] = _human_bytes(int(out.get("total_bytes") or 0))
            if out.get("status") == "done":
                out["download_url"] = zip_download_public_url(job_id)
            return jsonify(out)
        if _zip_blob_path(job_id).is_file():
            meta = _read_zip_meta(job_id)
            sz = _zip_blob_path(job_id).stat().st_size
            return jsonify(
                {
                    "job_id": job_id,
                    "status": "done",
                    "progress": 100.0,
                    "download_url": zip_download_public_url(job_id),
                    "rel_path": meta.get("rel_path", ""),
                    "download_name": meta.get("download_name", "download.zip"),
                    "zip_size_bytes": sz,
                    "zip_size_human": _human_bytes(sz),
                }
            )
        abort(404)

    @app.route("/api/fs/zip/by-path", methods=["GET"])
    @limiter.limit("120 per minute")
    def api_fs_zip_by_path():
        """Resume UI after refresh: active job or latest completed zip for a folder."""
        if not require_auth():
            abort(401)
        rel = request.args.get("path", "").strip().strip("/")
        if rel and ".." in rel.split("/"):
            return jsonify({"error": "Invalid path"}), 400
        if not rel:
            return jsonify({"status": "none"})

        zs = _zip_store
        assert zs is not None
        aj = zs.active_job_for_path(rel)
        if aj and aj.get("status") in ("queued", "running"):
            out = dict(aj)
            out["job_id"] = aj["job_id"]
            out["processed_human"] = _human_bytes(int(out.get("processed_bytes") or 0))
            out["total_human"] = _human_bytes(int(out.get("total_bytes") or 0))
            return jsonify(out)

        dj = zs.latest_done_for_path(rel)
        if dj and _zip_blob_path(dj["job_id"]).is_file():
            jid = dj["job_id"]
            meta = _read_zip_meta(jid)
            return jsonify(
                {
                    "status": "done",
                    "job_id": jid,
                    "progress": 100.0,
                    "download_url": zip_download_public_url(jid),
                    "download_name": meta.get("download_name") or "download.zip",
                    "rel_path": rel,
                }
            )

        return jsonify({"status": "none"})

    @app.route("/api/fs/zip/list", methods=["GET"])
    @limiter.limit("60 per minute")
    def api_fs_zip_list():
        """All zip jobs (memory) plus orphan files on disk (e.g. after restart)."""
        _auth_json()
        rows: list[dict[str, Any]] = []

        zs = _zip_store
        assert zs is not None
        _apply_zip_retention()

        snap_rows = zs.list_all_jobs()
        snap_ids = {r["job_id"] for r in snap_rows}

        for j in snap_rows:
            jid = j["job_id"]
            zp = _zip_blob_path(jid)
            row: dict[str, Any] = {
                "job_id": jid,
                "status": j.get("status"),
                "rel_path": j.get("rel_path", ""),
                "folder_name": j.get("folder_name", ""),
                "download_name": j.get("download_name", ""),
                "progress": j.get("progress"),
                "processed_bytes": j.get("processed_bytes"),
                "total_bytes": j.get("total_bytes"),
                "processed_human": _human_bytes(int(j.get("processed_bytes") or 0)),
                "total_human": _human_bytes(int(j.get("total_bytes") or 0)),
                "error": j.get("error"),
                "started": j.get("started"),
                "cancel_requested": bool(int(j.get("cancel_requested") or 0)),
                "orphan": False,
            }
            if j.get("status") == "done" and zp.is_file():
                row["download_url"] = zip_download_public_url(jid)
            elif j.get("status") == "done":
                row["download_url"] = None
            else:
                row["download_url"] = None

            if zp.is_file():
                try:
                    st = zp.stat()
                    row["zip_size_bytes"] = st.st_size
                    row["zip_size_human"] = _human_bytes(st.st_size)
                    row["sort_ts"] = st.st_mtime
                except OSError:
                    row["sort_ts"] = 0
            else:
                row["sort_ts"] = 0
            rows.append(row)

        if ZIP_STORAGE_DIR.is_dir():
            for zp in ZIP_STORAGE_DIR.glob("*.zip"):
                jid = zp.stem
                if jid in snap_ids:
                    continue
                meta = _read_zip_meta(jid)
                try:
                    st = zp.stat()
                    sz = st.st_size
                    ts = st.st_mtime
                except OSError:
                    continue
                rows.append(
                    {
                        "job_id": jid,
                        "status": "stored",
                        "rel_path": meta.get("rel_path", ""),
                        "folder_name": "",
                        "download_name": meta.get("download_name") or f"{jid}.zip",
                        "progress": None,
                        "processed_human": "",
                        "total_human": "",
                        "error": None,
                        "started": None,
                        "finished": meta.get("finished"),
                        "orphan": True,
                        "download_url": zip_download_public_url(jid),
                        "zip_size_bytes": sz,
                        "zip_size_human": _human_bytes(sz),
                        "sort_ts": ts,
                    }
                )

        rows.sort(key=lambda r: float(r.get("sort_ts") or 0), reverse=True)
        for r in rows:
            r.pop("sort_ts", None)
        retention_note = ""
        if float(os.environ.get("ZIP_MAX_AGE_DAYS", "0") or "0") > 0:
            retention_note += f" Max age {os.environ.get('ZIP_MAX_AGE_DAYS')} days."
        if int(os.environ.get("ZIP_MAX_TOTAL_BYTES", "0") or "0") > 0:
            retention_note += " Total size cap active."
        return jsonify(
            {
                "items": rows,
                "zip_storage_dir": str(ZIP_STORAGE_DIR),
                "retention_hint": retention_note.strip(),
            }
        )

    @app.route("/api/fs/zip/delete/<job_id>", methods=["DELETE"])
    @limiter.limit("60 per minute")
    def api_fs_zip_delete(job_id: str):
        """Remove zip artifacts; running jobs get a cancel request."""
        _auth_json()
        job_id = job_id.strip()
        if not job_id or len(job_id) > 48:
            return jsonify({"error": "Invalid job id"}), 400

        zs = _zip_store
        assert zs is not None
        j = zs.get_job(job_id)
        if j is None:
            _delete_zip_artifacts(job_id)
            _audit("zip_delete_orphan", job_id=job_id)
            return jsonify({"ok": True})

        if j.get("status") == "running":
            zs.request_cancel(job_id)
            _audit("zip_cancel_requested", job_id=job_id)
            return jsonify({"ok": True, "status": "cancelling"})

        zs.delete_job_row(job_id)
        _delete_zip_artifacts(job_id)
        _audit("zip_deleted", job_id=job_id)
        _notify_webhook("zip_deleted", {"job_id": job_id})
        return jsonify({"ok": True})

    @app.route("/api/fs/zip/download/<job_id>", methods=["GET", "HEAD"])
    @limiter.limit("120 per minute")
    def api_fs_zip_download(job_id: str):
        """Download a finished zip from persistent ZIP_STORAGE_DIR (not a temp file)."""
        job_id = job_id.strip()
        if not job_id or len(job_id) > 48:
            abort(400)
        tok = request.args.get("token")
        token_ok = bool(tok and _verify_zip_download_token(job_id, tok))
        anon = _files_anonymous_downloads_ok()
        if not token_ok and not require_auth() and not anon:
            abort(401)
        zp = _zip_blob_path(job_id)
        if not zp.is_file():
            abort(404)
        meta = _read_zip_meta(job_id)
        download_name = str(meta.get("download_name") or f"{job_id}.zip")
        etag_val, lm_anchor = _zip_download_validators(zp)

        conn_id: str | None = None
        if request.method == "GET":
            client_ip = get_client_ip()
            range_hdr = request.headers.get("Range") or ""
            ua = (request.headers.get("User-Agent") or "")[:450]
            conn_id = secrets.token_hex(10)
            norm_path = f"_zip/{job_id}.zip"
            entry = {
                "id": conn_id,
                "path": norm_path,
                "filename": download_name,
                "ip": client_ip,
                "user_agent": ua,
                "range_request": bool(range_hdr),
                "range_preview": range_hdr[:100],
                "since": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            }
            with _file_download_lock:
                _active_http_downloads[conn_id] = entry

        resp = range_file_download_response(
            zp,
            download_name=download_name,
            mimetype="application/zip",
            etag=etag_val,
            last_modified=lm_anchor,
            method=request.method,
            range_header=request.headers.get("Range"),
            if_range_header=request.headers.get("If-Range"),
        )

        if conn_id is not None:

            def _release_http_download() -> None:
                with _file_download_lock:
                    _active_http_downloads.pop(conn_id, None)

            resp.call_on_close(_release_http_download)
        return resp

    @app.route("/files/<path:rel_path>", methods=["GET", "HEAD"])
    def download_file(rel_path: str):
        norm_rel = rel_path.replace("\\", "/")
        tok = request.args.get("token")
        token_ok = bool(
            tok
            and _verify_files_download_token(norm_rel, tok)
        )
        anon = _files_anonymous_downloads_ok()
        if not token_ok and not require_auth() and not anon:
            abort(401)
        if ".." in rel_path.split("/"):
            abort(400)
        full = safe_under_root(DOWNLOAD_DIR, (DOWNLOAD_DIR / rel_path).resolve())
        if full is None or not full.is_file():
            abort(404)

        conn_id: str | None = None
        if request.method == "GET":
            client_ip = get_client_ip()
            range_hdr = request.headers.get("Range") or ""
            ua = (request.headers.get("User-Agent") or "")[:450]
            conn_id = secrets.token_hex(10)
            norm_path = rel_path.replace("\\", "/")
            entry = {
                "id": conn_id,
                "path": norm_path,
                "filename": full.name,
                "ip": client_ip,
                "user_agent": ua,
                "range_request": bool(range_hdr),
                "range_preview": range_hdr[:100],
                "since": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            }
            with _file_download_lock:
                _active_http_downloads[conn_id] = entry

        etag_val, lm_anchor = _http_download_validators(full)
        guessed, _ = mimetypes.guess_type(full.name)
        mimetype = guessed or "application/octet-stream"
        resp = range_file_download_response(
            full,
            download_name=full.name,
            mimetype=mimetype,
            etag=etag_val,
            last_modified=lm_anchor,
            method=request.method,
            range_header=request.headers.get("Range"),
            if_range_header=request.headers.get("If-Range"),
        )

        if conn_id is not None:

            def _release_http_download() -> None:
                with _file_download_lock:
                    _active_http_downloads.pop(conn_id, None)

            resp.call_on_close(_release_http_download)
        return resp

    def _rss_worker_loop() -> None:
        import sqlite3

        from rss_grabber import fetch_magnets_from_feed_url

        feed = (os.environ.get("RSS_FEED_URL") or "").strip()
        if not feed:
            app.logger.warning("ENABLE_RSS_GRABS is set but RSS_FEED_URL is empty")
            return
        dbp = Path(os.environ.get("RSS_STATE_DB", str(DOWNLOAD_DIR / ".rss_magnets.sqlite")))
        try:
            dbp.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            app.logger.error("RSS state DB: %s", e)
            return
        interval = max(60, int(os.environ.get("RSS_POLL_SECONDS", "900")))
        max_per = max(1, int(os.environ.get("RSS_MAX_MAGNETS_PER_POLL", "5")))
        parent_rss = (os.environ.get("RSS_PARENT_SUBDIR") or "").strip().strip("/")
        conn = sqlite3.connect(str(dbp))
        conn.execute("CREATE TABLE IF NOT EXISTS seen (magnet TEXT PRIMARY KEY)")
        conn.commit()
        while True:
            try:
                magnets = fetch_magnets_from_feed_url(feed)
                added = 0
                for mag in magnets:
                    if added >= max_per:
                        break
                    try:
                        with conn:
                            conn.execute("INSERT INTO seen (magnet) VALUES (?)", (mag,))
                    except sqlite3.IntegrityError:
                        continue
                    payload, code = magnet_add_handler(mag, parent_rss)
                    if code >= 400:
                        try:
                            with conn:
                                conn.execute("DELETE FROM seen WHERE magnet = ?", (mag,))
                        except sqlite3.Error:
                            pass
                        app.logger.warning("RSS magnet add failed %s: %s", code, payload)
                    else:
                        added += 1
                        _audit("rss_magnet_added", gid=payload.get("gid"))
                        _notify_webhook(
                            "rss_torrent_added",
                            {
                                "gid": payload.get("gid"),
                                "save_folder": payload.get("save_folder"),
                            },
                        )
            except Exception:
                app.logger.exception("RSS poll failed")
            time.sleep(interval)

    if os.environ.get("ENABLE_RSS_GRABS", "").lower() in ("1", "true", "yes"):
        threading.Thread(target=_rss_worker_loop, daemon=True).start()

    return app


app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
