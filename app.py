"""
Torrent dashboard: aria2 RPC (Python-backed), concurrent downloads, live stats,
file management, hardened authentication (Argon2, CSRF, secure cookies, rate limits).
"""

from __future__ import annotations

import os
import secrets
import shutil
import threading
import time
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
    send_file,
    session,
    url_for,
)
from flask_limiter import Limiter
from werkzeug.security import check_password_hash

from aria2_service import Aria2RPCError, fetch_all_downloads, get_service, global_stat
from magnet_util import auto_subfolder_name, parse_magnet, pick_unique_dir

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

_file_download_lock = threading.Lock()
_active_http_downloads: dict[str, dict[str, Any]] = {}


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


def _disk_reserve(u: object) -> int:
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


def _remove_aria2_download_best_effort(svc: Any, gid: str) -> None:
    try:
        svc.call("aria2.remove", [gid])
    except Aria2RPCError:
        try:
            svc.call("aria2.removeDownloadResult", [gid])
        except Aria2RPCError:
            pass


def wait_for_torrent_total_length(svc: Any, gid: str, timeout: float = 120.0) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            st = svc.call(
                "aria2.tellStatus",
                [gid, ["totalLength", "status", "errorMessage", "errorCode"]],
            )
        except Aria2RPCError:
            time.sleep(0.35)
            continue
        if not isinstance(st, dict):
            time.sleep(0.35)
            continue
        if st.get("status") == "error":
            msg = st.get("errorMessage") or st.get("errorCode") or "unknown error"
            _remove_aria2_download_best_effort(svc, gid)
            raise Aria2RPCError(f"Torrent failed: {msg}")
        tl = int(st.get("totalLength") or 0)
        if tl > 0:
            return tl
        time.sleep(0.35)
    _remove_aria2_download_best_effort(svc, gid)
    raise Aria2RPCError(
        "Timeout waiting for torrent size (metadata). "
        "Try again, or add &xl=BYTES to the magnet if the indexer provides it."
    )


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

    def safe_under_root(root: Path, candidate: Path) -> Path | None:
        try:
            resolved = candidate.resolve()
            root_resolved = root.resolve()
            resolved.relative_to(root_resolved)
            return resolved
        except (OSError, ValueError):
            return None

    def ensure_aria2():
        svc = get_service(DOWNLOAD_DIR)
        svc.ensure_daemon()
        return svc

    @app.after_request
    def _security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
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

    @app.route("/health")
    def health():
        return {"ok": True}

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
                return redirect(url_for("overview"))
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
                out.append(
                    {
                        "name": p.name,
                        "rel_path": rel_path,
                        "is_dir": p.is_dir(),
                        "size": size,
                        "mtime": mtime,
                    }
                )
        except OSError:
            pass
        return out

    def _auth_json():
        if not require_auth():
            abort(401)

    @app.route("/api/torrents", methods=["GET"])
    @limiter.limit("120 per minute")
    def api_torrents_list():
        _auth_json()
        try:
            svc = ensure_aria2()
            data = fetch_all_downloads(svc)
            gs = global_stat(svc)
        except Aria2RPCError as e:
            return jsonify({"error": str(e)}), 503
        return jsonify({"downloads": data, "meta": gs})

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
        magnet = (request.form.get("magnet") or body.get("magnet") or "").strip()
        if not magnet.lower().startswith("magnet:"):
            return jsonify({"error": "Invalid magnet URI"}), 400
        try:
            parsed = parse_magnet(magnet)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        if not parsed.get("btih"):
            return jsonify({"error": "Could not parse info-hash (xt=urn:btih:…) from magnet"}), 400

        parent_rel = (
            body.get("parent")
            or body.get("subdir")
            or request.form.get("parent")
            or request.form.get("subdir")
            or ""
        )
        parent_rel = str(parent_rel).strip().strip("/")

        base = DOWNLOAD_DIR
        if parent_rel:
            if ".." in parent_rel.split("/"):
                return jsonify({"error": "Invalid parent path"}), 400
            p = (DOWNLOAD_DIR / parent_rel).resolve()
            parent_safe = safe_under_root(DOWNLOAD_DIR, p)
            if parent_safe is None:
                return jsonify({"error": "Invalid parent path"}), 400
            base = parent_safe
            base.mkdir(parents=True, exist_ok=True)

        folder_label = auto_subfolder_name(parsed.get("dn"), str(parsed["btih"]))
        final_dir = pick_unique_dir(base, folder_label)

        du = shutil.disk_usage(DOWNLOAD_DIR)
        reserve = _disk_reserve(du)
        free_effective = max(0, du.free - reserve)

        options: dict[str, Any] = {
            "dir": str(final_dir),
            "seed-time": os.environ.get("ARIA2_SEED_TIME", "0"),
            "seed-ratio": os.environ.get("ARIA2_SEED_RATIO", "0"),
        }

        xl_bytes = parsed.get("xl")
        need_metadata = not (isinstance(xl_bytes, int) and xl_bytes > 0)

        if isinstance(xl_bytes, int) and xl_bytes > 0:
            if xl_bytes > free_effective:
                return jsonify(
                    {
                        "error": (
                            f"Not enough free space (after reserve). Need {_human_bytes(xl_bytes)}, "
                            f"effective free {_human_bytes(free_effective)}."
                        ),
                        "need_bytes": xl_bytes,
                        "free_effective_bytes": free_effective,
                    }
                ), 400
        else:
            options["pause"] = "true"

        try:
            svc = ensure_aria2()
            gid = svc.call("aria2.addUri", [[magnet], options])
        except Aria2RPCError as e:
            return jsonify({"error": str(e)}), 503

        if need_metadata:
            try:
                total_len = wait_for_torrent_total_length(svc, gid)
            except Aria2RPCError as e:
                return jsonify({"error": str(e)}), 400
            du2 = shutil.disk_usage(DOWNLOAD_DIR)
            reserve2 = _disk_reserve(du2)
            free2 = max(0, du2.free - reserve2)
            if total_len > free2:
                _remove_aria2_download_best_effort(svc, gid)
                return jsonify(
                    {
                        "error": (
                            f"Not enough free space for this torrent (~{_human_bytes(total_len)}). "
                            f"Effective free {_human_bytes(free2)}."
                        ),
                        "need_bytes": total_len,
                        "free_effective_bytes": free2,
                    }
                ), 400
            try:
                svc.call("aria2.unpause", [gid])
            except Aria2RPCError as e:
                return jsonify({"error": str(e)}), 503

        rel_dir = str(final_dir.relative_to(DOWNLOAD_DIR)).replace("\\", "/")
        return jsonify({"ok": True, "gid": gid, "save_folder": rel_dir})

    @app.route("/api/torrents/<gid>/pause", methods=["POST"])
    def api_torrent_pause(gid: str):
        _auth_json()
        try:
            ensure_aria2().call("aria2.pause", [gid])
        except Aria2RPCError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"ok": True})

    @app.route("/api/torrents/<gid>/resume", methods=["POST"])
    def api_torrent_resume(gid: str):
        _auth_json()
        try:
            ensure_aria2().call("aria2.unpause", [gid])
        except Aria2RPCError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"ok": True})

    @app.route("/api/torrents/<gid>/prioritize", methods=["POST"])
    def api_torrent_prioritize(gid: str):
        _auth_json()
        try:
            ensure_aria2().call("aria2.changePosition", [gid, 0, "POS_SET"])
        except Aria2RPCError as e:
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
            ensure_aria2().call("aria2.changeOption", [gid, filtered])
        except Aria2RPCError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"ok": True})

    @app.route("/api/torrents/<gid>", methods=["DELETE"])
    def api_torrent_remove(gid: str):
        _auth_json()
        delete_files = request.args.get("delete_files", "0") in ("1", "true", "yes")
        svc = ensure_aria2()
        paths_to_delete: list[Path] = []
        if delete_files:
            try:
                raw = svc.call(
                    "aria2.tellStatus",
                    [
                        gid,
                        ["files", "dir", "status"],
                    ],
                )
                if isinstance(raw, dict):
                    d = raw.get("dir") or str(DOWNLOAD_DIR)
                    base = Path(d).resolve()
                    for f in raw.get("files") or []:
                        if not isinstance(f, dict):
                            continue
                        rel_p = f.get("path")
                        if not rel_p:
                            continue
                        full = safe_under_root(DOWNLOAD_DIR, (base / rel_p).resolve())
                        if full:
                            paths_to_delete.append(full)
            except Aria2RPCError:
                pass
        try:
            svc.call("aria2.remove", [gid])
        except Aria2RPCError:
            try:
                svc.call("aria2.removeDownloadResult", [gid])
            except Aria2RPCError as e:
                return jsonify({"error": str(e)}), 400
        if delete_files:
            for p in paths_to_delete:
                try:
                    if p.is_dir():
                        shutil.rmtree(p)
                    elif p.is_file():
                        p.unlink()
                except OSError as e:
                    app.logger.warning("Could not delete %s: %s", p, e)
        return jsonify({"ok": True})

    @app.route("/api/torrents/purge-stopped", methods=["POST"])
    def api_purge_stopped():
        _auth_json()
        try:
            ensure_aria2().call("aria2.purgeDownloadResult")
        except Aria2RPCError as e:
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
        return jsonify({"ok": True})

    @app.route("/files/<path:rel_path>")
    def download_file(rel_path: str):
        if not require_auth():
            abort(401)
        if ".." in rel_path.split("/"):
            abort(400)
        full = safe_under_root(DOWNLOAD_DIR, (DOWNLOAD_DIR / rel_path).resolve())
        if full is None or not full.is_file():
            abort(404)

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

        # conditional=True enables HTTP Range (206) + Accept-Ranges — required for IDM/FDM multi-connection segmented downloads
        resp = send_file(
            full,
            as_attachment=True,
            download_name=full.name,
            conditional=True,
            etag=True,
        )

        def _release_http_download() -> None:
            with _file_download_lock:
                _active_http_downloads.pop(conn_id, None)

        resp.call_on_close(_release_http_download)
        return resp

    return app


app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
