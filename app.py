"""
Torrent dashboard: aria2 RPC (Python-backed), concurrent downloads, live stats,
file management, hardened authentication (Argon2, CSRF, secure cookies, rate limits).
"""

from __future__ import annotations

import os
import secrets
import shutil
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
    send_from_directory,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash

from aria2_service import Aria2RPCError, fetch_all_downloads, get_service, global_stat

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
        key_func=get_remote_address,
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
            return redirect(url_for("dashboard"))
        error = None
        if request.method == "POST":
            pw = request.form.get("password", "")
            if verify_password(pw):
                session.clear()
                session["auth"] = True
                session.permanent = True
                session["_fresh"] = secrets.token_hex(16)
                return redirect(url_for("dashboard"))
            error = "Invalid credentials."
        return render_template("login.html", error=error)

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    def dashboard():
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
            "dashboard.html",
            download_dir=str(DOWNLOAD_DIR),
            current_path=rel,
            parent_path=parent_rel,
            entries=entries,
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

    @app.route("/api/torrents/add", methods=["POST"])
    @limiter.limit("60 per minute")
    def api_torrents_add():
        _auth_json()
        body = request.get_json(silent=True) or {}
        magnet = (request.form.get("magnet") or body.get("magnet") or "").strip()
        if not magnet.startswith("magnet:?xt=urn:btih:"):
            return jsonify({"error": "Invalid magnet (must start with magnet:?xt=urn:btih:)"}), 400
        options: dict[str, Any] = {}
        subdir = (body.get("subdir") or request.form.get("subdir") or "").strip().strip("/")
        if subdir and ".." not in subdir.split("/"):
            target = (DOWNLOAD_DIR / subdir).resolve()
            if safe_under_root(DOWNLOAD_DIR, target):
                target.mkdir(parents=True, exist_ok=True)
                options["dir"] = str(target)
        try:
            svc = ensure_aria2()
            gid = svc.call("aria2.addUri", [[magnet], options])
        except Aria2RPCError as e:
            return jsonify({"error": str(e)}), 503
        return jsonify({"ok": True, "gid": gid})

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
        return send_from_directory(full.parent, full.name, as_attachment=True)

    return app


app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
