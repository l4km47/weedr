"""
Password-protected web dashboard for magnet downloads via downloader.sh
and browsing files under DOWNLOAD_DIR.
"""

from __future__ import annotations

import os
import queue
import secrets
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

DOWNLOAD_DIR = Path(os.environ.get("DOWNLOAD_DIR", Path.home() / "torrents")).expanduser().resolve()
DOWNLOADER_SCRIPT = Path(
    os.environ.get("DOWNLOADER_SCRIPT", Path(__file__).resolve().parent / "downloader.sh")
).expanduser().resolve()

_password_plain = os.environ.get("DASHBOARD_PASSWORD")
_password_hash = os.environ.get("DASHBOARD_PASSWORD_HASH")

if _password_hash:
    _stored_pw = _password_hash
elif _password_plain:
    _stored_pw = generate_password_hash(_password_plain)
else:
    _stored_pw = None

_jobs_lock = threading.Lock()
_jobs: dict[str, dict] = {}
_job_queue: queue.Queue[str] = queue.Queue()
_worker_started = False


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _require_auth() -> bool:
    return session.get("authenticated") is True


def _verify_login(password: str) -> bool:
    if not _stored_pw:
        app.logger.error("DASHBOARD_PASSWORD or DASHBOARD_PASSWORD_HASH must be set")
        return False
    return check_password_hash(_stored_pw, password)


def _safe_under_root(root: Path, candidate: Path) -> Path | None:
    try:
        resolved = candidate.resolve()
        root_resolved = root.resolve()
        resolved.relative_to(root_resolved)
        return resolved
    except (OSError, ValueError):
        return None


def _list_tree(rel: str = "") -> list[dict]:
    """Flat list of entries under DOWNLOAD_DIR/rel for browser."""
    base = DOWNLOAD_DIR
    if rel:
        sub = _safe_under_root(base, (base / rel).resolve())
        if sub is None or not sub.is_dir():
            return []
        base = sub
    out: list[dict] = []
    try:
        for p in sorted(base.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            rel_path = str(p.relative_to(DOWNLOAD_DIR)).replace("\\", "/")
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


def _run_downloader_job(job_id: str, magnet: str) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return
        job["status"] = "running"
        job["log_lines"] = []
        job["started_at"] = _utc_now_iso()

    log_lines: list[str] = []

    def append_line(line: str) -> None:
        line = line.rstrip("\n\r")
        log_lines.append(line)
        if len(log_lines) > 500:
            del log_lines[:-500]
        with _jobs_lock:
            j = _jobs.get(job_id)
            if j:
                j["log_lines"] = list(log_lines)

    try:
        if not DOWNLOADER_SCRIPT.is_file():
            raise FileNotFoundError(f"downloader script not found: {DOWNLOADER_SCRIPT}")
        proc = subprocess.Popen(
            ["bash", str(DOWNLOADER_SCRIPT), magnet],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=str(DOWNLOADER_SCRIPT.parent),
            env={**os.environ, "HOME": str(Path.home())},
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            append_line(line)
        code = proc.wait()
        if code != 0:
            append_line(f"--- process exited with code {code} ---")
            with _jobs_lock:
                j = _jobs.get(job_id)
                if j:
                    j["status"] = "error"
                    j["finished_at"] = _utc_now_iso()
            return
        append_line("--- finished ---")
        with _jobs_lock:
            j = _jobs.get(job_id)
            if j:
                j["status"] = "done"
                j["finished_at"] = _utc_now_iso()
    except Exception as e:
        append_line(f"ERROR: {e}")
        with _jobs_lock:
            j = _jobs.get(job_id)
            if j:
                j["status"] = "error"
                j["finished_at"] = _utc_now_iso()


def _queue_worker() -> None:
    while True:
        job_id = _job_queue.get()
        try:
            with _jobs_lock:
                job = _jobs.get(job_id)
                magnet = job["magnet"] if job else None
            if magnet:
                _run_downloader_job(job_id, magnet)
        finally:
            _job_queue.task_done()


def _ensure_worker() -> None:
    global _worker_started
    if _worker_started:
        return
    with _jobs_lock:
        if _worker_started:
            return
        t = threading.Thread(target=_queue_worker, daemon=True)
        t.start()
        _worker_started = True


@app.before_request
def _check_password_configured() -> None:
    if request.endpoint in ("login", "static") or request.endpoint is None:
        return
    if not _stored_pw and request.endpoint != "health":
        return abort(
            503,
            "Server misconfigured: set DASHBOARD_PASSWORD or DASHBOARD_PASSWORD_HASH",
        )


@app.route("/health")
def health():
    return {"ok": True}


@app.route("/login", methods=["GET", "POST"])
def login():
    if _require_auth():
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        pw = request.form.get("password", "")
        if _verify_login(pw):
            session["authenticated"] = True
            session.permanent = True
            return redirect(url_for("dashboard"))
        error = "Invalid password."
    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def dashboard():
    if not _require_auth():
        return redirect(url_for("login"))
    rel = request.args.get("path", "").strip().strip("/")
    if rel and ".." in rel.split("/"):
        abort(400)
    entries = _list_tree(rel)
    parent_rel = ""
    if rel:
        parent_rel = str(Path(rel).parent).replace("\\", "/")
        if parent_rel == ".":
            parent_rel = ""
    with _jobs_lock:
        jobs_snapshot = dict(_jobs)
    jobs_sorted = sorted(
        jobs_snapshot.values(),
        key=lambda j: j.get("created_at", ""),
        reverse=True,
    )
    return render_template(
        "dashboard.html",
        download_dir=str(DOWNLOAD_DIR),
        current_path=rel,
        parent_path=parent_rel,
        entries=entries,
        jobs=jobs_sorted,
    )


@app.route("/api/download", methods=["POST"])
def api_download():
    if not _require_auth():
        abort(401)
    body = request.get_json(silent=True) or {}
    magnet = (request.form.get("magnet") or body.get("magnet") or "").strip()
    if not magnet.startswith("magnet:?xt=urn:btih:"):
        return {"error": "Invalid magnet URL. Must start with magnet:?xt=urn:btih:"}, 400
    _ensure_worker()
    job_id = str(uuid.uuid4())
    created = _utc_now_iso()
    with _jobs_lock:
        _jobs[job_id] = {
            "id": job_id,
            "magnet": magnet,
            "status": "queued",
            "created_at": created,
            "started_at": None,
            "finished_at": None,
            "log_lines": [],
        }
    _job_queue.put(job_id)
    return {"ok": True, "job_id": job_id}


@app.route("/api/jobs")
def api_jobs():
    if not _require_auth():
        abort(401)
    with _jobs_lock:
        jobs_sorted = sorted(
            _jobs.values(),
            key=lambda j: j.get("created_at", ""),
            reverse=True,
        )
    return {"jobs": jobs_sorted}


@app.route("/files/<path:rel_path>")
def download_file(rel_path: str):
    if not _require_auth():
        abort(401)
    if ".." in rel_path.split("/"):
        abort(400)
    full = _safe_under_root(DOWNLOAD_DIR, (DOWNLOAD_DIR / rel_path).resolve())
    if full is None or not full.is_file():
        abort(404)
    directory = full.parent
    fname = full.name
    return send_from_directory(directory, fname, as_attachment=True)


def create_app():
    return app


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
