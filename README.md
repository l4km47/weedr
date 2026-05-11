# Torrent server (weedr)

A small **Flask** web dashboard that runs **aria2** with JSON-RPC on the same machine, gives you a password-protected UI for BitTorrent and file management, and exposes JSON APIs for automation. Sessions use secure cookies, **Argon2id** (or Werkzeug-compatible hashes) for the dashboard password, **CSRF** protection on mutating requests, and optional **rate limiting** on login.

Use it responsibly: only download and share content you have the right to distribute.

## What you get

- **Overview** (`/`) — disk usage, quick magnet preview, HTTP download activity summary  
- **Torrents** (`/torrents`) — add magnets or torrent URLs, pause/resume/prioritize/remove, global aria2 stats  
- **Files** (`/files`) — browse under `DOWNLOAD_DIR`, delete paths, optional folder ZIP jobs, signed download tokens when configured  
- **Activity** (`/activity`) — live view of clients hitting `GET /files/…` (useful behind a reverse proxy with real client IPs)  
- **Zips** (`/zips`) — background ZIP creation with SQLite-backed job state (shared across gunicorn workers)  
- **Health** (`/health`) — shallow `{"ok": true}` or deep checks (`?deep=1` or `HEALTH_DEEP=1`) for download dir, zip storage, and aria2 RPC  
- **Optional** — append-only audit log (`AUDIT_LOG_PATH`), webhook notifications (`NOTIFY_WEBHOOK_URL`), IP allowlist (`DASHBOARD_ALLOWED_CIDRS`), experimental RSS auto-grab (`ENABLE_RSS_GRABS`; off by default)

## Requirements

| Component | Notes |
|-----------|--------|
| **Python** | 3.10+ (Dockerfile uses 3.12) |
| **aria2** | `aria2c` on `PATH` or set `ARIA2_BIN` — the app starts a localhost JSON-RPC daemon for downloads |
| **OS** | Linux/macOS for `./build.sh` / `./run.sh` (bash). On Windows, use a venv + gunicorn or Docker |

Python dependencies are listed in [`requirements.txt`](requirements.txt) (Flask, flask-wtf, flask-limiter, argon2-cffi, gunicorn, itsdangerous, pytest).

## Quick start (Linux / macOS, PM2)

The repo includes a scripted path that creates a venv, generates `.env` if missing, and starts **PM2** with gunicorn:

```bash
./build.sh
```

- First run prints a generated **dashboard password** once; save it.  
- Requires **openssl**, **pm2** (`npm install -g pm2`), and **aria2** installed on the host.  
- Default listen address and port come from `.env` (`HOST`, `PORT`; build defaults often `0.0.0.0:8000`).

Logs and restarts:

```bash
pm2 logs torrent-server
pm2 restart torrent-server
```

## Manual setup (any OS with Python)

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
# Edit .env: SECRET_KEY, DASHBOARD_PASSWORD or DASHBOARD_PASSWORD_HASH, DOWNLOAD_DIR, etc.
.venv/bin/gunicorn -b "${HOST:-127.0.0.1}:${PORT:-5000}" -w 2 --timeout 120 app:app
```

For local development only:

```bash
export FLASK_DEBUG=1   # relaxes SECRET_KEY requirement; do not use in production
export SECRET_KEY=dev
export DASHBOARD_PASSWORD=dev
.venv/bin/python app.py
```

## Configuration

Copy [`.env.example`](.env.example) to `.env` and adjust values. Important groups:

- **Auth** — `DASHBOARD_PASSWORD` *or* `DASHBOARD_PASSWORD_HASH` (Argon2id, recommended in production), plus `SECRET_KEY` when `FLASK_DEBUG` is not `1`  
- **Paths** — `DOWNLOAD_DIR` (torrent output root), `ZIP_STORAGE_DIR`, `ARIA2_STATE_DIR`  
- **Sessions** — `SESSION_HOURS`, `SESSION_COOKIE_SECURE=1` when served over HTTPS  
- **Client IP** — `CF-Connecting-IP` / `True-Client-IP` used when present; `TRUST_X_FORWARDED_FOR` only behind a **trusted** reverse proxy  
- **Network guard** — `DASHBOARD_ALLOWED_CIDRS` to restrict dashboard and JSON APIs by IP/CIDR  
- **aria2** — `ARIA2_MAX_CONCURRENT`, `ARIA2_SEED_TIME`, `ARIA2_SEED_RATIO`, optional `ARIA2_BT_TRACKERS`, throughput overrides (`ARIA2_MAX_CONNECTION_PER_SERVER`, …)  
- **ZIP jobs** — `ZIP_MAX_CONCURRENT`, `ZIP_JOB_DB`, optional retention `ZIP_MAX_AGE_DAYS` / `ZIP_MAX_TOTAL_BYTES`  
- **Ops** — `RATELIMIT_STORAGE_URI` (e.g. Redis for multi-host), `AUDIT_LOG_PATH`, `NOTIFY_WEBHOOK_URL`, `FILES_DOWNLOAD_TOKEN_SECRET` for time-limited file URLs  

Full production notes: [`DEPLOYMENT.md`](DEPLOYMENT.md).

## Docker Compose

```bash
cp .env.example .env
# Set secrets and passwords in .env
docker compose up --build
```

Compose maps `${PORT:-5000}` on the host to the app and uses named volumes for downloads, zip cache, and aria2 state (see [`docker-compose.yml`](docker-compose.yml)).

**aria2 in the image:** The provided [`Dockerfile`](Dockerfile) is a minimal Python image and does **not** install `aria2c`. For BitTorrent support in containers you need `aria2` available inside the image (for example add a `RUN apt-get update && apt-get install -y --no-install-recommends aria2 && rm -rf /var/lib/apt/lists/*` layer on Debian-based images) or mount a binary and set `ARIA2_BIN`.

## HTTP API (authenticated unless noted)

All routes below expect a logged-in session cookie except `/health` and `/login`. Mutating requests require CSRF tokens as enforced by Flask-WTF.

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness; optional deep checks |
| GET | `/api/torrents` | List downloads |
| GET | `/api/torrents/<gid>/detail` | Single download detail |
| POST | `/api/torrents/add` | Add magnet / URI |
| POST | `/api/torrents/<gid>/pause` | Pause |
| POST | `/api/torrents/<gid>/resume` | Resume |
| POST | `/api/torrents/<gid>/prioritize` | Prioritize |
| POST | `/api/torrents/<gid>/options` | Update options |
| DELETE | `/api/torrents/<gid>` | Remove download |
| POST | `/api/torrents/purge-stopped` | Remove completed/error entries |
| GET | `/api/aria2/global` | Global aria2 stats |
| GET | `/api/fs/stats` | Filesystem stats under download root |
| POST | `/api/fs/delete` | Delete file or directory under root |
| POST | `/api/fs/download-token` | Issue signed URL for a file |
| GET | `/api/activity/http-downloads` | Active HTTP file downloads |
| POST | `/api/fs/zip/start` | Start ZIP job |
| GET | `/api/fs/zip/status/<job_id>` | Job status |
| GET | `/api/fs/zip/by-path` | Job by path |
| GET | `/api/fs/zip/list` | List jobs |
| DELETE | `/api/fs/zip/delete/<job_id>` | Remove cached zip job |
| GET | `/api/fs/zip/download/<job_id>` | Download completed zip |

Browser UI: `/`, `/torrents`, `/files`, `/activity`, `/zips`. Static files live under `static/`; templates under `templates/`.

## Tests

```bash
.venv/bin/pip install -r requirements.txt
.venv/bin/pytest
```

## Repository layout (high level)

| Path | Role |
|------|------|
| `app.py` | Flask app, routes, auth, zip orchestration, webhooks, RSS worker hook |
| `aria2_service.py` | Start/manage local aria2 RPC, normalize RPC responses |
| `magnet_util.py` | Magnet parsing and safe subfolder naming |
| `pathutil.py` | Path safety helpers under `DOWNLOAD_DIR` |
| `zip_jobs_store.py` | SQLite zip job persistence |
| `rss_grabber.py` | Optional RSS polling helpers |
| `build.sh` / `run.sh` | Venv + PM2 production-style launcher |
| `downloader.sh` | Standalone CLI helper using a user-local aria2 (optional) |

## License and legal use

This software is a general-purpose download manager front end. You are responsible for complying with copyright and your network’s acceptable use policies. The optional RSS auto-grab feature is disabled by default and can pull arbitrary magnet links from a feed — enable it only if you understand the source and the risks described in `DEPLOYMENT.md` and `.env.example`.
