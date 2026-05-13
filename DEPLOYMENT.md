# Production checklist

Use this when exposing **weedr** beyond localhost.

## TLS and secrets

- Terminate TLS at a reverse proxy (nginx, Caddy, Traefik, Cloudflare) or run behind a tunnel you trust.
- Set a strong `SECRET_KEY` (e.g. `python -c "import secrets; print(secrets.token_hex(48))"`).
- Prefer `DASHBOARD_PASSWORD_HASH` (Argon2) over a plain `DASHBOARD_PASSWORD` in env files.
- Enable `SESSION_COOKIE_SECURE=1` when the browser talks to your proxy over HTTPS.

## Reverse proxy and client IP

- Restrict who can reach your origin (firewall / Cloudflare / VPN).
- If you use `TRUST_X_FORWARDED_FOR=1`, only trust that header from your proxy; otherwise clients can spoof IPs.
- Use `DASHBOARD_ALLOWED_CIDRS` to restrict dashboard routes by IP/CIDR when appropriate.

## Process model

- Run under **gunicorn** (or similar) with multiple workers for availability.
- Zip job state is stored in SQLite (`ZIP_JOB_DB` or default under `ZIP_STORAGE_DIR`). Multiple workers share that DB; avoid mixing old in-memory-only deployments.

## Disk

- Size `DOWNLOAD_DIR` and `ZIP_STORAGE_DIR` volumes; set `ZIP_MAX_AGE_DAYS` / `ZIP_MAX_TOTAL_BYTES` if you need automatic zip cleanup.

## Optional features

- **`FILES_DOWNLOAD_TOKEN_SECRET`**: signed URLs for `GET /files/…?token=…`. Anyone with the URL can download until expiry — treat like a bearer secret.
- **`NOTIFY_WEBHOOK_URL`**: JSON POSTs for torrent/zip events; use HTTPS and authenticate the receiver if possible.
- **`AUDIT_LOG_PATH`**: append-only JSONL; rotate/truncate by log tooling; restrict filesystem permissions.
- **`ENABLE_RSS_GRABS`**: experimental; high abuse/legal risk; keep disabled unless you understand the feed source.

## Docker Compose

1. Copy `.env.example` to `.env` and fill secrets and passwords.
2. `docker compose up --build`
3. Ensure host firewall only exposes the proxy port you intend.

The image runs as a non-root user; mounted volumes must be writable by that UID or use named volumes as in `docker-compose.yml`.

BitTorrent uses **qBittorrent-nox** inside the container. Persist `QBITTORRENT_STATE_DIR` (see `docker-compose.yml`) so resume data survives restarts.

On first successful Web API login, the app applies higher default connection and queue limits via qBittorrent’s `setPreferences` (see `.env.example` for `QBITTORRENT_*` overrides and `QBITTORRENT_SKIP_THROUGHPUT_PREFS`). By default it also enables **share ratio 0** (no post-complete seeding; torrents pause or are removed from the client per `QBITTORRENT_RATIO_LIMIT_ACTION`) and sets the same limits on each added magnet; set `QBITTORRENT_ALLOW_SEEDING=1` to opt out. Real download speed still depends on swarm health, disk, and uplink; on Linux hosts with multi‑gigabit links you may also need larger TCP buffers and a higher `ulimit -n` than stock defaults.
