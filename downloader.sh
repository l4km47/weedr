#!/usr/bin/env bash
# Add a magnet via qBittorrent Web API (same env as the Flask app).
# Usage: ./downloader.sh "magnet:?xt=urn:btih:..."
set -euo pipefail

MAGNET_URL="${1-}"
DOWNLOAD_DIR="${DOWNLOAD_DIR:-$HOME/torrents}"
QBITTORRENT_URL="${QBITTORRENT_URL:-http://127.0.0.1:8080}"
QBITTORRENT_USERNAME="${QBITTORRENT_USERNAME:-admin}"
QBITTORRENT_PASSWORD="${QBITTORRENT_PASSWORD:-}"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

if [[ -z "$MAGNET_URL" ]]; then
  echo "Usage: $0 \"magnet:?xt=urn:btih:...\"" >&2
  exit 1
fi

if [[ ! "$MAGNET_URL" =~ ^magnet: ]]; then
  die "Invalid magnet URL (must start with magnet:)"
fi

if ! command -v curl >/dev/null 2>&1; then
  die "curl is required."
fi

mkdir -p "$DOWNLOAD_DIR"
BASE="${QBITTORRENT_URL%/}"

COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT

if [[ -n "$QBITTORRENT_PASSWORD" ]]; then
  if ! curl -fsS -c "$COOKIE_JAR" -X POST \
    -d "username=${QBITTORRENT_USERNAME}&password=${QBITTORRENT_PASSWORD}" \
    "${BASE}/api/v2/auth/login" | grep -q '^Ok\.$'; then
    die "qBittorrent auth failed (check QBITTORRENT_USERNAME / QBITTORRENT_PASSWORD)."
  fi
fi

curl -fsS -b "$COOKIE_JAR" -X POST \
  --data-urlencode "urls=${MAGNET_URL}" \
  --data-urlencode "savepath=${DOWNLOAD_DIR}" \
  --data-urlencode "paused=false" \
  --data-urlencode "root_folder=false" \
  "${BASE}/api/v2/torrents/add" >/dev/null

echo "Magnet submitted to qBittorrent at ${BASE} (savepath=${DOWNLOAD_DIR})."
