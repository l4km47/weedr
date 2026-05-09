#!/usr/bin/env bash
# Launched by PM2; sources .env then execs gunicorn (same shell limits as build.sh).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ ! -f "$ROOT/.env" ]]; then
  echo "Missing .env — run ./build.sh first." >&2
  exit 1
fi

if [[ ! -x "$ROOT/.venv/bin/gunicorn" ]]; then
  echo "Missing venv/gunicorn — run ./build.sh first." >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ROOT/.env"
set +a

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"

exec "$ROOT/.venv/bin/gunicorn" \
  -w 1 \
  -k gthread \
  --threads 4 \
  -b "${HOST}:${PORT}" \
  --timeout 120 \
  --access-logfile - \
  --error-logfile - \
  app:app
