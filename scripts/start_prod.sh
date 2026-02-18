#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -f ".env" ]]; then
  set -a
  source .env
  set +a
fi

if command -v gunicorn >/dev/null 2>&1; then
  exec gunicorn -c gunicorn.conf.py wsgi:app
fi

echo "[!] gunicorn not found. Falling back to python3 run.py"
exec python3 run.py
