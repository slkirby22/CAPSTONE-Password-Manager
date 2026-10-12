#!/bin/sh
set -eu
# Schema initialization is deliberate and synthetic-only. No users or vault data.
python scripts/init_synthetic_db.py
exec gunicorn --bind "${BIND_HOST:-0.0.0.0}:${PORT:-10000}" --workers 1 --threads 1 --timeout 30 --access-logfile - --error-logfile - app:app
