#!/bin/sh
set -eu
# Schema initialization is deliberate and synthetic-only. No users or vault data.
python scripts/init_synthetic_db.py
# Access logs deliberately omit request targets, headers, bodies and client data.
exec gunicorn --bind "${BIND_HOST:-0.0.0.0}:${PORT:-10000}" --workers 1 --threads 1 --timeout 30 --access-logfile - --access-logformat 'request_complete status=%(s)s duration=%(L)s' --error-logfile - app:app
