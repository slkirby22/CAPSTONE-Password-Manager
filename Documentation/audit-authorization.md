# Audit access boundary (P0-010)

Both audit routes require a session whose user still exists and currently has
`admin` in the database. The session's cached role is not an authorization
source. Deleting or demoting a user therefore removes audit access on the next
request.

- `/get_audit_logs`: returns JSON `401` for an absent or unknown session user,
  and JSON `403` for an existing non-administrator. Authorization happens before
  querying audit records or applying request filters.
- `/audit_log_viewer`: preserves the existing redirects to the index for an
  absent/unknown user and to the dashboard for a non-administrator. Authorized
  viewing still records `AUDIT_LOG_VIEW` and renders the past day's records.
- Authorized JSON responses retain the existing array shape and date-filter
  behavior. In particular, a date-only end bound retains its existing midnight
  cutoff; this change does not redefine date handling.

## Regression checks

From the repository root, with its dependencies installed:

```sh
python -m pytest -q tests/test_audit_authorization.py
python -m pytest -q
```

The new tests use an in-memory SQLite database and synthetic users/events. They
exercise missing, deleted, and nonexistent users; employee and manager roles;
forged/stale session roles; demotion between requests; current administrators;
JSON field compatibility; date filters; actual HTML template rendering; and
rejection before reading audit records. They do not contact a live vault.

The audit tests use the same request handlers as the production routes in a
minimal Flask test application. They do not exercise production startup, a live
MySQL/SQL Server connection, or a browser's JavaScript execution.

## Scope and limitations

This is one bounded legacy-v1 authorization correction. It does not make the
application production-ready or zero knowledge. Existing session/authentication,
account-locking, role-management, default-configuration, server-held encryption,
plaintext rendering, dependency, and audit-message rendering concerns require
separate review and fixes. A forged session user identity remains a wider
session-integrity concern; ignoring the session role does not fix that concern.

No schema, cryptographic format, deployment, or repository security settings
change is required. Existing installations gain the authorization check only
after this change is reviewed and deliberately adopted.
