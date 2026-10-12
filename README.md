# CAPSTONE Password Manager: legacy prototype

**Synthetic test data only. This is not production-ready and is not zero knowledge.**
The server holds the vault decryption key and returns plaintext to clients.
Do not store real passwords or import a real vault.

CI and isolated Render test-hosting preparation are documented in
[the test deployment guide](Documentation/render-testing.md). Deployment remains
blocked pending its launch gates. Nothing deploys automatically from this setup.

The isolated [runtime dependency remediation](Documentation/dependency-remediation.md)
documents upgrade compatibility checks and the remaining security gates.

## Web-first development contract

The development version uses [immutable item selection and deliberate per-item
reveal](Documentation/web-first-item-access.md). List/detail pages contain only
metadata. Shared users can reveal; only owners can change or delete items.
The [legacy vault API is retired](Documentation/web-first-api-retirement.md)
with authenticated HTTP 410 responses. Historical mobile builds are intentionally
unsupported by this version; their source and the historical capstone are preserved.
Mobile adaptation follows a future versioned protocol, not a bulk-plaintext fallback.

Existing disposable SQLite fixtures also require the explicit
[item identity upgrade](Documentation/item-identity-upgrade.md). No startup
migration or real-data migration is authorized. This milestone's schema readiness
is SQLite-only; other backend guards require separate review.

## Account identity upgrade

Existing disposable SQLite databases need the explicit
[account identity migration](Documentation/account-identity-upgrade.md) before
starting this version. All existing web sessions and JWTs intentionally sign out;
fresh login is required. New empty synthetic schemas include the binding.

## Password changes and sessions

Successful account password changes now invalidate all existing cookies and JWTs
for that account. Reauthentication is required. See the
[revocation contract and upgrade limits](Documentation/password-session-revocation.md).
This adds no schema migration; pre-upgrade credentials intentionally sign out.
Lock and logout scope remain unchanged.

## Test locally

Python 3.12 and Node 22 are required for the prepared CI path:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements/test.txt
python -m pytest -q
python scripts/smoke_wsgi.py
```

## Configuration

Use `.env.example` as a placeholder-only reference; real keys belong outside
version control. Explicit stable `SECRET_KEY`, `JWT_SECRET_KEY`, and valid
`ENCRYPTION_KEY` values are required. Database credentials have no defaults.
See the deployment guide for the supported modes and legacy database setup.
`python app.py` never enables debug mode. Interactive local use still requires
HTTPS because session cookies are Secure.

## Original project

A Flask/SQLAlchemy password-manager capstone for CIST 1451, with web and REST
interfaces, roles, sharing, audit logging and Fernet-encrypted password fields.
MySQL and SQL Server scripts are historical artifacts, not safe hosting/bootstrap
instructions; they contain known sample credentials. Do not run them in a hosted
instance. The mobile app is separate from this repository.

License: [Apache 2.0](LICENSE). Contact: @slkirby22.
