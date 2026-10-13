# Autonomous development and testing readiness

Verified scope: synthetic SQLite development stack after PR30, October 13, 2026.
This is a development baseline, not a production-ready or zero-knowledge vault.
The original capstone main branch and mobile application are outside this change.

## Already available

- Python 3.12 environment with pinned application/test dependencies; tests create
  disposable public fixtures without real vault data or production credentials.
- Hosted CI exercises the Python suite, actual Gunicorn, real Chromium item flows,
  runtime dependency audit, Docker build and non-root container startup.
- Browser checks cover current item sharing/reveal and password-reset session
  invalidation. They do not establish complete browser or security coverage.
- Explicit offline account/item identity migrations reject unsupported synthetic
  SQLite schemas; repeated upgrades must preserve identities.
- Render Docker preparation is present, but no hosted deployment is authorized or
  claimed. Historical figures in `render-testing.md` describe PR20's original
  checkpoint; subsequent PRs remediate dependencies and add authorization/browser
  coverage. Consult exact current CI rather than those historical test counts.

## New recovery gate

Run from a clean Python environment:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements/test.txt
python -m pip check
python -m pytest -q
python scripts/smoke_recovery.py
python scripts/smoke_wsgi.py
```

CI now runs `smoke_recovery.py` as a blocking step. It accepts no arguments,
ignores external database configuration, creates only its own temporary fixtures,
and uses SQLite's backup API twice: source to backup, backup to restored file.
It tests both existing identity upgrades and their repeatability, all fixture rows
(including sharing, audit and revoked-token rows), integrity/foreign-key checks,
correct-key decryption, wrong-key rejection, and current application's readiness
and ORM relationships against the restored database. A post-backup source change
must not appear in the restore. It does not use `create_all()` to repair a restore.
Fixtures and database files are removed on normal completion or exceptions.

This is a CI drill, not an operator backup utility. There is no user-supplied
path, live backup, retention policy, encryption-key backup, cloud disk snapshot,
or restoration into an existing service. It does not yet test every historical
schema, every route after restoration, or concurrent database writers. It uses
server-held Fernet as the current prototype does; it does not change cryptography.

Important: restoring an old database can restore an old password hash and old
revocation state. This drill preserves that state faithfully; it does NOT prove
old sessions stay revoked after rollback. A future live recovery procedure needs
an explicit signing-key/session invalidation policy and secure key handling.

## What still needs decisions or setup

1. Choose an isolated v2 integration/release branch strategy; adopting one stacked
   PR does not automatically adopt the whole draft stack into main. Future merges
   and deployments require the applicable owner's authorization.
2. A saved coding environment would reduce repeated dependency installation and
   provide predictable browser/container tooling. Current cloud shell can run
   Python tests; Docker is unavailable there. Hosted CI supplies the container and
   Chromium gates. No claim that the user's computer is connected is made here.
3. Hosted synthetic testing needs an approved provider/plan and spend, exact
   deployment branch, access boundary, trusted hostname, and owner-entered secrets.
   A personal Render service and skirby.net subdomain are proposals, not configured
   infrastructure. No cost or current provider feature is assumed by this document.
4. Decide disposable versus retained test data. Current hosted preparation creates
   empty tables and no default administrator. An owner-operated offline synthetic bootstrap command is now prepared; see
   `synthetic-administrator-bootstrap.md`. It has not created a real account.
   Approved credential setup, access controls and an obvious synthetic-data notice
   remain launch gates.
5. Set deliberate required CI/review checks and deployment permissions. Automated
   testing does not itself authorize automatic merges or public deployment.
6. Remaining product decisions include manual locks, logout revocation, failed-login
   cooldowns, encryption/recovery architecture and team ownership. Unrelated test,
   documentation and reliability improvements need not wait for all those decisions.

A mature loop is: isolated change, synthetic unit/integration/browser checks,
independent review, explicitly permitted integration, then gated synthetic staging
with smoke checks and rollback/recovery evidence. Real password storage requires a
separate security review; green CI alone is not that review.
