# Legacy account identity upgrade

This draft Phase 0 correction closes account impersonation after deletion and
SQLite numeric row-ID reuse. It is tested with disposable synthetic data only;
v1 remains non-production, server-decrypted, and not zero knowledge.

## Authentication contract and compatibility

Each account now has a distinct random UUID4 `auth_identity`, generated on insert,
with a non-null, unique database constraint. This account-incarnation identifier
is independent of its recyclable integer primary key, username and current role.
It is not a password, vault key, bearer credential, or an authorization grant.
Signed cookies and JWTs must contain the matching binding, and each protected
request resolves the current database account with both fields. Deleting an
account and creating another account with the same integer ID does not revive
the old account's cookies or JWTs. Current roles continue to come from the DB.

**This upgrade intentionally signs every existing session out.** Legacy cookies
and JWTs without the binding are rejected; they are never upgraded by numeric ID.
Missing, malformed or mismatched bindings fail closed. Invalid web identity state
is cleared, including on `/login`, so a stale cookie cannot cause a login loop.
A new successful login emits the binding for both transports. Web logout removes
it. UUID collisions are extraordinarily unlikely and the unique constraint rejects
an active-account collision rather than silently identifying another account.

API paths and successful login response fields are unchanged: `user_id` remains
an integer, JWT `sub` remains its string representation, and the additional signed
`auth_identity` claim is mandatory. Clients that treat access tokens as opaque and
log in again on HTTP 401 retain their contract. Clients that mint, persistently
reuse, or reconstruct tokens without the claim are incompatible and must change.
No mobile-client execution or compatibility certification is claimed.

This is an account-incarnation boundary, **not full session revocation**. Account
password reset, manual lock and anonymous failed-login counters still do not revoke
existing sessions; that broader abuse/recovery policy remains undecided. Deletion
is checked at request authorization, not a new serializable transaction guarantee
for concurrent account deletion and vault mutation. Restoring an old DB backup can
restore old identities and sessions when the same signing keys remain; such a
restore needs separately approved session-key rotation/reconciliation. Do not
interpret this fix as compromise recovery, backup security, or v2 key rotation.

## Explicit disposable SQLite migration

New empty schemas include the column through the existing synthetic initializer.
`create_all()` does not upgrade an existing table. `/healthz` returns 503 for an
old table missing the column; do not start serving it with the new code.

The bounded script `scripts/migrate_account_identity.py` supports the known SQLite
user-table baseline only. It does not read `.env`, import application configuration,
create a database at a misspelled path, touch encryption/signing keys, or run on
startup. This script is not an Alembic framework and does not complete P0-038.
MySQL/MSSQL migration and live-vault use are unsupported and untested.

For an explicitly authorized, disposable synthetic upgrade drill:

The migration script is included in the container at
`/app/scripts/migrate_account_identity.py`, but startup never invokes it. An
authorized offline container drill must mount only its disposable DB and keep
all ordinary application instances stopped.

1. Stop all app instances and writers. Confirm the file contains only synthetic
   records; keep an offline copy of that disposable file for rollback testing.
2. Run `python scripts/migrate_account_identity.py /absolute/path/synthetic.db --synthetic-only`.
3. The script explicitly opens one SQLite write transaction, adds the binding,
   assigns a distinct UUID to each existing account, creates a uniqueness index,
   and adds insert/update validity guards before committing. The temporary empty
   column default is rejected by those guards. Existing IDs, hashes, ciphertext,
   sharing, roles and counters are preserved.
4. A failure rolls back schema, backfill and indexes/triggers together. It can be
   retried once the fault is resolved. A repeat on a valid upgraded schema keeps
   every binding unchanged; an incomplete or malformed identity schema is rejected.
5. Start only the new code, verify readiness, and log in again on web and API.
   Do not overlap old and new writers: the old code cannot supply account bindings.

There is no automated down migration. Rolling back to the old code restores the
identity-reuse vulnerability. Any approved synthetic rollback should use its
matching offline fixture and keep it isolated. Do not use a successful upgrade
exercise as permission to deploy, migrate real data, or relax launch gates.

## Verification and limits

Actual-route regressions reproduce the old attack (deleted ID 2 becomes a new
administrator ID 2), then assert stale JWT/cookie denial, valid replacement login,
legacy/malformed binding rejection and current-role demotion. The tests failed
against the prior implementation before the fix. Legacy authorization matrices
use explicit bound fixtures; no automatic test hook inserts missing bindings.

Disposable migration tests preserve baseline records and foreign keys, verify
idempotence and new ORM inserts, inject backfill/index/trigger failures, force a
UUID collision, and prove full schema/data rollback. An isolated shipped-app
process verifies old-schema readiness failure, migration, both legacy transport
rejections and fresh logins. This is bounded regression evidence, not a qualified
independent security audit or proof that every legacy route is safe.
