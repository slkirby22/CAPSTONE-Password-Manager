# Account create/update audit transactions

This draft follows the synthetic integration candidate (PR 35). It changes only
successful account creation and account/profile/password updates: the account
write and its `USER_CREATE` or `USER_UPDATE` audit event now commit together.

Previously, account changes committed first. The separate best-effort audit
writer swallowed database errors, allowing a success response and a changed
account without the matching audit record. Disposable SQLite fault injection
reproduced this for both operations.

The routes now stage the event in the same SQLAlchemy transaction and return a
generic 500 on a transaction failure after rolling back. Self-update cookie
changes occur only after commit. A committed password change continues to
invalidate password-bound web sessions and JWTs under the existing contract.
An unsuccessful password update leaves the previous password and binding intact.

Tests exercise audit insertion failure, account-write failure, failure after a
flush but before commit, one-commit successful operations, self-renaming,
unchanged-password updates, and self-update session preservation on failure.
All fixtures use the isolated in-memory test database and public synthetic data.

## Limits

- This is not a durable external audit ledger or tamper-proof logging system.
- Lock/unlock, deletion, login events and other legacy best-effort audit callers
  are outside this increment. No lock, cooldown, logout or recovery policy changes.
- A lost response after a successful database commit can still leave a caller
  uncertain; this change does not introduce idempotency or distributed transactions.
- Username uniqueness remains enforced by the database. A concurrent conflict
  rolls back and returns a generic error; no new retry or conflict UX is added.
- No merge, deployment, real account bootstrap or production password use is
  implied by the synthetic tests.
