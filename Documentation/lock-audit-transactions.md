# Manual account lock/unlock audit transactions

This bounded follow-on to draft PR 36 makes each successful manual account
lock or unlock and its ACCOUNT_LOCK/ACCOUNT_UNLOCK event commit together.

Previously the account counter committed before the best-effort audit writer.
An audit INSERT failure could leave a successful lock change without its event.
The route now stages the event in the same transaction and rolls both back on
failure, returning a generic 500 without exception details.

Synthetic in-memory SQLite tests cover both directions: audit insertion failure,
account write failure, failure after flush but before commit, one successful
commit/event, repeated-state no-ops, restricted self-actions and missing targets.
Existing role/authorization coverage remains applicable.

## Boundaries

- Existing lock counters, threshold, role permissions, self-action restrictions,
  login cooldown and cookie/JWT lifecycle policy are unchanged.
- Automatic failed-login counters, account deletion and other legacy audit
  callers are outside this increment.
- No external/tamper-proof ledger or distributed transaction is introduced.
  A lost response after commit can still make the outcome uncertain.
- Tests use disposable synthetic fixtures, not a production database or vault.
- This draft does not merge, deploy, create real accounts or alter hosting.
