# Owner-operated synthetic administrator bootstrap

This command closes the empty-schema setup gap for disposable testing. It does
not authorize account creation, credential entry, hosting, public access or
production use. The owner must explicitly approve the target and personally
enter, confirm and submit the new password through a trusted local terminal.
An assistant may prepare code and run public-fixture tests, not enter deployment
credentials on the owner's behalf.

## Preconditions

- A separately approved, isolated synthetic environment. Never use a real vault
  database or reuse a personal/work password. The synthetic flag declares intent;
  it cannot prove the provenance of an arbitrary database file.
- Current schema already initialized, with ALL application tables empty. No
  legacy seed scripts, sample administrator, account-creation web route or reset
  override. Account/item identity upgrades must already be present.
- Schema validation requires the exact freshly initialized ORM layout (including
  column types/order/defaults, keys and relationships). Historical migrated
  layouts may be rejected even if otherwise compatible; no automatic repair
  or migration is attempted.
- Stop application writers; use a trusted directory owned by the service user.
  Do not expose that directory to other users who could replace database files.
- Use the same Python dependency environment as the application. The container
  packages this script but does not invoke it during startup.

## Manual setup, after separate approval

From the approved service's local terminal, set APP_ENV=synthetic and
SYNTHETIC_DATA_ONLY=true, then run:

```sh
python scripts/bootstrap_synthetic_admin.py /absolute/path/synthetic.db --synthetic-only
```

No `.env`, DATABASE_URL or signing/encryption secrets are read by this command.
It requires an existing regular file and rejects relative/symlink paths. It
prompts for username, password twice (non-echoing terminal), and final literal
confirmation. No password flags, environment-password values, stdin piping or
noninteractive fallback are accepted. Do not record terminal input or include
credentials in screenshots, CI variables, command history or logs.

The existing application password policy and scrypt hashing are reused. The
account gets a fresh incarnation identity and administrator role; no default
username/password exists. A generic audit record is committed in the same
transaction. A failed insert/audit rolls back. Concurrent first-run attempts
serialize using BEGIN IMMEDIATE, then recheck the empty schema under the lock;
only one can succeed. Re-running refuses rather than resetting credentials.

After success, start the approved service and verify ordinary login and current
permission checks using synthetic-only data. Keep public hosting disabled until
the separate access/HTTPS/secret/release review is complete. No authenticated
session or API token is issued by bootstrap.

## Limits

This is SQLite and synthetic-only. It is not a production provisioning system,
account recovery flow, invitation mechanism or general migration framework.
A pre-existing account or any other application data blocks it; investigate
rather than adding a force/reset switch. Recovery, credential rotation and
existing-account administration remain separate operations. Disposable hosting
may erase the database on restart and require owner-operated setup again; a
persistent demo needs a separate storage and recovery decision.

Tests use public synthetic values only: first/repeated setup, invalid inputs,
nonempty/old schema, concurrent attempts, atomic audit failure, safe CLI failures
and rejected noninteractive/argument password input. No real credential was
created or entered while developing this feature.
