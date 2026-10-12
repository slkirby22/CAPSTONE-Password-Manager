# Offline synthetic item-identity upgrade

This is a bounded Phase 0 drill for disposable SQLite fixtures only. It is not a
production migration or the general Alembic baseline. Do not run against a real
vault, a live database, or with any application/mixed-version writer running.
The application and container entrypoint never run this upgrade automatically.

## Contract

`password.id`, owner foreign keys and `password_user` remain internal integers.
Each new item receives a server-generated UUID4 `item_id`, represented as exactly
32 lowercase hexadecimal characters (UUID version 4 and RFC variant required).
This value is unique, non-null and immutable for that row's lifetime, including
across label, credential and share changes. The model constructor rejects caller
identity arguments; request handlers must reject caller-supplied identity fields.
The application attribute guard and SQLite immutable trigger reject replacement
of an existing identity. SQLite insert/update format triggers protect both fresh
and upgraded schemas, and fresh schemas also include a CHECK constraint. Raw SQL
inserts must supply a valid unique identity; omission fails closed. The supported
application constructor always generates it.

Numeric primary-key reuse after deletion cannot revive the old item UUID. Random
UUID uniqueness is probabilistic; an active unique index fails closed on a
collision. This is neither a historic tombstone registry nor a defense against
backup rollback. Restoring an old backup can restore its old identities.

## Disposable drill

1. Make a disposable synthetic SQLite fixture and stop all writers.
2. If it predates account identities, first run the separate account-identity
   drill documented in `account-identity-upgrade.md`.
3. Invoke the offline script with its explicit safety acknowledgement:

   ```sh
   python scripts/upgrade_item_identity.py /absolute/path/synthetic.db --synthetic-only
   ```

4. Repeat it: it must report that identities are already present and valid.
5. Start only the new application against the upgraded disposable fixture and
   check `/healthz`. Old or partial schemas must fail readiness rather than
   silently backfilling or accepting writers.

The command opens only an existing file (`mode=rw`), does not load `.env`, import
Flask, rotate keys, decrypt fields, or change sharing. `BEGIN IMMEDIATE` wraps the
column addition, UUID backfill, unique index, all format/immutability triggers and
validation in one transaction. Any exception rolls back DDL and data together.
A repeat validates rather than repairs: missing/altered guards, invalid stored
UUIDs, nullable identity columns, missing or partial unique indexes, and partial
upgrade artifacts fail closed without replacing any identity. Trigger definitions
are deliberately checked against the supported implementation; manually changed
ones require explicit review, not implicit acceptance.

The migrated column has an empty internal ALTER default to support populated
SQLite tables; insert guards reject that default, so callers cannot insert an
identity-less row. The application generates a valid UUID before insertion.
SQLite is the only supported readiness/upgrade dialect for this drill. Other
databases need a separately reviewed schema/guard design.

## Verification

`tests/test_item_identity_schema.py` uses disposable SQLite fixtures to check:
- Repeat stability, UUID4 validity and uniqueness
- Ciphertext bytes, existing integer keys and sharing rows preserved
- Foreign-key integrity after upgrade
- Direct SQL immutability and format enforcement, and model-level rejection
- Rollback at ALTER, backfill, index creation and each trigger creation
- Collision rollback and successful retry after injected failure is removed
- Partial or invalid schema rejection without repair
- Fresh-schema guards and new UUIDs even when SQLite recycles an integer key

This drill does not change crypto, account lifecycle, recipient-incarnation
selectors, backup/restore security, or ownership/share policy. It does not claim
that a real vault or deployment was migrated or certified.
