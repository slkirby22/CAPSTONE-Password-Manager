"""Explicit one-way SQLite upgrade for disposable synthetic databases only.

Does not import the app, read .env, run at startup, or rotate signing/encryption keys.
This bounded upgrade is not the planned general Alembic migration framework.
"""
import argparse
from pathlib import Path
import re
import sqlite3
from uuid import uuid4


BASELINE_COLUMNS = {'id', 'username', 'password', 'role', 'failed_login_attempts'}


def migrate(connection):
    """Atomically backfill distinct account identities; return whether changed.

    The caller owns the connection and must stop all application writers first.
    SQLite DDL participates in our explicit transaction, so partial failure leaves
    the original schema/data intact. Existing valid identities are never replaced.
    """
    if connection.in_transaction:
        raise ValueError('Migration needs an idle connection')
    connection.execute('BEGIN IMMEDIATE')
    try:
        columns = {row[1]: row for row in connection.execute('PRAGMA table_info("user")')}
        if not BASELINE_COLUMNS.issubset(columns):
            raise ValueError('Unsupported user schema')
        if 'auth_identity' in columns:
            identities = [row[0] for row in connection.execute('SELECT auth_identity FROM "user"')]
            if (not columns['auth_identity'][3]
                    or any(not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{32}', value) is None
                           for value in identities)
                    or len(set(identities)) != len(identities)):
                raise ValueError('Invalid existing identity schema/data')
            # A partially hand-edited schema without a single-column unique index
            # must not be mistaken for a completed upgrade.
            unique = any(row[2] and not row[4] and [entry[2] for entry in connection.execute(
                'SELECT * FROM pragma_index_info(?)', (row[1],))] == ['auth_identity']
                for row in connection.execute('PRAGMA index_list("user")'))
            if not unique:
                raise ValueError('Missing account identity uniqueness constraint')
            connection.commit()
            return False

        # A temporary empty default permits ALTER on a populated SQLite table.
        # Backfill and insert/update guards complete before the same commit.
        connection.execute('ALTER TABLE "user" ADD COLUMN auth_identity VARCHAR(32) NOT NULL DEFAULT \'\'')
        for (user_id,) in connection.execute('SELECT id FROM "user"').fetchall():
            connection.execute('UPDATE "user" SET auth_identity=? WHERE id=?', (uuid4().hex, user_id))
        connection.execute('CREATE UNIQUE INDEX uq_user_auth_identity ON "user" (auth_identity)')
        for operation in ('INSERT', 'UPDATE'):
            connection.execute(f'''
                CREATE TRIGGER user_auth_identity_{operation.lower()}
                BEFORE {operation} ON "user"
                WHEN length(NEW.auth_identity) != 32
                     OR NEW.auth_identity GLOB '*[^0-9a-f]*'
                BEGIN SELECT RAISE(ABORT, 'Invalid account identity'); END
            ''')
        connection.commit()
        return True
    except Exception:
        connection.rollback()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('database', type=Path, help='Existing disposable SQLite database file')
    parser.add_argument('--synthetic-only', action='store_true', required=True,
                        help='Confirm the file is a disposable synthetic fixture')
    args = parser.parse_args()
    # mode=rw prevents accidental creation of an empty database at a typo path.
    with sqlite3.connect(args.database.resolve().as_uri() + '?mode=rw', uri=True) as connection:
        changed = migrate(connection)
    print('Synthetic account identity migration applied.' if changed else 'Account identities already present.')


if __name__ == '__main__':
    main()
