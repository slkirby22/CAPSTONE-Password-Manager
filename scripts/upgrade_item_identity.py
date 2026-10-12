"""Explicit, offline SQLite item-identity upgrade for disposable synthetic data.

Never imports the app, reads .env, or runs automatically at startup. Stop all
writers before running. This is not a general or production migration framework.
"""
import argparse
from pathlib import Path
import sqlite3
import sys
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from item_identity import ITEM_TRIGGERS, validate_item_schema

BASELINE_COLUMNS = {'id', 'service_name', 'username', 'password', 'notes', 'user_id'}


def migrate(connection):
    """Atomically add UUID4 identities and guards; return False if already valid."""
    if connection.in_transaction:
        raise ValueError('Migration needs an idle connection')
    connection.execute('BEGIN IMMEDIATE')
    try:
        columns = {row[1]: row for row in connection.execute('PRAGMA table_info(password)')}
        if not BASELINE_COLUMNS.issubset(columns):
            raise ValueError('Unsupported password schema')
        if 'item_id' in columns:
            validate_item_schema(connection)
            connection.commit()
            return False
        if connection.execute("SELECT 1 FROM sqlite_master WHERE name IN (?, ?, ?, ?)",
                              (*ITEM_TRIGGERS, 'uq_password_item_identity')).fetchone():
            raise ValueError('Partial item identity schema')
        connection.execute("ALTER TABLE password ADD COLUMN item_id VARCHAR(32) NOT NULL DEFAULT ''")
        for (password_id,) in connection.execute('SELECT id FROM password').fetchall():
            connection.execute('UPDATE password SET item_id=? WHERE id=?', (uuid4().hex, password_id))
        connection.execute('CREATE UNIQUE INDEX uq_password_item_identity ON password(item_id)')
        for sql in ITEM_TRIGGERS.values():
            connection.execute(sql)
        validate_item_schema(connection)
        connection.commit()
        return True
    except Exception:
        connection.rollback()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('database', type=Path, help='Existing disposable SQLite fixture')
    parser.add_argument('--synthetic-only', action='store_true', required=True,
                        help='Confirm this file contains disposable synthetic data only')
    args = parser.parse_args()
    with sqlite3.connect(args.database.resolve().as_uri() + '?mode=rw', uri=True) as connection:
        changed = migrate(connection)
    print('Synthetic item identity upgrade applied.' if changed else 'Item identities already present and valid.')


if __name__ == '__main__':
    main()
