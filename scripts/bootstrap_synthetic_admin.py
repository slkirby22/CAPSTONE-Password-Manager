"""One-time, owner-operated administrator setup for an empty synthetic SQLite DB.

Never run automatically, against real data, or through a web endpoint. Passwords
are read from a local non-echoing terminal only, never arguments or environment.
The owner must approve and personally perform credential entry and submission.
"""
import argparse
from datetime import datetime, timezone
import getpass
import os
from pathlib import Path
import sqlite3
import stat
import sys
from uuid import uuid4
import warnings

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from functions import password_meets_requirements, pwd_context
from item_identity import validate_item_schema
from models import db
from sqlalchemy import create_engine

TABLES = {'user', 'password', 'password_user', 'audit_log', 'token_blacklist'}


class BootstrapError(Exception):
    """Safe generic setup failure; never interpolate supplied values."""


def require(condition, message):
    if not condition:
        raise BootstrapError(message)


def schema_signature(connection, table):
    columns = tuple(tuple(row[1:]) for row in connection.execute(f'PRAGMA table_info("{table}")'))
    foreign_keys = tuple(sorted(tuple(row[2:]) for row in connection.execute(f'PRAGMA foreign_key_list("{table}")')))
    unique = tuple(sorted(tuple(entry[2] for entry in connection.execute(
        'SELECT * FROM pragma_index_info(?)', (row[1],)))
        for row in connection.execute(f'PRAGMA index_list("{table}")') if row[2] and not row[4]))
    return columns, foreign_keys, unique


def validate_empty_schema(connection):
    tables = {row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    require(tables == TABLES, 'Expected the current, initialized synthetic schema')
    # Compare against the shipped ORM schema, not a few recognizable columns.
    # This catches unusable identifiers and malformed ancillary tables before
    # the irreversible first account is committed. Index names are immaterial.
    reference = create_engine('sqlite:///:memory:')
    try:
        db.metadata.create_all(reference)
        with reference.connect() as expected:
            expected_db = expected.connection.driver_connection
            for table in TABLES:
                require(schema_signature(connection, table) == schema_signature(expected_db, table),
                        'Unsupported synthetic database schema')
    finally:
        reference.dispose()
    validate_item_schema(connection)
    require(connection.execute('PRAGMA integrity_check').fetchone() == ('ok',), 'Database integrity check failed')
    require(not connection.execute('PRAGMA foreign_key_check').fetchall(), 'Database references are invalid')
    for table in TABLES:
        require(connection.execute(f'SELECT 1 FROM "{table}" LIMIT 1').fetchone() is None,
                'Bootstrap requires every application table to be empty')


def create_admin(connection, username, password):
    """Single transaction; caller owns offline synthetic connection. No CLI secrets."""
    require(isinstance(username, str) and 1 <= len(username) <= 255
            and username == username.strip() and username.isprintable(), 'Invalid administrator username')
    username = username.upper()
    require(len(username) <= 255, 'Invalid administrator username')
    require(isinstance(password, str) and len(password) <= 1024
            and password_meets_requirements(password), 'Password does not meet the existing application policy')
    require(not connection.in_transaction, 'Bootstrap requires an idle connection')
    # Hash before the lock; repeat validation while holding the write lock below.
    hashed = pwd_context.hash(password)
    try:
        connection.execute('BEGIN IMMEDIATE')
        validate_empty_schema(connection)
        connection.execute('INSERT INTO "user" '
                           '(auth_identity,username,password,role,failed_login_attempts) VALUES(?,?,?,?,0)',
                           (uuid4().hex, username, hashed, 'admin'))
        user_id = connection.execute('SELECT id FROM "user"').fetchone()[0]
        connection.execute('INSERT INTO audit_log(event_time,event_message,event_type,user_id) VALUES(?,?,?,?)',
                           (datetime.now(timezone.utc).replace(tzinfo=None).isoformat(' '),
                            'Synthetic administrator initialized locally', 'SYNTHETIC_BOOTSTRAP', user_id))
        require(connection.execute('SELECT count(*) FROM "user"').fetchone() == (1,), 'Unexpected account state')
        connection.commit()
    except Exception:
        connection.rollback()
        raise BootstrapError('Bootstrap refused or failed; no account was committed') from None


def existing_target(path):
    require(path.is_absolute(), 'Use an explicit absolute database path')
    require(path == path.resolve(), 'Database path must not contain symlinks or traversal')
    require(stat.S_ISREG(path.lstat().st_mode), 'Target must be an existing regular database file')
    return path.as_uri() + '?mode=rw'


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'Invalid bootstrap arguments. Passwords must never be supplied as arguments.\n')


def main():
    parser = SafeParser(description=__doc__)
    parser.add_argument('database', type=Path, help='Existing empty synthetic SQLite database, absolute path')
    parser.add_argument('--synthetic-only', action='store_true', required=True,
                        help='Confirm disposable synthetic use, never real vault contents')
    args = parser.parse_args()
    try:
        require(os.environ.get('APP_ENV') == 'synthetic'
                and os.environ.get('SYNTHETIC_DATA_ONLY') == 'true', 'Explicit synthetic mode is required')
        require(sys.stdin.isatty() and sys.stderr.isatty(), 'A local interactive terminal is required')
        uri = existing_target(args.database)
        # Fail early on nonempty/schema-mismatched targets; checked again atomically.
        with sqlite3.connect(uri, uri=True, timeout=5) as connection:
            connection.execute('PRAGMA foreign_keys=ON')
            validate_empty_schema(connection)
            username = input('Synthetic administrator username: ')
            with warnings.catch_warnings():
                warnings.simplefilter('error', getpass.GetPassWarning)
                password = getpass.getpass('New synthetic-only password: ')
                confirm = getpass.getpass('Repeat password: ')
            require(password == confirm, 'Passwords do not match')
            require(input('Type CREATE SYNTHETIC ADMIN to commit: ') == 'CREATE SYNTHETIC ADMIN', 'Setup cancelled')
            create_admin(connection, username, password)
        print('Synthetic administrator created. No password or recovery material was printed.')
    except (Exception, KeyboardInterrupt):
        # Do not expose paths, usernames, database contents, password values or traces.
        print('Synthetic administrator setup did not complete. Check the empty schema, local terminal and synthetic configuration.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
