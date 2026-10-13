"""Offline recovery drill using only self-created disposable synthetic fixtures.

Accepts no database paths, URLs or credentials. Does not read .env or contact a
server. This tests current SQLite identity upgrades and a backup/restore round
trip, not an operator-facing backup tool or a production recovery procedure.
"""
import base64
import os
from pathlib import Path
import sqlite3
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptography.fernet import Fernet, InvalidToken
from scripts.migrate_account_identity import migrate as migrate_accounts
from scripts.upgrade_item_identity import migrate as migrate_items

PUBLIC_KEY = base64.urlsafe_b64encode(b'0' * 32)
PUBLIC_VALUE = b'Public-recovery-fixture-only-123!'


def require(condition, message):
    # Do not use assert: the safety/verification checks must survive python -O.
    if not condition:
        raise RuntimeError(message)


def snapshot(connection):
    return {table: connection.execute(f'SELECT * FROM "{table}" ORDER BY 1').fetchall()
            for table in ('user', 'password', 'password_user', 'audit_log', 'token_blacklist')}


def run_drill(directory):
    """Caller must supply a newly created temporary directory, never a live DB."""
    source_path = directory / 'source.db'
    backup_path = directory / 'backup.db'
    restored_path = directory / 'restored.db'
    require(not any(directory.iterdir()), 'Recovery drill requires an empty directory')
    with sqlite3.connect(source_path) as source:
        source.executescript('''
            PRAGMA foreign_keys=ON;
            CREATE TABLE user(id INTEGER PRIMARY KEY, username VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL, role VARCHAR(50) NOT NULL, failed_login_attempts INTEGER);
            CREATE TABLE password(id INTEGER PRIMARY KEY, service_name VARCHAR(255) NOT NULL,
                username VARCHAR(255) NOT NULL, password VARCHAR(255) NOT NULL, notes VARCHAR(500),
                user_id INTEGER NOT NULL REFERENCES user(id));
            CREATE TABLE password_user(password_id INTEGER REFERENCES password(id),
                user_id INTEGER REFERENCES user(id), PRIMARY KEY(password_id,user_id));
            CREATE TABLE audit_log(id INTEGER PRIMARY KEY, event_time DATETIME NOT NULL,
                event_message TEXT NOT NULL, event_type VARCHAR(255) NOT NULL,
                user_id INTEGER REFERENCES user(id));
            CREATE TABLE token_blacklist(id INTEGER PRIMARY KEY, jti VARCHAR(36) NOT NULL UNIQUE,
                expires_at DATETIME NOT NULL, created_at DATETIME);
            INSERT INTO user VALUES(1,'RECOVERYOWNER','not-a-login-hash','employee',0),
                (2,'RECOVERYSHARED','not-a-login-hash','employee',0);
        ''')
        cipher = Fernet(PUBLIC_KEY)
        source.execute('INSERT INTO password VALUES(1,?,?,?,?,1)',
                       ('Recovery fixture', 'synthetic', cipher.encrypt(PUBLIC_VALUE), 'synthetic notes'))
        source.execute('INSERT INTO password_user VALUES(1,2)')
        source.execute("INSERT INTO audit_log VALUES(1,'2026-01-01 00:00:00','Public fixture','fixture',1)")
        source.execute("INSERT INTO token_blacklist VALUES(1,'public-revoked-jti','2030-01-01 00:00:00','2026-01-01 00:00:00')")
        source.commit()
        legacy = snapshot(source)
        widths = {table: len(source.execute(f'PRAGMA table_info("{table}")').fetchall())
                  for table in legacy}
        require(migrate_accounts(source), 'Expected account upgrade')
        require(migrate_items(source), 'Expected item upgrade')
        before = snapshot(source)
        payload = {table: [row[:widths[table]] for row in rows]
                   for table, rows in before.items()}
        require(payload == legacy, 'Identity upgrade changed existing fixture payload')
        require(not migrate_accounts(source), 'Account upgrade was not repeatable')
        require(not migrate_items(source), 'Item upgrade was not repeatable')
        require(snapshot(source) == before, 'Repeated upgrade changed fixture data')
        with sqlite3.connect(backup_path) as backup:
            source.backup(backup)
        # A post-backup change must not accidentally leak into the restored copy.
        source.execute("UPDATE password SET notes='after backup'")
        source.commit()
    with sqlite3.connect(backup_path) as backup, sqlite3.connect(restored_path) as restored:
        backup.backup(restored)
        restored.execute('PRAGMA foreign_keys=ON')
        require(restored.execute('PRAGMA integrity_check').fetchone() == ('ok',), 'Integrity check failed')
        require(not restored.execute('PRAGMA foreign_key_check').fetchall(), 'Foreign-key check failed')
        require(snapshot(restored) == before, 'Restore changed identities, sharing or data')
        require(not migrate_accounts(restored) and not migrate_items(restored), 'Restore lost migration constraints')
        ciphertext = restored.execute('SELECT password FROM password').fetchone()[0]
        require(cipher.decrypt(ciphertext) == PUBLIC_VALUE, 'Restored ciphertext cannot be decrypted')
        try:
            Fernet(base64.urlsafe_b64encode(b'1' * 32)).decrypt(ciphertext)
        except InvalidToken:
            pass
        else:
            raise RuntimeError('Wrong encryption key unexpectedly worked')
    return restored_path


def verify_application(restored_path):
    os.environ.update(APP_ENV='synthetic', SYNTHETIC_DATA_ONLY='true',
                      DATABASE_URL=f'sqlite:///{restored_path}',
                      SECRET_KEY='public-recovery-session-fixture-00000000',
                      JWT_SECRET_KEY='public-recovery-jwt-fixture-000000000000',
                      ENCRYPTION_KEY=PUBLIC_KEY.decode(), TRUSTED_HOSTS='localhost',
                      PYTHON_DOTENV_DISABLED='1')
    os.environ.pop('RENDER', None)
    from app import app
    from models import db, Password
    with app.app_context():
        require(app.test_client().get('/healthz').status_code == 200, 'Restored app is not ready')
        item = db.session.get(Password, 1)
        require(item.user.username == 'RECOVERYOWNER', 'Restored owner mismatch')
        require([user.username for user in item.shared_users] == ['RECOVERYSHARED'], 'Restored sharing mismatch')
        db.session.remove()
        db.engine.dispose()


def main():
    require(len(sys.argv) == 1, 'This drill accepts no arguments or existing database paths')
    with tempfile.TemporaryDirectory(prefix='password-recovery-synthetic-') as directory:
        verify_application(run_drill(Path(directory)))
    print('Synthetic recovery passed: repeatable upgrades, consistent backup/restore, identities, sharing, ciphertext and app readiness')


if __name__ == '__main__':
    main()
