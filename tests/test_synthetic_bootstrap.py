"""Offline bootstrap regressions against public disposable fixtures only."""
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine
from models import db
from scripts.bootstrap_synthetic_admin import BootstrapError, create_admin, existing_target
from functions import pwd_context

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = 'Public-fixture-only-123!'


@pytest.fixture
def database(tmp_path):
    path = tmp_path / 'synthetic.db'
    engine = create_engine(f'sqlite:///{path}')
    db.metadata.create_all(engine)
    engine.dispose()
    return path


def test_bootstrap_hashes_and_audits(database):
    with sqlite3.connect(database) as connection:
        create_admin(connection, 'owner', PASSWORD)
        row = connection.execute('SELECT username,password,role,failed_login_attempts,auth_identity FROM user').fetchone()
        assert row[0] == 'OWNER' and row[2:4] == ('admin', 0)
        assert row[1] != PASSWORD and pwd_context.verify(PASSWORD, row[1])
        assert len(row[4]) == 32
        assert connection.execute('SELECT event_type FROM audit_log').fetchone() == ('SYNTHETIC_BOOTSTRAP',)
        with pytest.raises(BootstrapError):
            create_admin(connection, 'second', PASSWORD)
        assert connection.execute('SELECT count(*) FROM user').fetchone() == (1,)


def test_refuses_preexisting_nonaccount_data(database):
    with sqlite3.connect(database) as connection:
        connection.execute("INSERT INTO token_blacklist(jti,expires_at) VALUES('public','2030-01-01')")
        connection.commit()
        with pytest.raises(BootstrapError):
            create_admin(connection, 'owner', PASSWORD)
        assert connection.execute('SELECT count(*) FROM user').fetchone() == (0,)


def test_audit_failure_rolls_back_account(database):
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TRIGGER refuse_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'PUBLIC_SENTINEL'); END")
        with pytest.raises(BootstrapError) as error:
            create_admin(connection, 'owner', PASSWORD)
        assert 'PUBLIC_SENTINEL' not in str(error.value)
        assert connection.execute('SELECT count(*) FROM user').fetchone() == (0,)


def test_two_bootstraps_cannot_create_two_admins(database):
    def attempt(name):
        with sqlite3.connect(database, timeout=10) as connection:
            try:
                create_admin(connection, name, PASSWORD)
                return True
            except BootstrapError:
                return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, ['FIRST', 'SECOND'])) == [False, True]
    with sqlite3.connect(database) as connection:
        assert connection.execute('SELECT count(*) FROM user').fetchone() == (1,)
        assert connection.execute('SELECT count(*) FROM audit_log').fetchone() == (1,)


@pytest.mark.parametrize('username,password', [(' ', PASSWORD), ('a\nb', PASSWORD), ('x'*256, PASSWORD), ('OWNER', 'weak'), ('OWNER', 'x'*1025)])
def test_bad_input_does_not_write(database, username, password):
    with sqlite3.connect(database) as connection:
        with pytest.raises(BootstrapError):
            create_admin(connection, username, password)
        assert connection.execute('SELECT count(*) FROM user').fetchone() == (0,)


def test_rejects_symlink_and_relative_target(database):
    alias = database.parent / 'alias.db'
    alias.symlink_to(database)
    with pytest.raises(BootstrapError):
        existing_target(alias)
    with pytest.raises(BootstrapError):
        existing_target(Path('synthetic.db'))


def test_no_new_database_or_noninteractive_credentials(tmp_path):
    target = tmp_path / 'missing.db'
    result = subprocess.run([sys.executable, '-O', 'scripts/bootstrap_synthetic_admin.py', str(target), '--synthetic-only'],
                            cwd=ROOT, env=dict(os.environ, APP_ENV='synthetic', SYNTHETIC_DATA_ONLY='true'),
                            input=PASSWORD, capture_output=True, text=True)
    assert result.returncode == 1 and not target.exists()
    assert PASSWORD not in result.stdout + result.stderr
    assert str(target) not in result.stdout + result.stderr


def test_old_schema_rejected(database):
    with sqlite3.connect(database) as connection:
        connection.execute('DROP TABLE user')
        connection.execute('CREATE TABLE user(id INTEGER PRIMARY KEY, username TEXT)')
        with pytest.raises(BootstrapError):
            create_admin(connection, 'owner', PASSWORD)
        assert connection.execute('SELECT count(*) FROM user').fetchone() == (0,)


def test_accidental_password_argument_is_not_echoed(database):
    result = subprocess.run([sys.executable, 'scripts/bootstrap_synthetic_admin.py', str(database),
                             '--synthetic-only', '--password', PASSWORD], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 2
    assert PASSWORD not in result.stdout + result.stderr


@pytest.mark.parametrize('confirmation,expected', [('CREATE SYNTHETIC ADMIN', 0), ('cancel', 1)])
def test_owner_confirmation_is_required(database, monkeypatch, capsys, confirmation, expected):
    from scripts import bootstrap_synthetic_admin as bootstrap
    monkeypatch.setenv('APP_ENV', 'synthetic')
    monkeypatch.setenv('SYNTHETIC_DATA_ONLY', 'true')
    monkeypatch.setattr(sys, 'argv', ['bootstrap', str(database), '--synthetic-only'])
    monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr(sys.stderr, 'isatty', lambda: True)
    answers = iter(['OWNER', confirmation])
    monkeypatch.setattr('builtins.input', lambda prompt: next(answers))
    monkeypatch.setattr(bootstrap.getpass, 'getpass', lambda prompt: PASSWORD)
    assert bootstrap.main() == expected
    with sqlite3.connect(database) as connection:
        assert connection.execute('SELECT count(*) FROM user').fetchone() == ((1 if expected == 0 else 0),)
    captured = capsys.readouterr()
    assert PASSWORD not in captured.out + captured.err


def test_cli_rejects_non_synthetic_mode_before_prompt(database, monkeypatch):
    from scripts import bootstrap_synthetic_admin as bootstrap
    monkeypatch.setenv('APP_ENV', 'production')
    monkeypatch.setenv('SYNTHETIC_DATA_ONLY', 'true')
    monkeypatch.setattr(sys, 'argv', ['bootstrap', str(database), '--synthetic-only'])
    def unexpected(prompt):
        pytest.fail('must not prompt in non-synthetic mode')
    monkeypatch.setattr('builtins.input', unexpected)
    assert bootstrap.main() == 1
    with sqlite3.connect(database) as connection:
        assert connection.execute('SELECT count(*) FROM user').fetchone() == (0,)


@pytest.mark.parametrize('replacement', [
    'DROP TABLE token_blacklist; CREATE TABLE token_blacklist(id INTEGER PRIMARY KEY);',
    'DROP TABLE user; CREATE TABLE user(id TEXT PRIMARY KEY, auth_identity VARCHAR(32) NOT NULL UNIQUE, username VARCHAR(255) NOT NULL UNIQUE, password VARCHAR(255) NOT NULL, role VARCHAR(50) NOT NULL, failed_login_attempts INTEGER);',
    'DROP TABLE password_user; CREATE TABLE password_user(password_id INTEGER, user_id INTEGER, PRIMARY KEY(password_id,user_id));',
])
def test_malformed_full_schema_is_refused(database, replacement):
    with sqlite3.connect(database) as connection:
        connection.executescript(replacement)
        with pytest.raises(BootstrapError):
            create_admin(connection, 'owner', PASSWORD)
        assert connection.execute('SELECT count(*) FROM user').fetchone() == (0,)
