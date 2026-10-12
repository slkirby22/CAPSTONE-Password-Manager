"""Item identity invariants using only disposable SQLite data."""
import sqlite3
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from flask import Flask
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from item_identity import ITEM_TRIGGERS, is_item_id, validate_item_schema
from models import db, Password, User
from scripts.upgrade_item_identity import migrate


@pytest.fixture
def legacy():
    connection = sqlite3.connect(':memory:')
    connection.executescript('''
        PRAGMA foreign_keys=ON;
        CREATE TABLE user(id INTEGER PRIMARY KEY, auth_identity TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, role TEXT NOT NULL,
            failed_login_attempts INTEGER);
        CREATE TABLE password(id INTEGER PRIMARY KEY, service_name TEXT NOT NULL,
            username TEXT NOT NULL, password BLOB NOT NULL, notes TEXT,
            user_id INTEGER NOT NULL REFERENCES user(id));
        CREATE TABLE password_user(password_id INTEGER REFERENCES password(id),
            user_id INTEGER REFERENCES user(id), PRIMARY KEY(password_id,user_id));
        INSERT INTO user VALUES(1,'11111111111141118111111111111111','OWNER','hash','employee',0),
            (2,'22222222222242228222222222222222','SHARED','hash','employee',0);
        INSERT INTO password VALUES(1,'same','synthetic',X'01020304','notes',1);
        INSERT INTO password VALUES(2,'same','synthetic',X'ff000011','notes',1);
        INSERT INTO password_user VALUES(1,2);
    ''')
    yield connection
    connection.close()


def snapshot(connection):
    return (connection.execute('SELECT id,service_name,username,password,notes,user_id FROM password ORDER BY id').fetchall(),
            connection.execute('SELECT * FROM password_user').fetchall())


def test_atomic_preserving_upgrade_and_repeat(legacy):
    before = snapshot(legacy)
    assert migrate(legacy)
    ids = legacy.execute('SELECT item_id FROM password ORDER BY id').fetchall()
    assert len(set(ids)) == 2
    assert all(is_item_id(row[0]) for row in ids)
    assert snapshot(legacy) == before
    assert legacy.execute('PRAGMA foreign_key_check').fetchall() == []
    assert not migrate(legacy)
    assert legacy.execute('SELECT item_id FROM password ORDER BY id').fetchall() == ids
    legacy.execute("UPDATE password SET service_name='changed' WHERE id=1")
    assert legacy.execute('SELECT item_id FROM password WHERE id=1').fetchone() == ids[0]
    legacy.rollback()
    for value in (None, '', 'F' * 32, '1' * 32, uuid4().hex, ids[1][0]):
        with pytest.raises(sqlite3.IntegrityError):
            legacy.execute('UPDATE password SET item_id=? WHERE id=1', (value,))
        legacy.rollback()
    for value in (None, '', 'F' * 32, '1' * 32, ids[0][0]):
        with pytest.raises(sqlite3.IntegrityError):
            legacy.execute("INSERT INTO password VALUES(3,'x','x',X'01','',1,?)", (value,))
        legacy.rollback()
    valid = uuid4().hex
    legacy.execute("INSERT INTO password VALUES(3,'x','x',X'01','',1,?)", (valid,))
    legacy.commit()
    validate_item_schema(legacy)


@pytest.mark.parametrize('failure_point', ['alter', 'backfill', 'index', *ITEM_TRIGGERS])
def test_fault_injected_full_rollback(legacy, failure_point):
    before = snapshot(legacy)
    schema = legacy.execute('SELECT type,name,sql FROM sqlite_master ORDER BY name').fetchall()
    def deny(action, first, second, database, source):
        fail = ((failure_point == 'alter' and action == sqlite3.SQLITE_ALTER_TABLE)
                or (failure_point == 'backfill' and action == sqlite3.SQLITE_UPDATE and second == 'item_id')
                or (failure_point == 'index' and action == sqlite3.SQLITE_CREATE_INDEX and first == 'uq_password_item_identity')
                or (action == sqlite3.SQLITE_CREATE_TRIGGER and first == failure_point))
        return sqlite3.SQLITE_DENY if fail else sqlite3.SQLITE_OK
    legacy.set_authorizer(deny)
    with pytest.raises(sqlite3.DatabaseError):
        migrate(legacy)
    legacy.set_authorizer(None)
    assert not legacy.in_transaction
    assert snapshot(legacy) == before
    assert legacy.execute('SELECT type,name,sql FROM sqlite_master ORDER BY name').fetchall() == schema
    assert migrate(legacy)


def test_collision_rolls_back(legacy, monkeypatch):
    fixed = uuid4()
    monkeypatch.setattr('scripts.upgrade_item_identity.uuid4', lambda: fixed)
    with pytest.raises(sqlite3.IntegrityError):
        migrate(legacy)
    assert 'item_id' not in [row[1] for row in legacy.execute('PRAGMA table_info(password)')]


@pytest.mark.parametrize('damage', ['missing_insert', 'missing_update', 'missing_immutable', 'fake_immutable', 'missing_unique', 'partial_unique', 'invalid_data'])
def test_completed_schema_damage_rejected_without_repair(legacy, damage):
    migrate(legacy)
    if damage.startswith('missing_') and damage != 'missing_unique':
        trigger = {'missing_insert': 'insert', 'missing_update': 'update', 'missing_immutable': 'immutable'}[damage]
        legacy.execute('DROP TRIGGER password_item_identity_' + trigger)
    elif damage == 'fake_immutable':
        legacy.execute('DROP TRIGGER password_item_identity_immutable')
        legacy.execute('CREATE TRIGGER password_item_identity_immutable BEFORE UPDATE ON password BEGIN SELECT 1; END')
    elif damage in ('missing_unique', 'partial_unique'):
        legacy.execute('DROP INDEX uq_password_item_identity')
        if damage == 'partial_unique':
            legacy.execute('CREATE UNIQUE INDEX uq_partial ON password(item_id) WHERE id < 0')
    else:
        legacy.execute('DROP TRIGGER password_item_identity_update')
        legacy.execute('DROP TRIGGER password_item_identity_immutable')
        legacy.execute("UPDATE password SET item_id='invalid' WHERE id=1")
        legacy.execute(ITEM_TRIGGERS['password_item_identity_update'])
        legacy.execute(ITEM_TRIGGERS['password_item_identity_immutable'])
    legacy.commit()
    before = legacy.execute('SELECT type,name,sql FROM sqlite_master ORDER BY name').fetchall()
    with pytest.raises(ValueError):
        migrate(legacy)
    assert legacy.execute('SELECT type,name,sql FROM sqlite_master ORDER BY name').fetchall() == before


def test_partial_column_and_unknown_schema_rejected(legacy):
    legacy.execute('ALTER TABLE password ADD COLUMN item_id TEXT')
    with pytest.raises(ValueError):
        migrate(legacy)
    with sqlite3.connect(':memory:') as empty:
        with pytest.raises(ValueError):
            migrate(empty)
        assert empty.execute('SELECT * FROM sqlite_master').fetchall() == []


def test_model_identity_and_fresh_schema_guards():
    app = Flask(__name__)
    app.config.update(SQLALCHEMY_DATABASE_URI='sqlite:///:memory:', TESTING=True)
    db.init_app(app)
    with app.app_context():
        db.create_all()
        validate_item_schema(db.session.connection())
        user = User('SYNTHETIC', 'hash', 'employee')
        db.session.add(user)
        db.session.flush()
        item = Password('same', 'user', b'ciphertext', '', user.id)
        original = item.item_id
        assert is_item_id(original)
        with pytest.raises(TypeError):
            Password('same', 'user', b'ciphertext', '', user.id, item_id=uuid4().hex)
        with pytest.raises(ValueError, match='Immutable'):
            item.item_id = uuid4().hex
        db.session.add(item)
        db.session.commit()
        numeric = item.id
        with pytest.raises(ValueError, match='Immutable'):
            item.item_id = uuid4().hex
        with pytest.raises(IntegrityError):
            db.session.execute(text('UPDATE password SET item_id=:value'), {'value': uuid4().hex})
        db.session.rollback()
        db.session.delete(item)
        db.session.commit()
        replacement = Password('same', 'user', b'ciphertext', '', user.id)
        db.session.add(replacement)
        db.session.commit()
        assert replacement.id == numeric
        assert replacement.item_id != original
        validate_item_schema(db.session.connection())


def test_offline_command_requires_acknowledgement_and_existing_file(tmp_path):
    import subprocess
    script = Path(__file__).resolve().parents[1] / 'scripts/upgrade_item_identity.py'
    missing = tmp_path / 'missing.db'
    result = subprocess.run([sys.executable, str(script), str(missing)], capture_output=True, text=True)
    assert result.returncode != 0
    assert not missing.exists()
    result = subprocess.run([sys.executable, str(script), str(missing), '--synthetic-only'],
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert not missing.exists()


def test_container_ships_item_upgrade_without_startup_execution():
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / 'Dockerfile').read_text()
    assert 'item_identity.py /app/' in dockerfile
    assert 'COPY scripts/upgrade_item_identity.py /app/scripts/' in dockerfile
    assert 'upgrade_item_identity' not in (root / 'deployment/start.sh').read_text()


@pytest.mark.parametrize('value', [None, '', 'A' * 32, 'a' * 32,
                                    '00000000000010008000000000000000',
                                    '00000000000040007000000000000000'])
def test_fresh_schema_direct_sql_rejects_invalid_insert(value):
    app = Flask(__name__)
    app.config.update(SQLALCHEMY_DATABASE_URI='sqlite:///:memory:', TESTING=True)
    db.init_app(app)
    with app.app_context():
        db.create_all()
        with pytest.raises(IntegrityError):
            db.session.execute(text('''INSERT INTO password(item_id,service_name,username,password,user_id)
                VALUES(:identity,'synthetic','synthetic','ciphertext',1)'''), {'identity': value})
        db.session.rollback()
        validate_item_schema(db.session.connection())


def test_migrated_model_generates_valid_new_id_and_preserves_ciphertext(legacy, tmp_path):
    migrate(legacy)
    path = tmp_path / 'synthetic-migrated.db'
    with sqlite3.connect(path) as target:
        legacy.backup(target)
    app = Flask(__name__)
    app.config.update(SQLALCHEMY_DATABASE_URI=f'sqlite:///{path}', TESTING=True)
    db.init_app(app)
    with app.app_context():
        validate_item_schema(db.session.connection())
        old = db.session.get(Password, 1)
        identity, ciphertext = old.item_id, old.password
        old.notes = 'edited metadata'
        new = Password('same', 'user', b'new ciphertext', '', 1)
        db.session.add(new)
        db.session.commit()
        assert old.item_id == identity and old.password == ciphertext
        assert is_item_id(new.item_id) and new.item_id != identity
        assert old.shared_users  # Existing integer associations still resolve.
        validate_item_schema(db.session.connection())
