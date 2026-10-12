"""Disposable legacy SQLite migration, rollback, and route compatibility proof."""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

from authorization import register_jwt_current_user
from models import User, db
from scripts.migrate_account_identity import migrate


@pytest.fixture
def legacy_db(tmp_path):
    path = tmp_path / 'synthetic.db'
    with sqlite3.connect(path) as connection:
        connection.executescript('''
            PRAGMA foreign_keys=ON;
            CREATE TABLE user (id INTEGER NOT NULL PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE, password VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL, failed_login_attempts INTEGER);
            CREATE TABLE password (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES user(id),
                password BLOB NOT NULL);
            CREATE TABLE password_user (password_id INTEGER REFERENCES password(id),
                user_id INTEGER REFERENCES user(id), PRIMARY KEY(password_id,user_id));
            INSERT INTO user VALUES (1,'SYNTHETIC_ADMIN','synthetic-hash','admin',0);
            INSERT INTO user VALUES (2,'SYNTHETIC_OTHER','synthetic-hash','employee',2);
            INSERT INTO password VALUES (1,1,X'01020304');
            INSERT INTO password_user VALUES (1,2);
        ''')
    return path


def baseline_rows(connection):
    return (
        connection.execute('SELECT id,username,password,role,failed_login_attempts FROM user').fetchall(),
        connection.execute('SELECT * FROM password').fetchall(),
        connection.execute('SELECT * FROM password_user').fetchall(),
    )


def test_existing_schema_preserved_and_upgrade_idempotent(legacy_db):
    with sqlite3.connect(legacy_db) as connection:
        connection.execute('PRAGMA foreign_keys=ON')
        before = baseline_rows(connection)
        assert migrate(connection)
        identities = connection.execute('SELECT auth_identity FROM user ORDER BY id').fetchall()
        assert len(set(identities)) == 2
        assert all(len(value[0]) == 32 for value in identities)
        assert baseline_rows(connection) == before
        assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
        assert not migrate(connection)
        assert connection.execute('SELECT auth_identity FROM user ORDER BY id').fetchall() == identities
        for value in ('', 'invalid', None, identities[0][0]):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute('INSERT INTO user(id,username,password,role,auth_identity) VALUES (3,?,?,?,?)',
                                   ('SYNTHETIC_INVALID', 'unused', 'employee', value))
            connection.rollback()
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("INSERT INTO user(id,username,password,role) VALUES (3,'NO_BINDING','unused','employee')")


@pytest.mark.parametrize('failure_point', ['backfill', 'index', 'trigger'])
def test_partial_failure_rolls_back_schema_and_data(legacy_db, failure_point):
    with sqlite3.connect(legacy_db) as connection:
        before = baseline_rows(connection)
        schema_before = connection.execute('SELECT type,name,sql FROM sqlite_master ORDER BY name').fetchall()
        def deny(action, arg1, arg2, database, source):
            denied = ((failure_point == 'backfill' and action == sqlite3.SQLITE_UPDATE
                       and arg1 == 'user' and arg2 == 'auth_identity')
                      or (failure_point == 'index' and action == sqlite3.SQLITE_CREATE_INDEX
                          and arg1 == 'uq_user_auth_identity')
                      or (failure_point == 'trigger' and action == sqlite3.SQLITE_CREATE_TRIGGER))
            return sqlite3.SQLITE_DENY if denied else sqlite3.SQLITE_OK
        connection.set_authorizer(deny)
        with pytest.raises(sqlite3.DatabaseError):
            migrate(connection)
        connection.set_authorizer(None)
        assert not connection.in_transaction
        assert baseline_rows(connection) == before
        assert connection.execute('SELECT type,name,sql FROM sqlite_master ORDER BY name').fetchall() == schema_before
        assert migrate(connection), 'Retry on original schema succeeds after fault is removed'


def test_collision_rolls_back_whole_upgrade(legacy_db, monkeypatch):
    class Fixed:
        hex = '1' * 32
    monkeypatch.setattr('scripts.migrate_account_identity.uuid4', Fixed)
    with sqlite3.connect(legacy_db) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            migrate(connection)
        assert 'auth_identity' not in [row[1] for row in connection.execute('PRAGMA table_info(user)')]


def test_migrated_model_issues_new_bindings_and_rejects_legacy_jwt(legacy_db):
    with sqlite3.connect(legacy_db) as connection:
        migrate(connection)
    app = Flask(__name__)
    app.config.update(TESTING=True, SQLALCHEMY_DATABASE_URI=f'sqlite:///{legacy_db}',
                      JWT_SECRET_KEY='synthetic-migration-signing-00000000')
    db.init_app(app)
    jwt = JWTManager(app)
    register_jwt_current_user(jwt)
    @app.get('/protected')
    @jwt_required()
    def protected():
        return 'synthetic authenticated'
    with app.app_context():
        legacy = create_access_token(identity='1')
        user = db.session.get(User, 1)
        current = create_access_token(identity='1', additional_claims={'auth_identity': user.auth_identity})
        new = User('SYNTHETIC_NEW', 'unused', 'employee')
        db.session.add(new)
        db.session.commit()
        assert new.auth_identity != user.auth_identity
    client = app.test_client()
    assert client.get('/protected', headers={'Authorization': f'Bearer {legacy}'}).status_code == 401
    assert client.get('/protected', headers={'Authorization': f'Bearer {current}'}).status_code == 200


def test_unknown_and_partial_schemas_rejected_without_mutation():
    with sqlite3.connect(':memory:') as connection:
        with pytest.raises(ValueError, match='Unsupported'):
            migrate(connection)
        assert connection.execute('SELECT * FROM sqlite_master').fetchall() == []


@pytest.mark.parametrize('definition,identity', [
    ('VARCHAR(32)', '1' * 32),
    ('VARCHAR(32) NOT NULL UNIQUE', ''),
    ('VARCHAR(32) NOT NULL', '1' * 32),
])
def test_incomplete_identity_schema_fails_closed(definition, identity):
    with sqlite3.connect(':memory:') as connection:
        connection.execute(f'''CREATE TABLE user(id INTEGER PRIMARY KEY, username TEXT,
            password TEXT, role TEXT, failed_login_attempts INTEGER, auth_identity {definition})''')
        connection.execute('INSERT INTO user VALUES(1,?,?,?,?,?)', ('SYNTHETIC', 'unused', 'admin', 0, identity))
        connection.commit()
        before = connection.execute('SELECT * FROM user').fetchall()
        with pytest.raises(ValueError):
            migrate(connection)
        assert connection.execute('SELECT * FROM user').fetchall() == before


def test_actual_app_upgrade_requires_migration_and_fresh_login(tmp_path):
    """Import shipped app in an isolated process against a disposable legacy file."""
    import os
    import subprocess
    database = tmp_path / 'actual-app-synthetic.db'
    with sqlite3.connect(database) as connection:
        connection.execute('''CREATE TABLE user (id INTEGER NOT NULL PRIMARY KEY,
            username VARCHAR(255) NOT NULL UNIQUE, password VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL, failed_login_attempts INTEGER)''')
    code = '''
import sqlite3
from app import app, limiter
from models import db, User, Password
from functions import pwd_context
from cryptography.fernet import Fernet
from flask_jwt_extended import create_access_token
from scripts.migrate_account_identity import migrate
app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
limiter.enabled = False
client = app.test_client()
with app.app_context():
    db.create_all()  # Startup never silently upgrades the old user table.
    path = db.engine.url.database
    with sqlite3.connect(path) as connection:
        connection.execute('INSERT INTO user VALUES(1,?,?,?,0)',
                           ('SYNTHETIC', pwd_context.hash('Synthetic!99'), 'admin'))
    legacy_token = create_access_token(identity='1')
assert client.get('/healthz').status_code == 503
with sqlite3.connect(path) as connection:
    assert migrate(connection)
assert client.get('/healthz').status_code == 200
with app.app_context():
    db.session.add(Password('synthetic', 'synthetic',
        Fernet(app.config['ENCRYPTION_KEY']).encrypt(b'synthetic migrated vault'), '', 1))
    db.session.commit()
with client.session_transaction() as session:
    session.update(user_id=1, role='admin', username='SYNTHETIC')
assert client.get('/get_audit_logs').status_code == 401
assert client.get('/api/dashboard', headers={'Authorization': 'Bearer ' + legacy_token}).status_code == 401
assert client.post('/login', data={'username':'SYNTHETIC','password':'Synthetic!99'}).status_code == 302
assert client.get('/get_audit_logs').status_code == 200
response = client.post('/api/login', json={'username':'SYNTHETIC','password':'Synthetic!99'})
assert response.status_code == 200
response = client.get('/api/dashboard', headers={'Authorization': 'Bearer ' + response.json['access_token']})
assert response.status_code == 410
assert response.json['error'] == 'vault_api_retired'
with app.app_context():
    assert Fernet(app.config['ENCRYPTION_KEY']).decrypt(Password.query.one().password) == b'synthetic migrated vault'
'''
    environment = dict(os.environ, DATABASE_URL=f'sqlite:///{database}', PYTHON_DOTENV_DISABLED='1')
    subprocess.run([sys.executable, '-c', code], env=environment,
                   cwd=Path(__file__).resolve().parents[1], check=True, capture_output=True, text=True)


def test_partial_unique_index_is_not_a_completed_upgrade():
    with sqlite3.connect(':memory:') as connection:
        connection.executescript("""
            CREATE TABLE user(id INTEGER PRIMARY KEY, username TEXT, password TEXT,
                role TEXT, failed_login_attempts INTEGER, auth_identity TEXT NOT NULL);
            CREATE UNIQUE INDEX partial_identity ON user(auth_identity) WHERE id < 0;
        """)
        with pytest.raises(ValueError, match='uniqueness'):
            migrate(connection)
