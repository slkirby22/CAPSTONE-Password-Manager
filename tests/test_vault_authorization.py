"""Object-level vault access through real routes and disposable synthetic data."""
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from flask_jwt_extended import create_access_token

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import app, limiter
from models import Password, User, audit_log, db


ROLES = ('employee', 'manager', 'admin')
ACTORS = {'owner': 1, 'shared': 2, 'unrelated': 3}
TARGET_SERVICE = 'synthetic-target-service'
TARGET_SECRET = 'synthetic-target-secret-unique'


@pytest.fixture
def vault_client(monkeypatch):
    # conftest.py establishes explicit test configuration before app imports.
    assert app.config['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///:memory:'
    monkeypatch.setitem(app.config, 'TESTING', True)
    monkeypatch.setitem(app.config, 'WTF_CSRF_ENABLED', False)
    monkeypatch.setattr(limiter, 'enabled', False)
    with app.app_context():
        db.create_all()
        users = [User(username=f'SYNTHETIC_{name.upper()}', password='unused',
                      role='employee') for name in ACTORS]
        db.session.add_all(users)
        db.session.flush()
        assert [user.id for user in users] == [1, 2, 3]
        cipher = Fernet(app.config['ENCRYPTION_KEY'])
        db.session.add_all([
            Password(user_id=1, service_name=TARGET_SERVICE,
                     username='synthetic-target-login',
                     password=cipher.encrypt(TARGET_SECRET.encode()),
                     notes='synthetic target notes', shared_users=[users[1]]),
            Password(user_id=3, service_name='synthetic-unrelated-private-service',
                     username='synthetic-private-login',
                     password=cipher.encrypt(b'synthetic-unrelated-private-secret'),
                     notes='synthetic unrelated notes'),
        ])
        db.session.commit()
    try:
        yield app.test_client()
    finally:
        with app.app_context():
            db.session.remove()
            db.drop_all()


def set_web_identity(client, user_id, cached_role='admin'):
    with client.session_transaction() as session:
        session.clear()
        session['user_id'] = user_id
        session['username'] = 'UNTRUSTED_CACHED_USERNAME'
        session['role'] = cached_role


def token_headers(user_id):
    with app.app_context():
        token = create_access_token(identity=str(user_id))
    return {'Authorization': f'Bearer {token}'}


def prepare_actor(client, actor, role, transport):
    user_id = ACTORS[actor]
    with app.app_context():
        db.session.get(User, user_id).role = role
        db.session.commit()
    if transport == 'web':
        # A forged/stale cached role must never override the current DB user.
        set_web_identity(client, user_id, 'employee' if role == 'admin' else 'admin')
        return {}
    return token_headers(user_id)


def vault_snapshot():
    with app.app_context():
        rows = Password.query.order_by(Password.id).all()
        return [
            (row.id, row.user_id, row.service_name, row.username, row.password,
             row.notes, tuple(sorted(user.id for user in row.shared_users)))
            for row in rows
        ]


def mutation_request(client, transport, operation, headers=None):
    if transport == 'api':
        if operation == 'update':
            return client.patch('/api/passwords/1', headers=headers or {}, json={
                'username': 'synthetic-changed-login',
                'password': 'synthetic-changed-secret', 'notes': 'changed notes',
                'shared_with': [3], 'user_id': 3, 'owner_id': 3,
            })
        return client.delete('/api/passwords/1', headers=headers or {})
    # Deliberately mismatch the service path and primary key: the object itself
    # determines authorization, even when the submitted path/body is crafted.
    return client.post(f'/{operation}_password/synthetic-unrelated-private-service', data={
        'pw_id': '1', 'username': 'synthetic-changed-login',
        'password': 'synthetic-changed-secret', 'notes': 'changed notes',
        'shared_users': ['3'], 'user_id': '3', 'owner_id': '3',
    })


def create_request(client, transport, headers=None):
    if transport == 'api':
        return client.post('/api/passwords', headers=headers or {}, json={
            'service_name': 'synthetic-created-service', 'username': 'created-login',
            'password': 'synthetic-created-secret', 'notes': 'created notes',
            'user_id': 3, 'owner_id': 3, 'shared_with': [2],
        })
    return client.post('/add_password', data={
        'service': 'synthetic-created-service', 'username': 'created-login',
        'password': 'synthetic-created-secret', 'notes': 'created notes',
        'user_id': '3', 'owner_id': '3', 'shared_users': ['2'],
    })


@pytest.mark.parametrize('role', ROLES)
@pytest.mark.parametrize('actor', ACTORS)
@pytest.mark.parametrize('transport', ['web', 'api'])
def test_dashboard_lists_only_owned_or_shared_passwords(vault_client, actor, role, transport):
    headers = prepare_actor(vault_client, actor, role, transport)
    response = vault_client.get('/dashboard' if transport == 'web' else '/api/dashboard',
                                headers=headers)
    assert response.status_code == 200
    allowed = actor in ('owner', 'shared')
    if transport == 'api':
        payload = response.get_json()
        assert payload['user']['id'] == ACTORS[actor]
        assert payload['user']['role'] == role
        assert {row['id'] for row in payload['passwords']} == ({1} if allowed else {2})
        if allowed:
            assert payload['passwords'][0]['password'] == TARGET_SECRET
        else:
            assert TARGET_SECRET not in response.get_data(as_text=True)
    else:
        assert (TARGET_SERVICE in response.get_data(as_text=True)) is allowed
        assert ('synthetic-unrelated-private-service' in response.get_data(as_text=True)) is not allowed
        with vault_client.session_transaction() as session:
            assert session['role'] == role


@pytest.mark.parametrize('role', ROLES)
@pytest.mark.parametrize('actor', ACTORS)
def test_select_reads_owned_or_shared_but_not_unrelated_passwords(vault_client, actor, role):
    prepare_actor(vault_client, actor, role, 'web')
    response = vault_client.get('/select_password_for_edit',
                                query_string={'service_name': TARGET_SERVICE})
    if actor in ('owner', 'shared'):
        assert response.status_code == 200
        assert TARGET_SECRET in response.get_data(as_text=True)
        assert 'synthetic-unrelated-private-secret' not in response.get_data(as_text=True)
        assert 'synthetic-unrelated-private-service' not in response.get_data(as_text=True)
    else:
        assert response.status_code == 302
        assert response.headers['Location'] == '/dashboard'
        assert TARGET_SECRET not in response.get_data(as_text=True)


@pytest.mark.parametrize('role', ROLES)
@pytest.mark.parametrize('actor', ACTORS)
@pytest.mark.parametrize('transport', ['web', 'api'])
@pytest.mark.parametrize('operation', ['update', 'delete'])
def test_only_owner_can_mutate_password_regardless_of_role(
        vault_client, actor, role, transport, operation):
    headers = prepare_actor(vault_client, actor, role, transport)
    before = vault_snapshot()
    with app.app_context():
        logs_before = audit_log.query.count()
    response = mutation_request(vault_client, transport, operation, headers)
    after = vault_snapshot()
    if actor != 'owner':
        assert after == before
        assert response.status_code == (302 if transport == 'web' else 404)
        with app.app_context():
            assert audit_log.query.count() == logs_before
        assert TARGET_SECRET not in response.get_data(as_text=True)
        return
    assert response.status_code == (302 if transport == 'web' else 200)
    assert after[-1] == before[-1], 'An unrelated password must remain unchanged'
    with app.app_context():
        target = db.session.get(Password, 1)
        if operation == 'delete':
            assert target is None
        else:
            assert target.user_id == 1, 'Crafted ownership fields cannot transfer ownership'
            assert target.username == 'synthetic-changed-login'
            assert target.notes == 'changed notes'
            assert Fernet(app.config['ENCRYPTION_KEY']).decrypt(target.password) == b'synthetic-changed-secret'
            assert {user.id for user in target.shared_users} == {3}


@pytest.mark.parametrize('role', ROLES)
@pytest.mark.parametrize('transport', ['web', 'api'])
def test_create_uses_authenticated_owner_and_ignores_crafted_ownership(vault_client, role, transport):
    headers = prepare_actor(vault_client, 'owner', role, transport)
    before = vault_snapshot()
    response = create_request(vault_client, transport, headers)
    assert response.status_code == (302 if transport == 'web' else 200)
    assert vault_snapshot()[:2] == before
    with app.app_context():
        created = Password.query.filter_by(service_name='synthetic-created-service').one()
        assert created.user_id == 1
        assert {user.id for user in created.shared_users} == {2}
        assert Fernet(app.config['ENCRYPTION_KEY']).decrypt(created.password) == b'synthetic-created-secret'


def prepare_invalid_identity(client, kind, transport):
    if kind == 'missing':
        return {}
    user_id = 999
    if kind == 'deleted':
        with app.app_context():
            user = User(username='SYNTHETIC_DELETED_USER', password='unused', role='admin')
            db.session.add(user)
            db.session.commit()
            user_id = user.id
    if transport == 'api':
        headers = token_headers(user_id)
    else:
        set_web_identity(client, user_id)
        headers = {}
    if kind == 'deleted':
        with app.app_context():
            db.session.delete(db.session.get(User, user_id))
            db.session.commit()
    return headers


@pytest.mark.parametrize('kind', ['missing', 'unknown', 'deleted'])
@pytest.mark.parametrize('operation', ['dashboard', 'select', 'create', 'update', 'delete'])
def test_web_denies_missing_unknown_or_deleted_identity(vault_client, kind, operation):
    prepare_invalid_identity(vault_client, kind, 'web')
    before = vault_snapshot()
    if operation == 'dashboard':
        response = vault_client.get('/dashboard')
    elif operation == 'select':
        response = vault_client.get('/select_password_for_edit',
                                    query_string={'service_name': TARGET_SERVICE})
    elif operation == 'create':
        response = create_request(vault_client, 'web')
    else:
        response = mutation_request(vault_client, 'web', operation)
    assert vault_snapshot() == before
    assert response.status_code == 302
    assert response.headers['Location'] == '/'
    assert TARGET_SECRET not in response.get_data(as_text=True)


@pytest.mark.parametrize('kind', ['missing', 'unknown', 'deleted'])
@pytest.mark.parametrize('operation', ['dashboard', 'create', 'update', 'delete'])
def test_api_denies_missing_unknown_or_deleted_identity(vault_client, kind, operation):
    headers = prepare_invalid_identity(vault_client, kind, 'api')
    before = vault_snapshot()
    if operation == 'dashboard':
        response = vault_client.get('/api/dashboard', headers=headers)
    elif operation == 'create':
        response = create_request(vault_client, 'api', headers)
    else:
        response = mutation_request(vault_client, 'api', operation, headers)
    assert vault_snapshot() == before, 'An invalid identity must never change vault records'
    assert response.status_code in (401, 404)
    assert TARGET_SECRET not in response.get_data(as_text=True)


@pytest.mark.parametrize('operation', ['create', 'update', 'delete'])
def test_real_web_mutations_require_csrf_even_for_owner(vault_client, monkeypatch, operation):
    prepare_actor(vault_client, 'owner', 'admin', 'web')
    monkeypatch.setitem(app.config, 'WTF_CSRF_ENABLED', True)
    before = vault_snapshot()
    response = (create_request(vault_client, 'web') if operation == 'create'
                else mutation_request(vault_client, 'web', operation))
    assert response.status_code == 400
    assert b'CSRF token is missing' in response.data
    assert vault_snapshot() == before


@pytest.mark.parametrize('transport', ['web', 'api'])
def test_share_revocation_removes_read_access_on_next_request(vault_client, transport):
    headers = prepare_actor(vault_client, 'shared', 'admin', transport)
    path = ('/select_password_for_edit?service_name=' + TARGET_SERVICE
            if transport == 'web' else '/api/dashboard')
    response = vault_client.get(path, headers=headers)
    assert response.status_code == 200
    assert TARGET_SECRET in response.get_data(as_text=True)
    with app.app_context():
        db.session.get(Password, 1).shared_users = []
        db.session.commit()
    response = vault_client.get(path, headers=headers)
    assert response.status_code == (302 if transport == 'web' else 200)
    assert TARGET_SECRET not in response.get_data(as_text=True)
    if transport == 'api':
        assert response.get_json()['passwords'] == []
