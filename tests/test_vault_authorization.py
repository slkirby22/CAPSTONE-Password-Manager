"""Object-level vault access through real routes and disposable synthetic data."""
from auth_helpers import auth_identity_for
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
        session['auth_identity'] = auth_identity_for(client, user_id)
        session['username'] = 'UNTRUSTED_CACHED_USERNAME'
        session['role'] = cached_role


def token_headers(user_id):
    with app.app_context():
        user = db.session.get(User, user_id)
        token = create_access_token(identity=str(user_id), additional_claims={
            'auth_identity': user.auth_identity if user else '0' * 32})
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


def item_id_for(password_id=1):
    with app.app_context():
        return db.session.get(Password, password_id).item_id


def share_identity(user_id):
    with app.app_context():
        return db.session.get(User, user_id).auth_identity


def mutation_request(client, transport, operation, headers=None):
    if transport == 'api':
        if operation == 'update':
            return client.patch('/api/passwords/1', headers=headers or {}, json={
                'username': 'synthetic-changed-login',
                'password': 'synthetic-changed-secret', 'notes': 'changed notes',
                'shared_with': [3], 'user_id': 3, 'owner_id': 3,
            })
        return client.delete('/api/passwords/1', headers=headers or {})
    return client.post(f'/passwords/{item_id_for()}/{operation}', data={
        'username': 'synthetic-changed-login', 'replace_password': '1',
        'password': 'synthetic-changed-secret', 'notes': 'changed notes',
        'shared_users': [share_identity(3)], 'user_id': '3', 'owner_id': '3',
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
        'user_id': '3', 'owner_id': '3', 'shared_users': [share_identity(2)],
    })


@pytest.mark.parametrize('role', ROLES)
@pytest.mark.parametrize('actor', ACTORS)
@pytest.mark.parametrize('transport', ['web', 'api'])
def test_dashboard_lists_only_owned_or_shared_passwords(vault_client, actor, role, transport):
    headers = prepare_actor(vault_client, actor, role, transport)
    response = vault_client.get('/dashboard' if transport == 'web' else '/api/dashboard',
                                headers=headers)
    allowed = actor in ('owner', 'shared')
    assert TARGET_SECRET not in response.get_data(as_text=True)
    if transport == 'api':
        assert response.status_code == 410
    else:
        assert response.status_code == 200
        assert (TARGET_SERVICE in response.get_data(as_text=True)) is allowed
        assert ('synthetic-unrelated-private-service' in response.get_data(as_text=True)) is not allowed
        with vault_client.session_transaction() as session:
            assert session['role'] == role


@pytest.mark.parametrize('role', ROLES)
@pytest.mark.parametrize('actor', ACTORS)
def test_detail_and_reveal_allow_owned_or_shared_but_not_unrelated(vault_client, actor, role):
    prepare_actor(vault_client, actor, role, 'web')
    item_id = item_id_for()
    response = vault_client.get(f'/passwords/{item_id}')
    assert response.status_code == (200 if actor in ('owner', 'shared') else 404)
    assert TARGET_SECRET not in response.get_data(as_text=True)
    assert 'synthetic-unrelated-private-secret' not in response.get_data(as_text=True)
    response = vault_client.post(f'/passwords/{item_id}/reveal')
    if actor in ('owner', 'shared'):
        assert response.status_code == 200
        assert response.get_json() == {'item_id': item_id, 'password': TARGET_SECRET}
    else:
        assert response.status_code == 404
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
    if transport == 'api' or actor != 'owner':
        assert after == before
        assert response.status_code == (404 if transport == 'web' else 410)
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
    if transport == 'api':
        assert response.status_code == 410
        assert vault_snapshot() == before
        return
    assert response.status_code == 302
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
@pytest.mark.parametrize('operation', ['dashboard', 'detail', 'reveal', 'select', 'create', 'update', 'delete'])
def test_web_denies_missing_unknown_or_deleted_identity(vault_client, kind, operation):
    prepare_invalid_identity(vault_client, kind, 'web')
    before = vault_snapshot()
    if operation == 'dashboard':
        response = vault_client.get('/dashboard')
    elif operation == 'detail':
        response = vault_client.get(f'/passwords/{item_id_for()}')
    elif operation == 'reveal':
        response = vault_client.post(f'/passwords/{item_id_for()}/reveal')
    elif operation == 'select':
        response = vault_client.get('/select_password_for_edit',
                                    query_string={'service_name': TARGET_SERVICE})
    elif operation == 'create':
        response = create_request(vault_client, 'web')
    else:
        response = mutation_request(vault_client, 'web', operation)
    assert vault_snapshot() == before
    assert response.status_code == (401 if operation == 'reveal' else 302)
    if operation != 'reveal':
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


@pytest.mark.parametrize('operation', ['create', 'update', 'delete', 'reveal'])
def test_real_web_mutations_require_csrf_even_for_owner(vault_client, monkeypatch, operation):
    prepare_actor(vault_client, 'owner', 'admin', 'web')
    monkeypatch.setitem(app.config, 'WTF_CSRF_ENABLED', True)
    before = vault_snapshot()
    response = (vault_client.post(f'/passwords/{item_id_for()}/reveal') if operation == 'reveal'
                else create_request(vault_client, 'web') if operation == 'create'
                else mutation_request(vault_client, 'web', operation))
    assert response.status_code == 400
    assert b'CSRF token is missing' in response.data
    assert vault_snapshot() == before


def test_share_revocation_removes_read_access_on_next_request(vault_client):
    prepare_actor(vault_client, 'shared', 'admin', 'web')
    path = f'/passwords/{item_id_for()}'
    assert vault_client.get(path).status_code == 200
    response = vault_client.post(path + '/reveal')
    assert response.status_code == 200
    assert response.get_json()['password'] == TARGET_SECRET
    with app.app_context():
        db.session.get(Password, 1).shared_users = []
        db.session.commit()
    for response in (vault_client.get(path), vault_client.post(path + '/reveal')):
        assert response.status_code == 404
        assert TARGET_SECRET not in response.get_data(as_text=True)


@pytest.mark.parametrize('path,method', [
    ('/select_password_for_edit?service_name=' + TARGET_SERVICE, 'get'),
    ('/select_password_for_edit', 'post'),
    ('/update_password/' + TARGET_SERVICE, 'post'),
    ('/delete_password/' + TARGET_SERVICE, 'post'),
])
def test_legacy_service_routes_retired_without_mutation(vault_client, path, method):
    prepare_actor(vault_client, 'owner', 'admin', 'web')
    before = vault_snapshot()
    response = getattr(vault_client, method)(path)
    assert response.status_code == 410
    assert vault_snapshot() == before
    assert TARGET_SECRET not in response.get_data(as_text=True)


@pytest.mark.parametrize('operation', ['update', 'delete'])
@pytest.mark.parametrize('field', ['pw_id', 'item_id', 'id'])
def test_mutation_rejects_body_identity_even_if_it_matches(vault_client, operation, field):
    prepare_actor(vault_client, 'owner', 'admin', 'web')
    before = vault_snapshot()
    response = vault_client.post(f'/passwords/{item_id_for()}/{operation}', data={
        field: '1' if field == 'pw_id' else item_id_for(),
        'username': 'attempted-change',
    })
    assert response.status_code == 400
    assert vault_snapshot() == before


@pytest.mark.parametrize('item_id', ['1', '0', 'not-an-id', 'A' * 32, '0' * 31, '0' * 33, '0' * 32])
@pytest.mark.parametrize('operation', ['detail', 'reveal', 'update', 'delete'])
def test_invalid_or_unknown_path_identity_is_opaque(vault_client, item_id, operation):
    prepare_actor(vault_client, 'owner', 'admin', 'web')
    before = vault_snapshot()
    path = f'/passwords/{item_id}'
    response = (vault_client.get(path) if operation == 'detail'
                else vault_client.post(path + '/' + operation, data={'username': 'attempted-change'}))
    assert response.status_code == 404
    assert vault_snapshot() == before
    assert TARGET_SECRET not in response.get_data(as_text=True)


@pytest.mark.parametrize('actor', ['owner', 'shared'])
def test_metadata_template_context_never_contains_secrets_or_models(vault_client, monkeypatch, actor):
    prepare_actor(vault_client, actor, 'employee', 'web')
    contexts = []

    def forbidden_decrypt(*args, **kwargs):
        raise AssertionError('Metadata rendering must not decrypt')

    def capture_render(template, **context):
        contexts.append(context)
        return 'rendered'

    def check_metadata(value):
        assert not isinstance(value, (Password, User))
        assert not isinstance(value, bytes)
        if isinstance(value, dict):
            assert not ({'password', 'ciphertext', 'encrypted_password', 'pw_id'} & value.keys())
            for nested in value.values():
                check_metadata(nested)
        elif isinstance(value, (list, tuple)):
            for nested in value:
                check_metadata(nested)

    monkeypatch.setattr(Fernet, 'decrypt', forbidden_decrypt)
    monkeypatch.setattr('functions.render_template', capture_render)
    assert vault_client.get('/dashboard').status_code == 200
    assert vault_client.get(f'/passwords/{item_id_for()}').status_code == 200
    assert len(contexts) == 2
    for context in contexts:
        check_metadata(context)
        assert TARGET_SECRET not in repr(context)
        assert 'gAAAA' not in repr(context)


def test_duplicate_service_names_cannot_select_or_mutate_wrong_item(vault_client):
    prepare_actor(vault_client, 'owner', 'employee', 'web')
    with app.app_context():
        duplicate = Password(user_id=1, service_name=TARGET_SERVICE,
                             username='second-login', notes='second notes',
                             password=Fernet(app.config['ENCRYPTION_KEY']).encrypt(b'second-secret'))
        db.session.add(duplicate)
        db.session.commit()
        duplicate_id = duplicate.item_id
        original_id = db.session.get(Password, 1).item_id
    assert original_id != duplicate_id
    response = vault_client.post(f'/passwords/{duplicate_id}/reveal')
    assert response.get_json() == {'item_id': duplicate_id, 'password': 'second-secret'}
    response = vault_client.post(f'/passwords/{original_id}/update', data={'username': 'updated-first'})
    assert response.status_code == 302
    with app.app_context():
        assert Password.query.filter_by(item_id=duplicate_id).one().username == 'second-login'
        assert Password.query.filter_by(item_id=original_id).one().username == 'updated-first'
