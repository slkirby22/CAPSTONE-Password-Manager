"""Actual route tests; public synthetic accounts only, no live credential files."""
import re

import pytest
from cryptography.fernet import Fernet
from flask_jwt_extended import create_access_token, decode_token

import functions
from app import app, limiter
from authorization import authentication_claims, credential_binding
from models import Password, User, db

OLD = 'Synthetic!99'
NEW = 'Changed!123'


@pytest.fixture
def clients(monkeypatch):
    assert app.config['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///:memory:'
    monkeypatch.setitem(app.config, 'TESTING', True)
    monkeypatch.setitem(app.config, 'WTF_CSRF_ENABLED', True)
    monkeypatch.setattr(limiter, 'enabled', False)
    with app.app_context():
        db.create_all()
        hashed = functions.pwd_context.hash(OLD)
        users = [User('ADMIN', hashed, 'admin'), User('TARGET', hashed, 'manager'),
                 User('OTHER', hashed, 'employee')]
        db.session.add_all(users)
        db.session.flush()
        db.session.add(Password('synthetic', 'public fixture',
            Fernet(app.config['ENCRYPTION_KEY']).encrypt(b'synthetic vault value'), '',
            users[1].id, shared_users=[users[2]]))
        db.session.commit()
    result = [app.test_client() for _ in range(4)]
    yield result
    with app.app_context():
        db.session.remove()
        db.drop_all()


def csrf(client):
    response = client.get('/login', base_url='https://localhost')
    if response.status_code == 302:
        response = client.get('/view_users', base_url='https://localhost')
    return re.search(r'name="csrf_token"[^>]*value="([^"]+)"', response.text)[1]


def post(client, path, data):
    return client.post(path, data={**data, 'csrf_token': csrf(client)},
                       base_url='https://localhost',
                       headers={'Referer': 'https://localhost/login'})


def login(client, username, password=OLD):
    response = post(client, '/login', {'username': username, 'password': password})
    assert response.status_code == 302
    assert response.location == '/dashboard'
    response = client.post('/api/login', json={'username': username, 'password': password})
    assert response.status_code == 200
    return response.json['access_token']


def api(client, token, path='/api/dashboard'):
    return client.get(path, headers={'Authorization': 'Bearer ' + token})


def state(user_id=2):
    with app.app_context():
        user = db.session.get(User, user_id)
        return user.username, user.password, user.auth_identity


def reset(client, password=NEW, username='TARGET'):
    return post(client, '/update_user/2', {'username': username, 'password': password,
                                          'role': 'manager'})


def replay_cookie(client, value):
    client.set_cookie(app.config['SESSION_COOKIE_NAME'], value, domain='localhost')


@pytest.mark.parametrize('actor_index', [0, 1])
@pytest.mark.parametrize('password', [NEW, OLD])
def test_self_and_admin_reset_revoke_all_copies_both_transports(clients, actor_index, password, monkeypatch):
    admin, target, second, other = clients
    admin_jwt = login(admin, 'ADMIN')
    first_jwt = login(target, 'TARGET')
    second_jwt = login(second, 'TARGET')
    # Employee has no user-management UI, so authenticate its cookie via ordinary login.
    other_jwt = login(other, 'OTHER')
    old_csrf = {target: csrf(target), second: csrf(second)}
    original_cookie = target.get_cookie('session').value
    copied_cookie = second.get_cookie('session').value
    before = state()
    with app.app_context():
        item_id = Password.query.one().item_id
    assert reset(clients[actor_index], password).status_code in (200, 302)
    after = state()
    assert before[1] != after[1]  # Re-entering the same password still re-salts.
    assert before[2] == after[2]  # Sharing/account incarnation never rotates.
    if actor_index == 1:
        with target.session_transaction() as session:
            assert 'user_id' not in session
    for client, cookie, token in [(target, original_cookie, first_jwt),
                                  (second, copied_cookie, second_jwt)]:
        for path in ['/get_audit_logs', '/dashboard', '/passwords/' + item_id]:
            replay_cookie(client, cookie)
            response = client.get(path)
            assert response.status_code == (401 if path == '/get_audit_logs' else 302)
            assert 'synthetic vault value' not in response.text
        replay_cookie(client, cookie)
        def forbidden(*args, **kwargs):
            pytest.fail('Revoked session must not decrypt a vault item')
        with monkeypatch.context() as patch:
            patch.setattr(Fernet, 'decrypt', forbidden)
            denied = client.post(f'/passwords/{item_id}/reveal',
                data={'csrf_token': old_csrf[client]}, base_url='https://localhost',
                headers={'Referer': 'https://localhost/dashboard'})
        assert denied.status_code == 401
        assert api(client, token).status_code == 401
        assert client.post('/api/logout', headers={'Authorization': 'Bearer ' + token}).status_code == 401
    assert api(admin, admin_jwt).status_code == 410
    assert admin.get('/get_audit_logs').status_code == 200
    assert api(other, other_jwt).status_code == 410
    assert other.get('/dashboard').status_code == 200
    new_jwt = login(target, 'TARGET', password)
    assert api(target, new_jwt).status_code == 410
    assert target.get('/dashboard').status_code == 200
    if password != OLD:
        assert clients[2].post('/api/login', json={'username': 'TARGET', 'password': OLD}).status_code == 401
    with app.app_context():
        item = Password.query.one()
        assert item.user_id == 2 and [u.id for u in item.shared_users] == [3]


@pytest.mark.parametrize('failure', ['short', 'no_digit', 'no_special', 'no_upper',
                                      'username_taken', 'hash', 'commit'])
def test_failed_reset_does_not_revoke_or_change_password(clients, monkeypatch, failure):
    admin, target, second, _ = clients
    login(admin, 'ADMIN')
    tokens = [login(target, 'TARGET'), login(second, 'TARGET')]
    before = state()
    passwords = {'short': 'S1!', 'no_digit': 'Synthetic!',
                 'no_special': 'Synthetic99', 'no_upper': 'synthetic!99'}
    with monkeypatch.context() as patch:
        if failure == 'hash':
            def fail_hash(*args, **kwargs):
                raise RuntimeError('synthetic hash failure')
            patch.setattr(functions.pwd_context, 'hash', fail_hash)
        if failure == 'commit':
            def fail_commit():
                db.session.flush()
                raise RuntimeError('synthetic commit failure')
            patch.setattr(db.session, 'commit', fail_commit)
        response = reset(admin, passwords.get(failure, NEW),
                         'ADMIN' if failure == 'username_taken' else 'TARGET')
    assert response.status_code == (500 if failure in ('hash', 'commit') else 200)
    assert state() == before
    for client, token in zip((target, second), tokens):
        assert client.get('/dashboard').status_code == 200
        assert api(client, token).status_code == 410


def test_blank_password_profile_edit_preserves_other_sessions(clients):
    admin, target, second, _ = clients
    login(admin, 'ADMIN')
    token = login(target, 'TARGET')
    login(second, 'TARGET')
    before = state()
    assert reset(admin, '', 'RENAMED').status_code == 200
    assert state()[1:] == before[1:]
    assert target.get('/dashboard').status_code == 200
    assert second.get('/dashboard').status_code == 200
    assert api(target, token).status_code == 410


@pytest.mark.parametrize('bad', [None, '', '0' * 64, 'A' * 64, 'g' * 64, 'a' * 63,
                                 'a' * 65, 0, [], {}, '\u2603' * 64])
@pytest.mark.parametrize('transport', ['web', 'jwt'])
def test_missing_legacy_or_invalid_credential_binding_fails_closed(clients, bad, transport):
    client = clients[0]
    token = login(client, 'ADMIN')
    if transport == 'web':
        with client.session_transaction() as session:
            session.pop('credential_binding')
            if bad is not None:
                session['credential_binding'] = bad
        assert client.get('/get_audit_logs').status_code == 401
        with client.session_transaction() as session:
            assert not session
    else:
        with app.app_context():
            user = db.session.get(User, 1)
            claims = {'auth_identity': user.auth_identity}
            if bad is not None:
                claims['credential_binding'] = bad
            token = create_access_token(identity='1', additional_claims=claims)
        assert api(client, token).status_code == 401


def test_binding_is_keyed_domain_separated_and_contains_no_password_hash(clients, monkeypatch):
    client = clients[0]
    token = login(client, 'ADMIN')
    with app.app_context():
        user = db.session.get(User, 1)
        claims = decode_token(token)
        assert claims['credential_binding'] == credential_binding(user, 'jwt')
        assert claims['credential_binding'] != credential_binding(user, 'web')
        assert user.password not in str(claims)
        assert len(claims['credential_binding']) == 64
        with monkeypatch.context() as patch:
            patch.setitem(app.config, 'JWT_SECRET_KEY', app.config['SECRET_KEY'])
            assert credential_binding(user, 'jwt') != credential_binding(user, 'web')
        # Two accounts share the synthetic hash, but never the account binding.
        other = db.session.get(User, 2)
        assert user.password == other.password
        assert credential_binding(user, 'web') != credential_binding(other, 'web')
    with client.session_transaction() as session:
        assert session['credential_binding'] != claims['credential_binding']
        assert user.password not in str(dict(session))


def test_lock_unlock_do_not_change_existing_session_policy(clients):
    admin, target, second, _ = clients
    login(admin, 'ADMIN')
    first, second_token = login(target, 'TARGET'), login(second, 'TARGET')
    before = state()
    for operation in ('lock', 'unlock'):
        assert post(admin, f'/{operation}_account/2', {}).status_code == 200
        assert state() == before
        assert target.get('/dashboard').status_code == 200
        assert second.get('/dashboard').status_code == 200
        assert api(target, first).status_code == 410
        assert api(second, second_token).status_code == 410
        response = clients[3].post('/api/login', json={'username': 'TARGET', 'password': OLD})
        assert response.status_code == (401 if operation == 'lock' else 200)


def test_logout_scope_is_unchanged(clients):
    _, target, second, _ = clients
    first, second_token = login(target, 'TARGET'), login(second, 'TARGET')
    cookie = target.get_cookie('session').value
    assert target.get('/logout').status_code == 302
    # Existing policy intentionally does not centrally revoke copied web cookies.
    replay_cookie(target, cookie)
    assert target.get('/dashboard').status_code == 200
    assert second.get('/dashboard').status_code == 200
    assert api(target, first).status_code == 410
    assert target.post('/api/logout', headers={'Authorization': 'Bearer ' + first}).status_code == 200
    assert api(target, first).status_code == 401
    assert api(second, second_token).status_code == 410
    assert target.get('/dashboard').status_code == 200


def test_repeated_resets_revoke_credentials_issued_between_them(clients):
    admin, target, _, _ = clients
    login(admin, 'ADMIN')
    old = login(target, 'TARGET')
    assert reset(admin).status_code == 200
    middle = login(target, 'TARGET', NEW)
    middle_cookie = target.get_cookie('session').value
    assert reset(admin, 'Second-change!456').status_code == 200
    replay_cookie(target, middle_cookie)
    assert target.get('/dashboard').status_code == 302
    assert api(target, old).status_code == 401
    assert api(target, middle).status_code == 401
    latest = login(target, 'TARGET', 'Second-change!456')
    assert api(target, latest).status_code == 410
