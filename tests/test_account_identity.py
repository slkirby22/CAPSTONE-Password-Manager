"""Real-route account incarnation regressions; disposable synthetic values only."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from cryptography.fernet import Fernet
from flask_jwt_extended import create_access_token, decode_token

from app import app, limiter
from functions import pwd_context
from models import Password, User, audit_log, db


@pytest.fixture
def clients(monkeypatch):
    assert app.config['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///:memory:'
    monkeypatch.setitem(app.config, 'TESTING', True)
    monkeypatch.setitem(app.config, 'WTF_CSRF_ENABLED', False)
    monkeypatch.setattr(limiter, 'enabled', False)
    with app.app_context():
        db.create_all()
        hashed = pwd_context.hash('Synthetic!99')
        db.session.add_all([User('ADMIN', hashed, 'admin'), User('OLD', hashed, 'employee')])
        db.session.commit()
    try:
        yield app.test_client(), app.test_client()
    finally:
        with app.app_context():
            db.session.remove()
            db.drop_all()


def login(client, username):
    response = client.post('/login', data={'username': username, 'password': 'Synthetic!99'})
    assert response.status_code == 302
    response = client.post('/api/login', json={'username': username, 'password': 'Synthetic!99'})
    assert response.status_code == 200
    assert isinstance(response.json['user_id'], int)
    return {'Authorization': 'Bearer ' + response.json['access_token']}


def test_deleted_account_credentials_never_become_replacement_account(clients):
    admin, old = clients
    login(admin, 'ADMIN')
    old_headers = login(old, 'OLD')
    with old.session_transaction() as session:
        old_session = dict(session)
    assert old.get('/api/dashboard', headers=old_headers).status_code == 200
    assert admin.post('/delete_user/2').status_code == 302
    assert old.get('/api/dashboard', headers=old_headers).status_code == 401
    assert admin.post('/create_user', data={
        'username': 'NEW', 'password': 'Synthetic!99', 'role': 'admin'}).status_code == 302
    with app.app_context():
        replacement = User.query.filter_by(username='NEW').one()
        assert replacement.id == 2, 'Exercise actual SQLite row-ID reuse'
        db.session.add(Password('replacement-vault', 'synthetic',
            Fernet(app.config['ENCRYPTION_KEY']).encrypt(b'synthetic replacement secret'), '', replacement.id))
        db.session.commit()
    assert old.get('/api/dashboard', headers=old_headers).status_code == 401
    # Replay the issued cookie even after the server has cleared another stale copy.
    with old.session_transaction() as session:
        session.clear()
        session.update(old_session)
    assert old.get('/get_audit_logs').status_code == 401
    with old.session_transaction() as session:
        assert 'user_id' not in session
    replacement_headers = login(old, 'NEW')
    assert old.get('/api/dashboard', headers=replacement_headers).status_code == 200
    assert old.get('/get_audit_logs').status_code == 200


@pytest.mark.parametrize('binding', [None, '', 'x', 1, [], {}, '0' * 32])
def test_legacy_or_mismatched_web_binding_fails_closed(clients, binding):
    client, _ = clients
    with client.session_transaction() as session:
        session.update(user_id=1, username='ADMIN', role='admin')
        if binding is not None:
            session['auth_identity'] = binding
    assert client.get('/get_audit_logs').status_code == 401
    # Invalid sessions must not redirect /login back to a protected-route loop.
    assert client.get('/login').status_code == 200


@pytest.mark.parametrize('binding', [None, '', 'x', 1, [], {}, '0' * 32])
def test_legacy_or_mismatched_jwt_binding_fails_closed(clients, binding):
    client, _ = clients
    with app.app_context():
        claims = {} if binding is None else {'auth_identity': binding}
        token = create_access_token(identity='1', additional_claims=claims)
    assert client.get('/api/dashboard', headers={'Authorization': f'Bearer {token}'}).status_code == 401


def test_login_binds_both_transports_and_current_role_remains_authoritative(clients):
    client, _ = clients
    headers = login(client, 'ADMIN')
    with app.app_context():
        user = db.session.get(User, 1)
        identity = user.auth_identity
        claims = decode_token(headers['Authorization'][7:])
        assert claims['sub'] == '1'
        assert claims['auth_identity'] == identity
        assert len(identity) == 32
        user.role = 'employee'
        db.session.commit()
    with client.session_transaction() as session:
        assert session['auth_identity'] == identity
    assert client.get('/get_audit_logs').status_code == 403
    response = client.get('/api/dashboard', headers=headers)
    assert response.status_code == 200
    assert response.json['user']['role'] == 'employee'
    assert client.get('/logout').status_code == 302
    with client.session_transaction() as session:
        assert 'auth_identity' not in session


@pytest.mark.parametrize('kind', ['legacy', 'deleted-recreated'])
def test_stale_logout_cannot_attribute_events_to_replacement(clients, kind):
    client, _ = clients
    if kind == 'legacy':
        with client.session_transaction() as session:
            session.update(user_id=2, username='OLD', role='employee')
    else:
        login(client, 'OLD')
        with app.app_context():
            # Match deletion's audit disassociation while retaining the cookie.
            audit_log.query.filter_by(user_id=2).update({'user_id': None})
            db.session.delete(db.session.get(User, 2))
            db.session.commit()
            db.session.add(User('REPLACEMENT', 'unused', 'admin'))
            db.session.commit()
            assert User.query.filter_by(username='REPLACEMENT').one().id == 2
    with app.app_context():
        before = audit_log.query.count()
    assert client.get('/logout').status_code == 302
    with app.app_context():
        assert audit_log.query.count() == before
    with client.session_transaction() as session:
        assert not session
