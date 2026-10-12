"""Retired vault contracts against shipped routes, with no decrypt or writes."""
import sys
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jwt
import pytest
from cryptography.fernet import Fernet
from authorization import authentication_claims
from flask_jwt_extended import create_access_token
from sqlalchemy import event

from api_functions import retired_vault_api
from app import app, limiter
from models import Password, User, db

RETIRED = {
    'error': 'vault_api_retired',
    'message': ('Vault API retired. Use the web interface; this version does not '
                'support the historical mobile client.'),
}
ENDPOINTS = [
    ('GET', '/api/dashboard'),
    ('POST', '/api/passwords'),
    ('PATCH', '/api/passwords/1'),
    ('DELETE', '/api/passwords/1'),
]


@pytest.fixture
def vault_client(monkeypatch):
    monkeypatch.setitem(app.config, 'TESTING', True)
    # Leave CSRF enabled: shipped API exemptions, not test bypasses, must work.
    monkeypatch.setitem(app.config, 'WTF_CSRF_ENABLED', True)
    monkeypatch.setattr(limiter, 'enabled', False)
    with app.app_context():
        assert db.engine.url.get_backend_name() == 'sqlite'
        assert db.engine.url.database == ':memory:'
        db.create_all()
        users = [User(name, 'unused synthetic hash', role) for name, role in [
            ('OWNER', 'employee'), ('SHARED', 'employee'),
            ('OUTSIDER', 'employee'), ('ADMIN', 'admin')]]
        db.session.add_all(users)
        db.session.flush()
        db.session.add(Password('synthetic service', 'synthetic username',
                               Fernet(app.config['ENCRYPTION_KEY']).encrypt(b'synthetic vault secret'),
                               'synthetic notes', users[0].id, [users[1]]))
        db.session.commit()
    try:
        yield app.test_client()
    finally:
        with app.app_context():
            db.session.remove()
            db.drop_all()


def token_for(username='OWNER', **kwargs):
    with app.app_context():
        user = User.query.filter_by(username=username).one()
        return create_access_token(identity=str(user.id),
                                   additional_claims=authentication_claims(user, 'jwt'), **kwargs)


def snapshot():
    with app.app_context():
        return {table.name: [tuple(row) for row in db.session.execute(table.select()).all()]
                for table in db.metadata.sorted_tables}


def assert_read_only_response(client, monkeypatch, method, path, token=None, expected=410,
                              body='{"password":"attempted replacement"}'):
    before = snapshot()
    def forbidden_decrypt(*args, **kwargs):
        pytest.fail('Retired API must never decrypt a vault secret')
    monkeypatch.setattr(Fernet, 'decrypt', forbidden_decrypt)
    def forbid_writes(connection, cursor, statement, parameters, context, executemany):
        assert statement.lstrip().split()[0].upper() not in {'INSERT', 'UPDATE', 'DELETE'}, statement
    with app.app_context():
        engine = db.engine
    event.listen(engine, 'before_cursor_execute', forbid_writes)
    try:
        response = client.open(path, method=method,
                               headers={'Authorization': f'Bearer {token}'} if token else {},
                               data=body, content_type='application/json')
    finally:
        event.remove(engine, 'before_cursor_execute', forbid_writes)
    assert response.status_code == expected
    assert response.is_json
    if expected == 410:
        assert response.get_json() == RETIRED
    else:
        assert response.get_json().get('error') != RETIRED['error']
    assert b'synthetic vault secret' not in response.data
    assert b'synthetic notes' not in response.data
    assert snapshot() == before
    return response


def test_retirement_helper_is_context_free():
    assert retired_vault_api() == (RETIRED, 410)


@pytest.mark.parametrize('method,path', ENDPOINTS)
@pytest.mark.parametrize('username', ['OWNER', 'SHARED', 'OUTSIDER', 'ADMIN'])
def test_valid_current_jwt_gets_retirement_without_data_or_mutation(vault_client, monkeypatch,
                                                                  method, path, username):
    assert_read_only_response(vault_client, monkeypatch, method, path, token_for(username))


@pytest.mark.parametrize('method,path', ENDPOINTS)
@pytest.mark.parametrize('kind', ['missing', 'malformed', 'wrong-key', 'expired', 'revoked',
                                  'legacy', 'stale', 'deleted', 'reused'])
def test_authentication_still_precedes_retirement(vault_client, monkeypatch, method, path, kind):
    token = token_for('ADMIN')
    expected = 401
    if kind == 'missing':
        token = None
    elif kind == 'malformed':
        token, expected = 'not.a.valid.jwt', 422
    elif kind == 'wrong-key':
        token = jwt.encode({'sub': '4'}, 'synthetic-wrong-key-000000000000000000', algorithm='HS256')
        expected = 422
    elif kind == 'expired':
        token = token_for('ADMIN', expires_delta=timedelta(seconds=-1))
    elif kind == 'revoked':
        response = vault_client.post('/api/logout', headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200
    elif kind == 'legacy':
        with app.app_context():
            token = create_access_token(identity='4')
    elif kind == 'stale':
        with app.app_context():
            User.query.filter_by(username='ADMIN').one().auth_identity = uuid4().hex
            db.session.commit()
    elif kind in ('deleted', 'reused'):
        with app.app_context():
            old = User.query.filter_by(username='ADMIN').one()
            old_id = old.id
            db.session.delete(old)
            db.session.commit()
            if kind == 'reused':
                replacement = User('REPLACEMENT', 'unused synthetic hash', 'admin')
                db.session.add(replacement)
                db.session.commit()
                assert replacement.id == old_id, 'Exercise actual SQLite ID reuse'
    assert_read_only_response(vault_client, monkeypatch, method, path, token, expected)


@pytest.mark.parametrize('method,path', ENDPOINTS)
def test_web_cookie_never_authorizes_retired_api(vault_client, monkeypatch, method, path):
    with app.app_context():
        user = User.query.filter_by(username='OWNER').one()
        user_id, claims = user.id, authentication_claims(user, 'web')
    with vault_client.session_transaction() as session:
        session.update(user_id=user_id, **claims, username='OWNER', role='employee')
    assert_read_only_response(vault_client, monkeypatch, method, path, expected=401)


@pytest.mark.parametrize('method,path', ENDPOINTS)
@pytest.mark.parametrize('body', ['{', 'null', '[]', ''])
def test_retired_vault_does_not_parse_or_validate_payload(vault_client, monkeypatch, method, path, body):
    assert_read_only_response(vault_client, monkeypatch, method, path, token_for(), body=body)


@pytest.mark.parametrize('method', ['PATCH', 'DELETE'])
@pytest.mark.parametrize('selector', ['999999999', 'synthetic-service', 'not-a-public-id'])
def test_retirement_does_not_resolve_item_selector(vault_client, monkeypatch, method, selector):
    assert_read_only_response(vault_client, monkeypatch, method, f'/api/passwords/{selector}', token_for())


def test_no_api_reveal_route_is_added(vault_client, monkeypatch):
    monkeypatch.setattr(Fernet, 'decrypt', lambda *args: pytest.fail('No API reveal exists'))
    response = vault_client.post('/api/passwords/1/reveal', headers={
        'Authorization': f'Bearer {token_for()}'})
    assert response.status_code == 404
