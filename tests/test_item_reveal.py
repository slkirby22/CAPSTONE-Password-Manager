"""Actual-route synthetic reveal, metadata and stale-incarnation regressions."""
import re
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from flask import template_rendered
from sqlalchemy import event

import functions
from auth_helpers import credential_binding_for
from app import app, limiter
from models import Password, User, db


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setitem(app.config, 'TESTING', True)
    monkeypatch.setitem(app.config, 'PROPAGATE_EXCEPTIONS', False)
    monkeypatch.setitem(app.config, 'WTF_CSRF_ENABLED', False)
    monkeypatch.setattr(limiter, 'enabled', False)
    with app.app_context():
        db.create_all()
        users = [User(username=name, password='unused', role='employee')
                 for name in ('OWNER', 'SHARED', 'OTHER')]
        db.session.add_all(users)
        db.session.flush()
        cipher = Fernet(app.config['ENCRYPTION_KEY'])
        rows = [Password(service_name='duplicate', username=f'login-{i}',
                         password=cipher.encrypt(f'synthetic-secret-{i}'.encode()),
                         notes='metadata', user_id=1, shared_users=[users[1]])
                for i in range(2)]
        db.session.add_all(rows)
        db.session.commit()
        identities = [u.auth_identity for u in users]
        items = [row.item_id for row in rows]
    c = app.test_client()
    c.items = items
    c.identities = identities
    with c.session_transaction() as s:
        s['user_id'] = 1
        s['auth_identity'] = identities[0]
        s['credential_binding'] = credential_binding_for(c, 1)
    yield c
    with app.app_context():
        db.session.remove()
        db.drop_all()


def forbid_decrypt(monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail('Decrypt must not be reached')
    monkeypatch.setattr(Fernet, 'decrypt', fail)


@pytest.mark.parametrize('detail', [False, True])
def test_metadata_projection_does_not_load_or_decrypt_secret(client, monkeypatch, detail):
    with app.app_context():
        Password.query.update({'password': b'corrupt-synthetic-ciphertext'})
        db.session.commit()
        engine = db.engine
    forbid_decrypt(monkeypatch)
    statements, contexts = [], []
    def sql(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)
    def capture(sender, template, context, **extra):
        contexts.append(context)
    event.listen(engine, 'before_cursor_execute', sql)
    template_rendered.connect(capture, app)
    try:
        response = client.get('/passwords/' + client.items[0] if detail else '/dashboard')
    finally:
        event.remove(engine, 'before_cursor_execute', sql)
        template_rendered.disconnect(capture, app)
    assert response.status_code == 200
    assert b'corrupt-synthetic-ciphertext' not in response.data
    assert b'synthetic-secret' not in response.data
    assert contexts
    for context in contexts:
        assert all(set(row) == {'item_id', 'service_name', 'username', 'notes', 'can_edit'}
                   for row in context['passwords'])
        if detail:
            assert set(context['selected_password']) == {
                'item_id', 'service_name', 'username', 'notes', 'can_edit', 'shared_users'}
    assert not any('password.password' in sql for sql in statements)


def test_duplicate_names_reveal_exact_one_item(client, monkeypatch):
    real = Fernet.decrypt
    calls = []
    def counted(self, token, *args, **kwargs):
        calls.append(token)
        return real(self, token, *args, **kwargs)
    monkeypatch.setattr(Fernet, 'decrypt', counted)
    for i, item in enumerate(client.items):
        response = client.post(f'/passwords/{item}/reveal')
        assert response.status_code == 200
        assert response.json == {'item_id': item, 'password': f'synthetic-secret-{i}'}
    assert len(calls) == 2


@pytest.mark.parametrize('change', ['share', 'item', 'actor'])
def test_list_then_revocation_denies_without_decrypt(client, monkeypatch, change):
    with client.session_transaction() as s:
        s['user_id'] = 2
        s['auth_identity'] = client.identities[1]
        s['credential_binding'] = credential_binding_for(client, 2)
    assert client.get('/dashboard').status_code == 200
    with app.app_context():
        item = Password.query.filter_by(item_id=client.items[0]).one()
        if change == 'share':
            item.shared_users = []
        elif change == 'item':
            db.session.delete(item)
        else:
            item.shared_users = []
            Password.query.filter_by(item_id=client.items[1]).one().shared_users = []
            db.session.delete(db.session.get(User, 2))
        db.session.commit()
    forbid_decrypt(monkeypatch)
    response = client.post(f'/passwords/{client.items[0]}/reveal')
    assert response.status_code == (401 if change == 'actor' else 404)


@pytest.mark.parametrize('operation', ['detail', 'reveal', 'update', 'delete'])
def test_reused_numeric_item_never_revives_old_reference(client, monkeypatch, operation):
    old_id = client.items[0]
    with app.app_context():
        row = Password.query.filter_by(item_id=old_id).one()
        numeric_id = row.id
        db.session.delete(row)
        db.session.commit()
        replacement = Password(service_name='duplicate', username='new',
                               password=b'never decrypt', notes='', user_id=1)
        replacement.id = numeric_id
        db.session.add(replacement)
        db.session.commit()
        assert replacement.item_id != old_id
    forbid_decrypt(monkeypatch)
    path = f'/passwords/{old_id}'
    response = client.get(path) if operation == 'detail' else client.post(
        path + '/' + operation, data={'username': 'changed'})
    assert response.status_code == 404
    with app.app_context():
        assert db.session.get(Password, numeric_id).username == 'new'


@pytest.mark.parametrize('selector', ['1', '-1', 'duplicate', 'X'*32, 'a'*31, 'a'*33])
def test_malformed_selector_never_decrypts(client, monkeypatch, selector):
    forbid_decrypt(monkeypatch)
    assert client.post(f'/passwords/{selector}/reveal').status_code == 404


def test_reveal_is_post_and_actual_csrf_protected(client, monkeypatch):
    monkeypatch.setitem(app.config, 'WTF_CSRF_ENABLED', True)
    path = f'/passwords/{client.items[0]}/reveal'
    assert client.get(path).status_code == 405
    assert client.post(path).status_code == 400
    html = client.get('/passwords/' + client.items[0]).get_data(as_text=True)
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html).group(1)
    response = client.post(path, headers={'X-CSRFToken': token})
    assert response.status_code == 200
    assert response.json['password'] == 'synthetic-secret-0'


def test_corrupt_ciphertext_generic_failure_and_no_store(client, caplog):
    with app.app_context():
        Password.query.filter_by(item_id=client.items[0]).update({'password': b'private-corrupt-bytes'})
        db.session.commit()
    response = client.post(f'/passwords/{client.items[0]}/reveal')
    assert response.status_code == 500
    assert response.json == {'error': 'Unable to reveal item'}
    assert b'private-corrupt' not in response.data
    assert 'private-corrupt' not in caplog.text
    assert response.headers['Cache-Control'] == 'no-store'


@pytest.mark.parametrize('path,method', [('/dashboard', 'get'), ('/logout', 'get'),
    ('/select_password_for_edit?service_name=duplicate', 'get'),
    ('/update_password/duplicate', 'post'), ('/api/dashboard', 'get'),
    ('/passwords/missing/reveal', 'post'), ('/missing', 'get')])
def test_no_store_even_errors_retirement_redirects(client, path, method):
    assert getattr(client, method)(path).headers['Cache-Control'] == 'no-store'


@pytest.mark.parametrize('operation', ['add', 'update'])
def test_stale_share_form_never_grants_reused_account(client, operation):
    stale = client.identities[1]
    with app.app_context():
        for row in Password.query.all():
            row.shared_users = []
        db.session.delete(db.session.get(User, 2))
        db.session.commit()
        replacement = User(username='REPLACEMENT', password='unused', role='employee')
        replacement.id = 2
        db.session.add(replacement)
        db.session.commit()
        assert replacement.auth_identity != stale
    data = {'service': 'new', 'username': 'changed', 'password': 'replacement',
            'shared_users': [stale]}
    path = '/add_password' if operation == 'add' else f'/passwords/{client.items[0]}/update'
    assert client.post(path, data=data).status_code == 400
    with app.app_context():
        assert Password.query.count() == 2
        assert all(not row.shared_users for row in Password.query.all())
        assert Password.query.filter_by(item_id=client.items[0]).one().username == 'login-0'


def test_database_reveal_failure_generic(client, monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise RuntimeError('private-synthetic-database-detail')
    monkeypatch.setattr(functions, 'resolve_item', fail)
    response = client.post(f'/passwords/{client.items[0]}/reveal')
    assert response.status_code == 500
    assert 'private-synthetic' not in response.get_data(as_text=True) + caplog.text


@pytest.mark.parametrize('stage', ['readiness', 'actor'])
def test_pre_reveal_database_errors_do_not_log_exception(client, monkeypatch, caplog, stage):
    import app as application
    import authorization
    def fail(*args, **kwargs):
        raise RuntimeError('synthetic-private-schema-diagnostic')
    if stage == 'readiness':
        monkeypatch.setattr(application, 'validate_item_schema', fail)
    else:
        monkeypatch.setattr(authorization, 'current_web_user', fail)
    forbid_decrypt(monkeypatch)
    response = client.post(f'/passwords/{client.items[0]}/reveal')
    assert response.status_code == 503
    assert response.headers['Cache-Control'] == 'no-store'
    assert 'synthetic-private-schema-diagnostic' not in response.get_data(as_text=True) + caplog.text


@pytest.mark.parametrize('operation', ['add', 'delete'])
@pytest.mark.parametrize('failure', ['audit', 'commit'])
def test_creation_deletion_and_audit_rollback_together(client, monkeypatch, operation, failure):
    import audit_events
    from models import audit_log
    def snapshot():
        with app.app_context():
            return ([(x.item_id, x.password, x.username, tuple(u.id for u in x.shared_users))
                     for x in Password.query.order_by(Password.id).all()],
                    audit_log.query.count())
    before = snapshot()
    def fail(*args, **kwargs):
        if failure == 'commit':
            db.session.flush()
        raise RuntimeError('synthetic-private-write-failure')
    if failure == 'audit':
        monkeypatch.setattr(audit_events, 'stage_event', fail)
    else:
        monkeypatch.setattr(db.session, 'commit', fail)
    path = '/add_password' if operation == 'add' else f'/passwords/{client.items[0]}/delete'
    response = client.post(path, data={'service': 'synthetic', 'username': 'new',
                                      'password': 'new-synthetic-secret'})
    assert response.status_code == 500
    assert snapshot() == before
    assert b'synthetic-private-write-failure' not in response.data


@pytest.mark.parametrize('field', ['id', 'item_id', 'pw_id'])
def test_creation_rejects_caller_item_identity(client, field):
    response = client.post('/add_password', data={
        'service': 'synthetic', 'username': 'new', 'password': 'new-synthetic-secret',
        field: uuid4().hex})
    assert response.status_code == 400
    with app.app_context():
        assert Password.query.count() == 2
