"""Actual web update routes against disposable, public synthetic SQLite data."""
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import event

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import functions
from app import app, limiter
from models import Password, User, audit_log, db


@pytest.fixture
def client(monkeypatch):
    assert app.config['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///:memory:'
    monkeypatch.setitem(app.config, 'TESTING', True)
    monkeypatch.setitem(app.config, 'PROPAGATE_EXCEPTIONS', False)
    monkeypatch.setitem(app.config, 'WTF_CSRF_ENABLED', False)
    monkeypatch.setattr(limiter, 'enabled', False)
    with app.app_context():
        db.create_all()
        users = [User(username=name, password=functions.pwd_context.hash('Synthetic1!'),
                      role='employee') for name in ('OWNER', 'OLD_SHARE', 'NEW_SHARE')]
        db.session.add_all(users)
        db.session.flush()
        cipher = Fernet(app.config['ENCRYPTION_KEY'])
        db.session.add(Password(service_name='synthetic-service', username='original-login',
                                password=cipher.encrypt(b'original-synthetic-secret'),
                                notes='original notes', user_id=users[0].id,
                                shared_users=[users[1]]))
        db.session.commit()
    result = app.test_client()
    assert result.post('/login', data={'username': 'OWNER', 'password': 'Synthetic1!'}).status_code == 302
    try:
        yield result
    finally:
        with app.app_context():
            db.session.remove()
            db.drop_all()


def share_identity(user_id):
    with app.app_context():
        return db.session.get(User, user_id).auth_identity


def form():
    return {'username': 'changed-login', 'replace_password': '1',
            'password': 'changed-synthetic-secret', 'notes': 'changed notes',
            'shared_users': [share_identity(3)]}


def snapshot():
    # Every observation gets a fresh session, independent of the request.
    with app.app_context():
        row = db.session.get(Password, 1)
        return (row.service_name, row.user_id, row.username, row.password, row.notes,
                tuple(sorted(user.id for user in row.shared_users)),
                tuple((log.id, log.event_message, log.event_type, log.user_id)
                      for log in audit_log.query.order_by(audit_log.id).all()))


def post(client, data):
    with app.app_context():
        item_id = db.session.get(Password, 1).item_id
    return client.post(f'/passwords/{item_id}/update', data=data)


@pytest.mark.parametrize('field', ['username', 'password'])
def test_missing_required_field_changes_nothing(client, field):
    before = snapshot()
    data = form()
    del data[field]
    response = post(client, data)
    assert snapshot() == before
    assert response.status_code == 400


@pytest.mark.parametrize('field,value', [('pw_id', 'no-id'), ('pw_id', '0'),
                                         ('shared_users', ['oops']),
                                         ('shared_users', ['0' * 32]),
                                         ('shared_users', ['3', '0' * 32]),
                                         ('item_id', '0' * 32)])
def test_invalid_id_or_share_changes_nothing(client, field, value):
    before = snapshot()
    data = form()
    data[field] = value
    response = post(client, data)
    assert snapshot() == before
    assert response.status_code == 400


@pytest.mark.parametrize('stage', ['key', 'encrypt', 'audit_insert', 'password_update', 'commit'])
def test_failure_rolls_back_fields_shares_secret_and_audit(client, monkeypatch, stage):
    before = snapshot()
    failure_text = 'synthetic-private-exception-details'
    listener = None
    engine = None
    if stage == 'key':
        monkeypatch.setitem(app.config, 'ENCRYPTION_KEY', 'invalid-synthetic-key')
    elif stage == 'encrypt':
        def fail_encrypt(*args, **kwargs):
            raise RuntimeError(failure_text)
        monkeypatch.setattr(functions.Fernet, 'encrypt', fail_encrypt)
    elif stage in ('audit_insert', 'password_update'):
        prefix = 'INSERT INTO audit_log' if stage == 'audit_insert' else 'UPDATE password'
        def listener(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith(prefix):
                raise RuntimeError(failure_text)
        with app.app_context():
            engine = db.engine
        event.listen(engine, 'before_cursor_execute', listener)
    else:
        def fail_commit():
            # Flush proves the rollback undoes writes, not just pending objects.
            db.session.flush()
            raise RuntimeError(failure_text)
        monkeypatch.setattr(db.session, 'commit', fail_commit)
    try:
        response = post(client, form())
    finally:
        if listener is not None:
            event.remove(engine, 'before_cursor_execute', listener)
    assert snapshot() == before
    assert response.status_code == 500
    assert failure_text not in response.get_data(as_text=True)
    assert 'changed-synthetic-secret' not in response.get_data(as_text=True)


@pytest.mark.parametrize('shares', [[], ['3'], ['3', '3']])
def test_success_commits_entire_update_and_audit_once(client, monkeypatch, shares):
    before = snapshot()
    commits = []
    real_commit = db.session.commit
    def counted_commit():
        commits.append(True)
        return real_commit()
    monkeypatch.setattr(db.session, 'commit', counted_commit)
    data = form()
    data['shared_users'] = [share_identity(int(value)) for value in shares]
    response = post(client, data)
    assert response.status_code == 302
    assert response.headers['Location'] == '/dashboard'
    after = snapshot()
    assert after[:3] == ('synthetic-service', 1, 'changed-login')
    assert Fernet(app.config['ENCRYPTION_KEY']).decrypt(after[3]) == b'changed-synthetic-secret'
    assert after[4:6] == ('changed notes', tuple(sorted(set(map(int, shares)))))
    assert len(after[6]) == len(before[6]) + 1
    assert after[6][-1][2:] == ('PASSWORD_SHARE', 1)
    assert 'changed-synthetic-secret' not in after[6][-1][1]
    assert len(commits) == 1


def test_existing_stored_credential_policy_is_preserved(client):
    data = form()
    data.update(username='', password='')
    data.pop('notes')
    assert post(client, data).status_code == 302
    after = snapshot()
    assert after[2] == ''
    assert Fernet(app.config['ENCRYPTION_KEY']).decrypt(after[3]) == b''
    assert after[4] is None


def test_metadata_only_update_preserves_ciphertext_without_encryption(client, monkeypatch):
    before = snapshot()
    data = form()
    del data['replace_password']
    del data['password']
    def forbidden_encrypt(*args, **kwargs):
        raise AssertionError('Metadata update must not encrypt')
    monkeypatch.setattr(functions.Fernet, 'encrypt', forbidden_encrypt)
    assert post(client, data).status_code == 302
    after = snapshot()
    assert after[2] == 'changed-login'
    assert after[3] == before[3]
    assert after[4:6] == ('changed notes', (3,))


def test_unrequested_password_field_cannot_replace_ciphertext(client):
    before = snapshot()
    data = form()
    del data['replace_password']
    assert post(client, data).status_code == 302
    assert snapshot()[3] == before[3]
