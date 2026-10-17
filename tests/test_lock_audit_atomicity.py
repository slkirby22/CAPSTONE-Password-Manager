"""Manual lock mutations and their audit evidence use one disposable transaction."""
import pytest
from sqlalchemy import event

import functions
from app import app, limiter
from models import User, audit_log, db


@pytest.fixture
def client(monkeypatch):
    assert app.config['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///:memory:'
    monkeypatch.setitem(app.config, 'TESTING', True)
    monkeypatch.setitem(app.config, 'WTF_CSRF_ENABLED', False)
    monkeypatch.setattr(limiter, 'enabled', False)
    with app.app_context():
        db.create_all()
        db.session.add_all([
            User(username='ADMIN', password=functions.pwd_context.hash('Synthetic1!'), role='admin'),
            User(username='EMPLOYEE', password=functions.pwd_context.hash('Synthetic1!'), role='employee'),
        ])
        db.session.commit()
    client = app.test_client()
    assert client.post('/login', data={'username': 'ADMIN', 'password': 'Synthetic1!'}).status_code == 302
    yield client
    with app.app_context():
        db.session.remove()
        db.drop_all()


def snapshot():
    with app.app_context():
        return (
            tuple((u.id, u.auth_identity, u.username, u.password, u.role, u.failed_login_attempts)
                  for u in User.query.order_by(User.id).all()),
            tuple((a.id, a.event_message, a.event_type, a.user_id)
                  for a in audit_log.query.order_by(audit_log.id).all()),
        )


def prepare(operation):
    with app.app_context():
        User.query.filter_by(id=2).one().failed_login_attempts = 4 if operation == 'unlock' else 0
        db.session.commit()


def submit(client, operation):
    return client.post(f'/{operation}_account/2')


@pytest.mark.parametrize('operation', ['lock', 'unlock'])
@pytest.mark.parametrize('stage', ['audit_insert', 'account_write', 'commit'])
def test_failed_account_transaction_preserves_account_and_audit(client, monkeypatch, operation, stage):
    prepare(operation)
    before = snapshot()
    marker = 'synthetic-private-exception-details'
    listener = None
    if stage == 'commit':
        def fail_commit():
            db.session.flush()
            raise RuntimeError(marker)
        monkeypatch.setattr(db.session, 'commit', fail_commit)
    else:
        prefix = 'INSERT INTO audit_log' if stage == 'audit_insert' else (
            'UPDATE user')
        def listener(connection, cursor, statement, parameters, context, executemany):
            if statement.startswith(prefix):
                raise RuntimeError(marker)
        with app.app_context():
            engine = db.engine
        event.listen(engine, 'before_cursor_execute', listener)
    try:
        response = submit(client, operation)
    finally:
        if listener:
            event.remove(engine, 'before_cursor_execute', listener)
    assert snapshot() == before
    assert response.status_code == 500
    assert marker not in response.get_data(as_text=True)
    assert 'ChangedSynthetic1!' not in response.get_data(as_text=True)


@pytest.mark.parametrize('operation', ['lock', 'unlock'])
def test_success_has_one_commit_and_one_matching_event(client, monkeypatch, operation):
    prepare(operation)
    before = snapshot()
    commits = []
    real_commit = db.session.commit
    def commit():
        commits.append(True)
        return real_commit()
    monkeypatch.setattr(db.session, 'commit', commit)
    response = submit(client, operation)
    assert response.status_code == 200
    assert len(commits) == 1
    after = snapshot()
    assert len(after[1]) == len(before[1]) + 1
    assert after[1][-1][2:] == ('ACCOUNT_LOCK' if operation == 'lock' else 'ACCOUNT_UNLOCK', 1)
    with app.app_context():
        target = User.query.filter_by(id=2).one()
        assert target.failed_login_attempts == (4 if operation == 'lock' else 0)
    assert after[0][0] == before[0][0]
    assert after[0][1][:-1] == before[0][1][:-1]
    assert after[1][:-1] == before[1]




@pytest.mark.parametrize('operation', ['lock', 'unlock'])
def test_repeated_state_has_no_commit_or_success_event(client, monkeypatch, operation):
    prepare('unlock' if operation == 'lock' else 'lock')
    before = snapshot()
    def forbidden_commit():
        pytest.fail('No-op lock request must not commit')
    monkeypatch.setattr(db.session, 'commit', forbidden_commit)
    assert submit(client, operation).status_code == 200
    assert snapshot() == before


@pytest.mark.parametrize('operation', ['lock', 'unlock'])
@pytest.mark.parametrize('target', [1, 999])
def test_self_and_missing_target_preserve_accounts(client, operation, target):
    before = snapshot()
    assert client.post(f'/{operation}_account/{target}').status_code == 302
    after = snapshot()
    assert after[0] == before[0]
    if target == 1:
        assert after[1][:-1] == before[1]
        assert after[1][-1][2:] == ('UNAUTHORIZED_ACTION', 1)
    else:
        assert after[1] == before[1]
