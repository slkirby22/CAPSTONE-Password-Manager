"""Account mutations and their audit evidence use one disposable transaction."""
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


def submit(client, operation):
    return client.post('/create_user' if operation == 'create' else '/update_user/2',
                       data={'username': 'CHANGED', 'password': 'ChangedSynthetic1!', 'role': 'manager'})


@pytest.mark.parametrize('operation', ['create', 'update'])
@pytest.mark.parametrize('stage', ['audit_insert', 'account_write', 'commit'])
def test_failed_account_transaction_preserves_account_and_audit(client, monkeypatch, operation, stage):
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
            'INSERT INTO user' if operation == 'create' else 'UPDATE user')
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


@pytest.mark.parametrize('operation', ['create', 'update'])
def test_success_has_one_commit_and_one_matching_event(client, monkeypatch, operation):
    before = snapshot()
    commits = []
    real_commit = db.session.commit
    def commit():
        commits.append(True)
        return real_commit()
    monkeypatch.setattr(db.session, 'commit', commit)
    response = submit(client, operation)
    assert response.status_code == (302 if operation == 'create' else 200)
    assert len(commits) == 1
    after = snapshot()
    assert len(after[1]) == len(before[1]) + 1
    assert after[1][-1][2:] == ('USER_CREATE' if operation == 'create' else 'USER_UPDATE', 1)
    with app.app_context():
        target = User.query.filter_by(username='CHANGED').one()
        assert target.role == 'manager'
        assert functions.pwd_context.verify('ChangedSynthetic1!', target.password)


@pytest.mark.parametrize('password', ['', 'ChangedSynthetic1!'])
@pytest.mark.parametrize('fail_audit', [False, True])
def test_self_update_cookie_changes_only_after_commit(client, password, fail_audit):
    before = snapshot()
    with client.session_transaction() as sess:
        cookie_before = dict(sess)
    with app.app_context():
        engine = db.engine
    def listener(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith('INSERT INTO audit_log'):
            raise RuntimeError('synthetic audit failure')
    if fail_audit:
        event.listen(engine, 'before_cursor_execute', listener)
    try:
        response = client.post('/update_user/1', data={
            'username': 'RENAMED_ADMIN', 'password': password, 'role': 'employee'})
    finally:
        if fail_audit:
            event.remove(engine, 'before_cursor_execute', listener)
    with client.session_transaction() as sess:
        cookie_after = dict(sess)
    if fail_audit:
        assert response.status_code == 500
        assert snapshot() == before
        assert cookie_after == cookie_before
        # The rolled-back password and session binding still authenticate.
        assert client.get('/dashboard').status_code == 200
    else:
        assert response.status_code == 302
        assert response.headers['Location'].endswith('/logout')
        after = snapshot()
        assert after[0][0][1] == before[0][0][1]  # stable account incarnation
        assert after[0][0][2] == 'RENAMED_ADMIN'
        assert after[0][0][4] == 'admin'  # crafted self-demotion ignored
        assert after[1][-1][1:] == ('User RENAMED_ADMIN updated their own account.', 'USER_UPDATE', 1)
        if password:
            assert cookie_after == {}
        else:
            assert after[0][0][3] == before[0][0][3]
            assert cookie_after['username'] == 'RENAMED_ADMIN'
