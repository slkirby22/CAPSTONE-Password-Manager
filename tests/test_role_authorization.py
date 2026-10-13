"""Legacy role matrix through actual routes using disposable synthetic records."""
from auth_helpers import auth_identity_for, credential_binding_for
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from app import app, limiter
from models import db, User, Password

ROLES = ('admin', 'manager', 'employee', 'unexpected')
TARGET_ROLES = ('admin', 'manager', 'employee')


@pytest.fixture
def client(monkeypatch):
    assert app.config['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///:memory:'
    monkeypatch.setitem(app.config, 'TESTING', True)
    monkeypatch.setitem(app.config, 'WTF_CSRF_ENABLED', False)
    monkeypatch.setattr(limiter, 'enabled', False)
    with app.app_context():
        db.create_all()
        db.session.add_all([
            User(username='ACTOR', password='synthetic original hash', role='admin'),
            User(username='TARGET', password='synthetic target hash', role='employee'),
        ])
        db.session.flush()
        db.session.add(Password(user_id=2, service_name='synthetic',
                                username='test', password=b'synthetic encrypted placeholder', notes='synthetic'))
        db.session.commit()
    try:
        yield app.test_client()
    finally:
        with app.app_context():
            db.session.remove()
            db.drop_all()


def sign_in(client, role='admin', target_role='employee', session_role='admin'):
    with app.app_context():
        db.session.get(User, 1).role = role
        db.session.get(User, 2).role = target_role
        db.session.commit()
    with client.session_transaction() as session:
        session.update(user_id=1, credential_binding=credential_binding_for(client, 1), auth_identity=auth_identity_for(client, 1), username='STALE_NAME', role=session_role)


def snapshot():
    with app.app_context():
        return [(u.id, u.username, u.password, u.role, u.failed_login_attempts)
                for u in User.query.order_by(User.id).all()], Password.query.count()


@pytest.mark.parametrize('actor_role', ROLES)
@pytest.mark.parametrize('target_role', TARGET_ROLES)
@pytest.mark.parametrize('operation', ('update_user', 'delete_user', 'lock_account', 'unlock_account'))
def test_role_target_matrix(client, actor_role, target_role, operation):
    sign_in(client, actor_role, target_role)
    if operation == 'unlock_account':
        with app.app_context():
            db.session.get(User, 2).failed_login_attempts = 4
            db.session.commit()
    before = snapshot()
    response = client.post(f'/{operation}/2', data={'username': 'CHANGED', 'password': ''})
    allowed = actor_role == 'admin' or (actor_role == 'manager' and target_role != 'admin')
    assert response.status_code in (200, 302)
    if not allowed:
        assert snapshot() == before
        assert b'synthetic target hash' not in response.data
    else:
        with app.app_context():
            target = db.session.get(User, 2)
            if operation == 'delete_user':
                assert target is None
                assert Password.query.count() == 0
            elif operation == 'update_user':
                assert target.username == 'CHANGED'
                assert target.role == target_role
            else:
                assert target.failed_login_attempts == (4 if operation == 'lock_account' else 0)


@pytest.mark.parametrize('actor_role', ROLES)
@pytest.mark.parametrize('new_role', (*TARGET_ROLES, 'unexpected', '', 'ADMIN'))
def test_create_role_assignments(client, actor_role, new_role):
    sign_in(client, actor_role)
    before = snapshot()
    response = client.post('/create_user', data={
        'username': 'new synthetic', 'password': 'Synthetic1!', 'role': new_role})
    assert response.status_code in (200, 302)
    allowed = (actor_role == 'admin' and new_role in TARGET_ROLES) or (
        actor_role == 'manager' and new_role == 'employee')
    with app.app_context():
        user = User.query.filter_by(username='NEW SYNTHETIC').first()
        assert (user is not None) == allowed
        if allowed:
            assert user.role == new_role
    if not allowed:
        assert snapshot() == before


@pytest.mark.parametrize('actor_role', ROLES)
@pytest.mark.parametrize('target_role', TARGET_ROLES)
@pytest.mark.parametrize('new_role', (*TARGET_ROLES, 'unexpected', ''))
def test_update_assignment_matrix_is_atomic(client, actor_role, target_role, new_role):
    sign_in(client, actor_role, target_role)
    before = snapshot()
    response = client.post('/update_user/2', data={
        'username': 'CHANGED', 'password': 'Synthetic2!', 'role': new_role})
    assert response.status_code in (200, 302)
    allowed = new_role in TARGET_ROLES and (
        actor_role == 'admin' or (actor_role == 'manager' and target_role != 'admin'
                                 and (new_role == 'employee' or new_role == target_role)))
    if not allowed:
        assert snapshot() == before  # Includes username, password, role, lock counter, vault rows.
    else:
        with app.app_context():
            target = db.session.get(User, 2)
            assert target.username == 'CHANGED'
            assert target.password != before[0][1][2]
            assert target.role == new_role


@pytest.mark.parametrize('role', ('admin', 'manager'))
@pytest.mark.parametrize('new_role', (*TARGET_ROLES, 'unexpected'))
def test_self_profile_keeps_role(client, role, new_role):
    sign_in(client, role)
    response = client.post('/update_user/1', data={
        'username': 'RENAMED', 'password': '', 'role': new_role})
    assert response.status_code == 302
    assert response.headers['Location'] == '/logout'
    with app.app_context():
        assert db.session.get(User, 1).role == role
        assert db.session.get(User, 1).username == 'RENAMED'


@pytest.mark.parametrize('role', ('admin', 'manager'))
@pytest.mark.parametrize('operation', ('delete_user', 'lock_account', 'unlock_account'))
def test_self_destructive_actions_denied(client, role, operation):
    sign_in(client, role)
    before = snapshot()
    assert client.post(f'/{operation}/1').status_code == 302
    assert snapshot() == before


@pytest.mark.parametrize('method,path', [
    ('get', '/dashboard'), ('get', '/select_password_for_edit?service_name=synthetic'),
    ('get', '/create_user'), ('get', '/view_users'), ('get', '/select_user_for_edit'),
    ('post', '/update_user/2'), ('post', '/delete_user/2'),
    ('post', '/lock_account/2'), ('post', '/unlock_account/2'),
    ('post', '/add_password'), ('post', '/update_password/synthetic'),
    ('post', '/delete_password/synthetic'), ('get', '/audit_log_viewer'),
    ('get', '/get_audit_logs'), ('get', '/search_user?username=TARGET'),
])
@pytest.mark.parametrize('actor', ('anonymous', 'deleted'))
def test_all_sensitive_web_routes_reject_missing_identity(client, method, path, actor):
    if actor == 'deleted':
        with client.session_transaction() as session:
            session.update(user_id=999, role='admin', username='DELETED')
    before = snapshot()
    response = getattr(client, method)(path)
    if path.startswith('/search_user'):
        assert response.get_json() == {'found': False}
    elif path == '/get_audit_logs':
        assert response.status_code == 401
    else:
        assert response.status_code == 302
        assert response.headers['Location'] == '/'
    assert snapshot() == before


@pytest.mark.parametrize('operation', ('update_user', 'delete_user', 'lock_account', 'unlock_account'))
def test_current_database_demotion_applies_next_request(client, operation):
    sign_in(client)
    assert client.get('/view_users').status_code == 200
    with app.app_context():
        db.session.get(User, 1).role = 'employee'
        db.session.commit()
    before = snapshot()
    assert client.post(f'/{operation}/2', data={'username': 'CHANGED', 'password': ''}).status_code == 302
    assert snapshot() == before


@pytest.mark.parametrize('session_role', ('employee', 'manager', None))
def test_current_admin_not_blocked_by_stale_session_role(client, session_role):
    sign_in(client, session_role=session_role)
    assert client.post('/lock_account/2').status_code == 200
    with app.app_context():
        assert db.session.get(User, 2).failed_login_attempts == 4


@pytest.mark.parametrize('path', ('/view_users', '/select_user_for_edit'))
def test_manager_cannot_select_admin_target(client, path):
    sign_in(client, 'manager', 'admin')
    response = client.post(path, data={'selected_user_id': '2'})
    assert response.status_code == 302
    assert b'Edit User Details' not in response.data


@pytest.mark.parametrize('operation', ('update_user', 'delete_user', 'lock_account', 'unlock_account'))
def test_nonexistent_target_does_not_crash(client, operation):
    sign_in(client)
    before = snapshot()
    assert client.post(f'/{operation}/999', data={'username': 'CHANGED', 'password': ''}).status_code == 302
    assert snapshot() == before


def test_csrf_still_required_for_account_mutation(client, monkeypatch):
    sign_in(client)
    monkeypatch.setitem(app.config, 'WTF_CSRF_ENABLED', True)
    before = snapshot()
    assert client.post('/lock_account/2').status_code == 400
    assert snapshot() == before


@pytest.mark.parametrize('role', ('admin', 'manager'))
@pytest.mark.parametrize('operation', ('update_user', 'delete_user', 'lock_account', 'unlock_account'))
def test_unrecognized_target_role_fails_closed(client, role, operation):
    sign_in(client, role, 'unexpected')
    before = snapshot()
    assert client.post(f'/{operation}/2', data={
        'username': 'CHANGED', 'password': '', 'role': 'employee'}).status_code == 302
    assert snapshot() == before


@pytest.mark.parametrize('operation,count', [('lock_account', 4), ('unlock_account', 2)])
def test_repeated_lock_state_preserves_existing_counter(client, operation, count):
    sign_in(client)
    with app.app_context():
        db.session.get(User, 2).failed_login_attempts = count
        db.session.commit()
    before = snapshot()
    assert client.post(f'/{operation}/2').status_code == 200
    assert snapshot() == before


@pytest.mark.parametrize('method,path', [
    ('get', '/create_user'), ('get', '/view_users'), ('get', '/select_user_for_edit'),
    ('post', '/update_user/2'), ('post', '/delete_user/2'),
    ('post', '/lock_account/2'), ('post', '/unlock_account/2'),
    ('get', '/audit_log_viewer'),
])
def test_denied_role_gate_preserves_security_audit(client, method, path):
    from models import audit_log

    sign_in(client, 'employee')
    before = snapshot()
    assert getattr(client, method)(path).status_code == 302
    assert snapshot() == before
    with app.app_context():
        events = audit_log.query.filter_by(event_type='UNAUTHORIZED_ACTION').all()
        assert len(events) == 1
        assert events[0].user_id == 1
        assert 'ACTOR' in events[0].event_message
        assert 'STALE_NAME' not in events[0].event_message


@pytest.mark.parametrize('path,role,fields', [
    ('/create_user', 'employee', {'username': 'NEW', 'password': 'Synthetic1!', 'role': 'admin'}),
    ('/view_users', 'admin', {'selected_user_id': '2'}),
    ('/update_user/2', 'admin', {'username': 'CHANGED', 'password': ''}),
    ('/update_user/2', 'employee', {'username': 'CHANGED', 'password': '', 'role': 'manager'}),
    ('/delete_user/2', 'admin', {}), ('/lock_account/2', 'admin', {}),
    ('/unlock_account/2', 'admin', {}),
])
def test_denied_target_or_assignment_is_audited(client, path, role, fields):
    from models import audit_log

    sign_in(client, 'manager', role)
    before = snapshot()
    assert client.post(path, data=fields).status_code in (200, 302)
    assert snapshot() == before
    with app.app_context():
        events = audit_log.query.filter_by(event_type='UNAUTHORIZED_ACTION').all()
        assert len(events) == 1
        assert events[0].user_id == 1
