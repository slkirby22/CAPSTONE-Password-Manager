"""Audit-route authorization with disposable SQLite data, never a live vault."""
from auth_helpers import auth_identity_for, credential_binding_for
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from flask import Flask
from flask_wtf.csrf import CSRFProtect

from functions import audit_log_viewer, est, get_audit_logs
from models import User, audit_log, db


@pytest.fixture
def client():
    app = Flask(__name__, template_folder=str(Path(__file__).parents[1] / 'templates'))
    app.config.update(
        TESTING=True,
        SECRET_KEY='synthetic-audit-test-session-key',
        SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
    )
    CSRFProtect(app)
    db.init_app(app)
    app.add_url_rule('/', 'index_route', lambda: 'index')
    app.add_url_rule('/dashboard', 'dashboard_route', lambda: 'dashboard')
    app.add_url_rule('/favicon.ico', 'favicon', lambda: '')
    app.add_url_rule('/audit_log_viewer', 'audit_log_viewer_route', audit_log_viewer)
    app.add_url_rule('/get_audit_logs', 'get_audit_logs_route', get_audit_logs)
    with app.app_context():
        db.create_all()
        db.session.add_all([
            User(username='SYNTHETIC_ADMIN', password='unused', role='admin'),
            User(username='SYNTHETIC_MANAGER', password='unused', role='manager'),
            User(username='SYNTHETIC_EMPLOYEE', password='unused', role='employee'),
        ])
        db.session.add_all([
            audit_log(id=101, event_time=datetime(2025, 1, 1, 12),
                      event_message='Synthetic older event', event_type='TEST', user_id=None),
            audit_log(id=102, event_time=datetime(2025, 1, 2, 12),
                      event_message='Synthetic selected event', event_type='TEST', user_id=None),
            audit_log(id=103, event_time=datetime(2025, 1, 3, 12),
                      event_message='Synthetic newer event', event_type='TEST', user_id=None),
        ])
        db.session.commit()
    with app.test_client() as test_client:
        yield test_client, app
    with app.app_context():
        db.session.remove()
        db.drop_all()


def set_session(client, user_id, role='admin'):
    with client.session_transaction() as session:
        session['user_id'] = user_id
        session['auth_identity'] = auth_identity_for(client, user_id)
        session['credential_binding'] = credential_binding_for(client, user_id)
        session['role'] = role
        session['username'] = 'UNTRUSTED_SESSION_NAME'


@pytest.mark.parametrize('user_id', [None, 999])
def test_json_rejects_missing_or_unknown_user(client, user_id):
    client, _ = client
    if user_id is not None:
        set_session(client, user_id)
    response = client.get('/get_audit_logs')
    assert response.status_code == 401
    assert response.get_json() == {'error': 'Authentication required'}


@pytest.mark.parametrize('user_id', [2, 3])
@pytest.mark.parametrize('session_role', ['admin', 'manager', 'employee'])
def test_json_rejects_non_admin_regardless_of_session_role(client, user_id, session_role):
    client, _ = client
    set_session(client, user_id, session_role)
    response = client.get('/get_audit_logs?start_date=2025-01-01&end_date=2025-01-04')
    assert response.status_code == 403
    assert response.get_json() == {'error': 'Administrator access required'}


@pytest.mark.parametrize('path', ['/get_audit_logs', '/audit_log_viewer'])
def test_deleted_session_user_is_denied(client, path):
    client, app = client
    set_session(client, 1)
    with app.app_context():
        db.session.delete(db.session.get(User, 1))
        db.session.commit()
    response = client.get(path)
    assert response.status_code == (401 if path == '/get_audit_logs' else 302)
    if path == '/audit_log_viewer':
        assert response.headers['Location'] == '/'
    assert b'Synthetic selected event' not in response.data


@pytest.mark.parametrize('path', ['/get_audit_logs', '/audit_log_viewer'])
def test_admin_demotion_takes_effect_on_next_request(client, path):
    client, app = client
    set_session(client, 1)
    assert client.get(path).status_code == 200
    with app.app_context():
        db.session.get(User, 1).role = 'employee'
        db.session.commit()
    response = client.get(path)
    assert response.status_code == (403 if path == '/get_audit_logs' else 302)
    assert b'Synthetic selected event' not in response.data


@pytest.mark.parametrize('session_role', ['admin', 'employee', None])
def test_json_uses_current_database_admin_and_preserves_contract(client, session_role):
    client, _ = client
    set_session(client, 1, session_role)
    response = client.get('/get_audit_logs')
    assert response.status_code == 200
    assert response.is_json
    assert {row['id'] for row in response.get_json()} == {101, 102, 103}
    selected = next(row for row in response.get_json() if row['id'] == 102)
    assert selected == {
        'id': 102, 'event_time': '2025-01-02 12:00:00',
        'event_message': 'Synthetic selected event', 'event_type': 'TEST', 'user_id': None,
    }


@pytest.mark.parametrize(('query', 'expected_ids'), [
    ('start_date=2025-01-02', {102, 103}),
    ('end_date=2025-01-03', {101, 102, 103}),
    ('start_date=2025-01-02&end_date=2025-01-03', {102, 103}),
    ('start_date=2025-01-04', set()),
])
def test_admin_date_filters_include_entire_selected_end_day(client, query, expected_ids):
    client, _ = client
    set_session(client, 1)
    response = client.get('/get_audit_logs?' + query)
    assert response.status_code == 200
    assert {row['id'] for row in response.get_json()} == expected_ids


@pytest.mark.parametrize('user_id', [None, 999, 2, 3])
def test_viewer_denies_non_admin_users(client, user_id):
    client, _ = client
    if user_id is not None:
        set_session(client, user_id)
    response = client.get('/audit_log_viewer')
    assert response.status_code == 302
    if user_id in (None, 999):
        assert response.headers['Location'] == '/'
    else:
        assert response.headers['Location'].startswith('/dashboard?error=')
    assert b'Audit Logs:' not in response.data


def test_admin_viewer_renders_and_can_refresh_json(client):
    client, app = client
    set_session(client, 1, 'employee')
    with app.app_context():
        db.session.add(audit_log(
            event_time=datetime.now(est) - timedelta(hours=1),
            event_message='Synthetic recent event', event_type='TEST', user_id=None,
        ))
        db.session.commit()
    response = client.get('/audit_log_viewer')
    assert response.status_code == 200
    assert b'Synthetic recent event' in response.data
    assert b'Synthetic older event' not in response.data
    assert b'static/js/audits.js' in response.data
    response = client.get('/get_audit_logs')
    assert response.status_code == 200
    assert any(row['event_type'] == 'AUDIT_LOG_VIEW' and row['user_id'] == 1
               for row in response.get_json())


@pytest.mark.parametrize('user_id', [None, 999, 2, 3])
def test_denied_json_request_does_not_query_audit_records(client, user_id):
    from sqlalchemy import event

    client, app = client
    if user_id is not None:
        set_session(client, user_id)
    statements = []

    def capture_statement(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.lower())

    with app.app_context():
        engine = db.engine
        event.listen(engine, 'before_cursor_execute', capture_statement)
    try:
        response = client.get('/get_audit_logs')
    finally:
        event.remove(engine, 'before_cursor_execute', capture_statement)
    assert response.status_code in (401, 403)
    assert not any('from audit_log' in statement for statement in statements)


@pytest.mark.parametrize('query', [
    'start_date=2025-02-30', 'end_date=2025-1-2',
    'start_date=2025-01-01T12:00:00', 'end_date=not-a-date',
    'start_date=2025-01-03&end_date=2025-01-02',
    'start_date=2025-01-01&start_date=2025-01-02',
    'end_date=0000-01-01',
])
def test_admin_rejects_invalid_date_filters_without_echoing_values(client, query):
    client, _ = client
    set_session(client, 1)
    response = client.get('/get_audit_logs?' + query)
    assert response.status_code == 400
    assert set(response.json) == {'error'}
    assert 'Synthetic selected event' not in response.text
    assert 'not-a-date' not in response.text


def test_same_day_range_includes_midnight_and_final_microsecond(client):
    client, app = client
    set_session(client, 1)
    with app.app_context():
        for ident, timestamp in [(201, datetime(2025, 1, 2)),
                                 (202, datetime(2025, 1, 2, 23, 59, 59, 999999)),
                                 (203, datetime(2025, 1, 3))]:
            db.session.add(audit_log(id=ident, event_time=timestamp, event_message='boundary', event_type='TEST'))
        db.session.commit()
    response = client.get('/get_audit_logs?start_date=2025-01-02&end_date=2025-01-02')
    assert response.status_code == 200
    assert {x['id'] for x in response.json} == {102, 201, 202}


def test_maximum_supported_end_date_does_not_overflow(client):
    client, _ = client
    set_session(client, 1)
    response = client.get('/get_audit_logs?end_date=9999-12-31')
    assert response.status_code == 200
    assert {x['id'] for x in response.json} == {101, 102, 103}
