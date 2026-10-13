"""Actual app, real password login, enabled CSRF, disposable public fixtures."""
import re
import sys
from pathlib import Path

import pytest
from sqlalchemy.orm import Query
from werkzeug.exceptions import BadRequest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import api_functions
import audit_events
import functions
from app import app, limiter
from models import User, Password, TokenBlacklist, audit_log, db
from cryptography.fernet import Fernet

SECRET = 'PUBLIC_SENTINEL_SECRET!9'
TOKEN = 'PUBLIC_SENTINEL_BEARER_TOKEN'
SOURCE = 'PUBLIC_SENTINEL_SOURCE_CONTENT'
FAULT = f'{SECRET} {TOKEN} {SOURCE}\nSELECT password FROM user; parameters=(secret,)'
LOGIN_PASSWORD = 'Public fixture login!9'


@pytest.fixture(scope='module')
def login_hash():
    return functions.pwd_context.hash(LOGIN_PASSWORD)


@pytest.fixture
def client(monkeypatch, login_hash):
    monkeypatch.setitem(app.config, 'TESTING', True)
    monkeypatch.setitem(app.config, 'WTF_CSRF_ENABLED', True)
    monkeypatch.setattr(limiter, 'enabled', False)
    with app.app_context():
        assert db.engine.url.get_backend_name() == 'sqlite'
        assert db.engine.url.database == ':memory:'
        db.create_all()
        admin = User(username='ADMIN_FIXTURE', password=login_hash, role='admin')
        employee = User(username='EMPLOYEE_FIXTURE', password=login_hash, role='employee')
        db.session.add_all([admin, employee])
        db.session.flush()
        db.session.add(Password(user_id=admin.id, service_name='public-fixture',
                                username='public-login', notes=SOURCE,
                                password=Fernet(app.config['ENCRYPTION_KEY']).encrypt(SECRET.encode())))
        db.session.commit()
    try:
        yield app.test_client()
    finally:
        with app.app_context():
            db.session.remove()
            db.drop_all()


def csrf(client):
    response = client.get('/login', base_url='https://localhost', follow_redirects=True)
    assert response.status_code == 200
    return re.search(r'name="csrf_token"[^>]*value="([^"]+)"', response.text).group(1)


def post(client, path, data=None, token=None):
    return client.post(path, base_url='https://localhost', data=data or {}, headers={
        'X-CSRFToken': token or csrf(client), 'Referer': 'https://localhost/login'})


def login(client, username='ADMIN_FIXTURE'):
    response = post(client, '/login', {'username': username, 'password': LOGIN_PASSWORD})
    assert response.status_code == 302
    assert response.headers['Location'] == '/dashboard'
    return csrf(client)


def fail(*args, **kwargs):
    raise RuntimeError(FAULT)


def clean(response, caplog, capfd):
    captured = capfd.readouterr()
    surfaces = response.text + repr(list(response.headers)) + caplog.text + captured.out + captured.err
    for sentinel in (SECRET, TOKEN, SOURCE):
        assert sentinel not in surfaces
    assert response.headers['Cache-Control'] == 'no-store'
    assert all(record.exc_info is None and record.stack_info is None for record in caplog.records)


@pytest.mark.parametrize('method,path', [
    ('GET', '/dashboard'), ('GET', '/passwords/not-an-id'),
    ('GET', '/create_user'), ('GET', '/view_users'), ('POST', '/view_users'),
    ('GET', '/select_user_for_edit'), ('POST', '/select_user_for_edit'),
    ('POST', '/create_user'), ('POST', '/update_user/2'), ('POST', '/delete_user/2'),
    ('POST', '/lock_account/2'), ('POST', '/unlock_account/2'),
    ('POST', '/add_password'), ('POST', '/passwords/not-an-id/update'),
    ('POST', '/passwords/not-an-id/delete'), ('GET', '/audit_log_viewer'),
    ('GET', '/select_password_for_edit'), ('POST', '/select_password_for_edit'),
    ('POST', '/update_password/old'), ('POST', '/delete_password/old'),
])
def test_anonymous_web_denial_uses_real_csrf(client, method, path):
    token = csrf(client)
    response = client.open(path, method=method, base_url='https://localhost',
                           headers={'X-CSRFToken': token, 'Referer': 'https://localhost/login'})
    assert response.status_code == 302
    assert response.headers['Location'] == '/'


@pytest.mark.parametrize('path,status,body', [
    ('/get_audit_logs', 401, {'error': 'Authentication required'}),
    ('/search_user?username=ADMIN_FIXTURE', 200, {'found': False}),
])
def test_anonymous_json_denial(client, path, status, body):
    response = client.get(path)
    assert (response.status_code, response.get_json()) == (status, body)


def test_anonymous_reveal_denial_with_valid_csrf(client):
    response = post(client, '/passwords/not-an-id/reveal')
    assert response.status_code == 401


@pytest.mark.parametrize('path', ['/create_user', '/update_user/2', '/delete_user/2',
                                  '/lock_account/2', '/unlock_account/2', '/add_password',
                                  '/passwords/bad/reveal', '/passwords/bad/update',
                                  '/passwords/bad/delete'])
def test_actual_mutations_require_csrf_after_real_login(client, path):
    login(client)
    response = client.post(path, base_url='https://localhost')
    assert response.status_code == 400
    assert 'CSRF token is missing' in response.text


@pytest.mark.parametrize('path,data', [('/login', {}), ('/create_user', {}),
                                      ('/update_user/2', {}), ('/add_password', {}),
                                      ('/passwords/bad/update', {})])
def test_missing_forms_generic_without_echo(client, path, data, caplog, capfd):
    token = csrf(client) if path == '/login' else login(client)
    response = post(client, path, {**data, 'unused': FAULT}, token)
    assert response.status_code == 400
    clean(response, caplog, capfd)


@pytest.mark.parametrize('body', ['{', 'null', '[]', '"'+TOKEN+'"', '{"password":"'+SECRET+'"}'])
def test_malformed_json_generic_without_echo(client, body, caplog, capfd):
    response = client.post('/api/login', data=body, content_type='application/json')
    assert response.status_code == 400
    clean(response, caplog, capfd)


@pytest.mark.parametrize('kind', ['verify', 'commit'])
def test_web_login_fault_cannot_establish_session(client, monkeypatch, caplog, capfd, kind):
    token = csrf(client)
    monkeypatch.setattr(functions.pwd_context if kind == 'verify' else db.session,
                        'verify' if kind == 'verify' else 'commit', fail)
    response = post(client, '/login', {'username': 'ADMIN_FIXTURE', 'password': LOGIN_PASSWORD}, token)
    assert response.status_code == 200
    assert 'Invalid username or password' in response.text
    with client.session_transaction() as session:
        assert 'user_id' not in session and 'auth_identity' not in session
    assert 'event=web_login_failed' in caplog.text
    clean(response, caplog, capfd)


def test_api_verifier_fault_is_generic(client, monkeypatch, caplog, capfd):
    monkeypatch.setattr(api_functions.pwd_context, 'verify', fail)
    response = client.post('/api/login', json={'username': 'ADMIN_FIXTURE', 'password': LOGIN_PASSWORD})
    assert response.status_code == 500
    assert response.get_json() == {'error': 'Request could not be completed'}
    assert 'event=request_failed' in caplog.text
    clean(response, caplog, capfd)


@pytest.mark.parametrize('path', ['/create_user', '/update_user/2'])
def test_user_hash_fault_sanitized(client, monkeypatch, caplog, capfd, path):
    token = login(client)
    monkeypatch.setattr(functions.pwd_context, 'hash', fail)
    response = post(client, path, {'username': 'OTHER_PUBLIC_USER', 'password': LOGIN_PASSWORD, 'role': 'employee'}, token)
    assert response.status_code == 500
    clean(response, caplog, capfd)
    with app.app_context():
        assert User.query.count() == 2
        assert db.session.get(User, 2).username == 'EMPLOYEE_FIXTURE'


@pytest.mark.parametrize('path', ['/create_user', '/update_user/2', '/delete_user/2', '/lock_account/2', '/unlock_account/2'])
def test_account_commit_fault_rolls_back(client, monkeypatch, caplog, capfd, path):
    if path == '/unlock_account/2':
        with app.app_context():
            db.session.get(User, 2).failed_login_attempts = 4
            db.session.commit()
    token = login(client)
    monkeypatch.setattr(db.session, 'commit', fail)
    response = post(client, path, {'username': 'CHANGED_FIXTURE', 'password': '', 'role': 'employee'}, token)
    if path == '/create_user':
        response = post(client, path, {'username': 'NEW_FIXTURE', 'password': LOGIN_PASSWORD, 'role': 'employee'}, token)
    assert response.status_code == 500
    clean(response, caplog, capfd)
    with app.app_context():
        assert User.query.count() == 2
        target = db.session.get(User, 2)
        assert target.username == 'EMPLOYEE_FIXTURE'
        assert target.failed_login_attempts == (4 if path == '/unlock_account/2' else 0)


@pytest.mark.parametrize('path', ['/view_users', '/audit_log_viewer', '/get_audit_logs'])
def test_query_fault_after_real_auth(client, monkeypatch, caplog, capfd, path):
    login(client)
    monkeypatch.setattr(Query, 'all', fail)
    response = client.get(path, base_url='https://localhost')
    assert response.status_code == 500
    clean(response, caplog, capfd)


def test_audit_writer_failure_is_best_effort_sanitized(client, monkeypatch, caplog, capfd):
    login(client)
    monkeypatch.setattr(audit_events, 'stage_event', fail)
    response = client.get('/view_users', base_url='https://localhost')
    assert response.status_code == 200
    assert 'event=audit_write_failed' in caplog.text
    clean(response, caplog, capfd)


def test_rollback_failure_does_not_escape_handler(client, monkeypatch, caplog, capfd):
    login(client)
    monkeypatch.setattr(Query, 'all', fail)
    monkeypatch.setattr(db.session, 'rollback', fail)
    response = client.get('/get_audit_logs', base_url='https://localhost')
    assert response.status_code == 500
    assert 'event=rollback_failed' in caplog.text
    clean(response, caplog, capfd)


def test_http_exception_description_cannot_echo_source(client, monkeypatch, caplog, capfd):
    login(client)
    def http_fail(*args, **kwargs):
        raise BadRequest(FAULT)
    monkeypatch.setattr(Query, 'all', http_fail)
    response = client.get('/get_audit_logs', base_url='https://localhost')
    assert response.status_code == 400
    clean(response, caplog, capfd)


@pytest.mark.parametrize('header', [TOKEN, 'Bearer '+TOKEN, 'Bearer one '+TOKEN])
def test_jwt_parser_does_not_echo_header(client, header, caplog, capfd):
    response = client.get('/api/dashboard', headers={'Authorization': header})
    expected = (401, {'msg': 'Authentication required'}) if header == TOKEN else (422, {'msg': 'Invalid token'})
    assert (response.status_code, response.get_json()) == expected
    clean(response, caplog, capfd)


def test_method_errors_preserve_allow_without_echo(client, caplog, capfd):
    response = client.get('/api/login?source='+SOURCE)
    assert response.status_code == 405
    assert 'POST' in response.headers['Allow']
    clean(response, caplog, capfd)


@pytest.mark.parametrize('method,path', [('GET', '/api/dashboard'), ('POST', '/api/passwords'),
                                        ('PATCH', '/api/passwords/1'), ('DELETE', '/api/passwords/1'),
                                        ('POST', '/api/logout')])
def test_api_cannot_use_web_cookie(client, method, path):
    login(client)
    response = client.open(path, method=method, base_url='https://localhost')
    assert response.status_code == 401
    assert response.get_json() == {'msg': 'Authentication required'}


def api_token(client):
    response = client.post('/api/login', json={'username': 'ADMIN_FIXTURE', 'password': LOGIN_PASSWORD})
    assert response.status_code == 200
    return response.get_json()['access_token']


def test_api_logout_commit_failure_is_sanitized(client, monkeypatch, caplog, capfd):
    token = api_token(client)
    monkeypatch.setattr(db.session, 'commit', fail)
    response = client.post('/api/logout', headers={'Authorization': 'Bearer '+token})
    assert response.status_code == 500
    assert token not in response.text + caplog.text
    clean(response, caplog, capfd)
    with app.app_context():
        assert TokenBlacklist.query.count() == 0


def test_jwt_blacklist_query_failure_is_sanitized(client, monkeypatch, caplog, capfd):
    token = api_token(client)
    original = Query.first
    def failed_blacklist(query):
        if query.column_descriptions[0]['entity'] is TokenBlacklist:
            fail()
        return original(query)
    monkeypatch.setattr(Query, 'first', failed_blacklist)
    response = client.get('/api/dashboard', headers={'Authorization': 'Bearer '+token})
    assert response.status_code == 500
    assert token not in response.text + caplog.text
    clean(response, caplog, capfd)


@pytest.mark.parametrize('path', ['/healthz', '/login', '/static/js/item-reveal.js'])
def test_readiness_failure_is_sanitized(client, monkeypatch, caplog, capfd, path):
    import app as app_module
    monkeypatch.setattr(app_module, 'validate_item_schema', fail)
    response = client.get(path)
    assert response.status_code == 503
    clean(response, caplog, capfd)


def test_web_actor_lookup_failure_is_sanitized(client, monkeypatch, caplog, capfd):
    import authorization
    login(client)
    monkeypatch.setattr(authorization, 'current_web_user', fail)
    response = client.get('/get_audit_logs', base_url='https://localhost')
    assert response.status_code == 503
    clean(response, caplog, capfd)


def test_invalid_csrf_does_not_echo_token(client, caplog, capfd):
    login(client)
    response = post(client, '/delete_user/2', token=TOKEN)
    assert response.status_code == 400
    clean(response, caplog, capfd)


def test_diagnostic_api_does_not_accept_arbitrary_content(client, caplog, capfd):
    from diagnostics import report_failure
    with app.app_context():
        report_failure(FAULT)
    response = client.get('/healthz')
    assert 'event=request_failed endpoint=none method=none' in caplog.text
    clean(response, caplog, capfd)


def test_registered_route_inventory_has_no_unreviewed_surface():
    # Extension/static routes count too. New routes require explicit review here
    # and a matching Documentation/route-error-acceptance.md inventory update.
    actual = {(rule.rule, tuple(sorted(rule.methods - {'HEAD', 'OPTIONS'})))
              for rule in app.url_map.iter_rules()}
    expected = {
        ('/', ('GET',)), ('/healthz', ('GET',)), ('/favicon.ico', ('GET',)),
        ('/static/<path:filename>', ('GET',)), ('/static/bootstrap/<path:filename>', ('GET',)),
        ('/login', ('GET', 'POST')), ('/logout', ('GET',)), ('/dashboard', ('GET',)),
        ('/create_user', ('GET', 'POST')), ('/view_users', ('GET', 'POST')),
        ('/select_user_for_edit', ('GET', 'POST')), ('/update_user/<user_id>', ('POST',)),
        ('/delete_user/<user_id>', ('POST',)), ('/lock_account/<user_id>', ('POST',)),
        ('/unlock_account/<user_id>', ('POST',)), ('/search_user', ('GET',)),
        ('/add_password', ('POST',)), ('/passwords/<item_id>', ('GET',)),
        ('/passwords/<item_id>/reveal', ('POST',)), ('/passwords/<item_id>/update', ('POST',)),
        ('/passwords/<item_id>/delete', ('POST',)), ('/select_password_for_edit', ('GET', 'POST')),
        ('/update_password/<service>', ('POST',)), ('/delete_password/<service>', ('POST',)),
        ('/audit_log_viewer', ('GET',)), ('/get_audit_logs', ('GET',)),
        ('/api/login', ('POST',)), ('/api/logout', ('POST',)), ('/api/dashboard', ('GET',)),
        ('/api/passwords', ('POST',)), ('/api/passwords/<password_id>', ('DELETE', 'PATCH')),
    }
    assert actual == expected


def test_audit_writer_and_rollback_failures_remain_best_effort(client, monkeypatch, caplog, capfd):
    login(client)
    monkeypatch.setattr(audit_events, 'stage_event', fail)
    monkeypatch.setattr(db.session, 'rollback', fail)
    response = client.get('/view_users', base_url='https://localhost')
    assert response.status_code == 200
    assert 'event=audit_write_failed endpoint=view_users_route method=GET' in caplog.text
    assert 'event=rollback_failed' in caplog.text
    clean(response, caplog, capfd)


def test_real_limiter_preserves_generic_429(client, monkeypatch, caplog, capfd):
    monkeypatch.setattr(limiter, 'enabled', True)
    limiter.reset()
    try:
        for _ in range(10):
            response = client.post('/api/login?source='+SOURCE, data=FAULT, content_type='application/json')
            assert response.status_code == 400
        response = client.post('/api/login?source='+SOURCE, data=FAULT, content_type='application/json')
        assert response.status_code == 429
        assert response.get_json() == {'error': 'This user has exceeded an allotted request count. Try again later.'}
        clean(response, caplog, capfd)
    finally:
        limiter.reset()



def test_landing_page_unload_does_not_send_logout(client):
    # Execute the actual response's inline scripts in a minimal JS event harness.
    # Deterministic dispatch catches the historical handler even when Chromium
    # would cancel the network fetch during navigation and mask the race.
    import json
    import subprocess
    response = client.get('/')
    assert response.status_code == 200
    scripts = re.findall(r'<script(?:\s[^>]*)?>(.*?)</script>', response.text, re.S)
    program = r"""
const vm = require('node:vm');
const assert = require('node:assert/strict');
const scripts = JSON.parse(process.argv[1]);
const requests = [];
const listeners = {};
const window = {addEventListener: (event, callback) => {
    (listeners[event] ||= []).push(callback);
}};
const context = vm.createContext({window, fetch: target => {
    requests.push(String(target));
    return Promise.resolve({status: 200});
}});
for (const script of scripts) vm.runInContext(script, context);
for (const event of ['beforeunload', 'pagehide', 'unload']) {
    if (typeof window['on' + event] === 'function') window['on' + event]();
    for (const callback of listeners[event] || []) callback();
}
assert.deepEqual(requests, [], 'Landing-page departure must not mutate session');
"""
    result = subprocess.run(['node', '-e', program, json.dumps(scripts)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_anonymous_csrf_precedes_auth_and_explicit_logout_clears_it(client):
    token = csrf(client)
    missing = client.post('/passwords/not-an-id/reveal', base_url='https://localhost',
                          headers={'Referer': 'https://localhost/login'})
    assert (missing.status_code, missing.get_json()) == (400, {'error': 'The CSRF token is missing.'})
    anonymous = post(client, '/passwords/not-an-id/reveal', token=token)
    assert (anonymous.status_code, anonymous.get_json()) == (401, {'error': 'Authentication required'})
    # Reproduce the old late-response race as a deterministic request order.
    # This remains expected for an explicit logout; index departure must not
    # silently issue that request behind the newly rendered login form.
    logout = client.get('/logout', base_url='https://localhost')
    assert logout.status_code == 302
    assert 'Max-Age=0' in logout.headers['Set-Cookie']
    stale = post(client, '/passwords/not-an-id/reveal', token=token)
    assert (stale.status_code, stale.get_json()) == (400, {'error': 'The CSRF session token is missing.'})
    fresh = post(client, '/passwords/not-an-id/reveal', token=csrf(client))
    assert (fresh.status_code, fresh.get_json()) == (401, {'error': 'Authentication required'})
