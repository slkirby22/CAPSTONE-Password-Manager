"""Login regression contracts against app.py, using synthetic in-memory data.

Keep the production route, CSRF exemption and password verifier in these tests;
a reimplemented test route previously hid the locked-account HTTP 200 bug.
"""
import json
import re
import sys
from pathlib import Path

import pytest
from flask_jwt_extended import decode_token

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api_functions import authenticate_and_get_token, pwd_context
from app import app, limiter
from models import User, audit_log, db


USERNAME = 'API_LOGIN_TEST'
PASSWORD = 'Synthetic login password!9'
INVALID_CREDENTIALS = {'error': 'Invalid credentials'}


@pytest.fixture(scope='module')
def password_hash():
    return pwd_context.hash(PASSWORD)


@pytest.fixture
def real_client(monkeypatch, password_hash):
    monkeypatch.setitem(app.config, 'TESTING', True)
    monkeypatch.setattr(limiter, 'enabled', False)
    with app.app_context():
        # Do not allow a misplaced test configuration to touch a real vault.
        assert db.engine.url.get_backend_name() == 'sqlite'
        assert db.engine.url.database == ':memory:'
        db.create_all()
        db.session.add(User(username=USERNAME, password=password_hash,
                            role='employee'))
        db.session.commit()
    try:
        yield app.test_client()
    finally:
        with app.app_context():
            db.session.remove()
            db.drop_all()


def api_login(client, password=PASSWORD, username=USERNAME):
    return client.post('/api/login', json={
        'username': username, 'password': password})


def web_login(client, password=PASSWORD):
    form = client.get('/login', base_url='https://localhost')
    assert form.status_code == 200
    token = re.search(r'name="csrf_token" value="([^"]+)"',
                      form.get_data(as_text=True)).group(1)
    return client.post('/login', base_url='https://localhost', data={
        'username': USERNAME.lower(), 'password': password, 'csrf_token': token,
    }, headers={'Referer': 'https://localhost/login'})


def failed_attempts():
    with app.app_context():
        return User.query.filter_by(username=USERNAME).one().failed_login_attempts


def assert_denied(response):
    assert response.status_code == 401
    assert response.is_json
    assert response.get_json() == INVALID_CREDENTIALS


def test_real_login_preserves_success_contract_and_resets_counter(real_client):
    with app.app_context():
        user = User.query.filter_by(username=USERNAME).one()
        user.failed_login_attempts = 3
        user_id = user.id
        db.session.commit()

    response = api_login(real_client, username=USERNAME.lower())
    assert response.status_code == 200
    data = response.get_json()
    assert set(data) == {'access_token', 'user_id'}
    assert data['user_id'] == user_id
    assert isinstance(data['access_token'], str)
    assert failed_attempts() == 0
    with app.app_context():
        assert decode_token(data['access_token'])['sub'] == str(user_id)
        log = audit_log.query.one()
        assert log.event_type == 'API_LOGIN'
        assert log.user_id == user_id
        assert PASSWORD not in log.event_message

    dashboard = real_client.get('/api/dashboard', headers={
        'Authorization': f"Bearer {data['access_token']}"})
    assert dashboard.status_code == 410
    assert dashboard.get_json()['error'] == 'vault_api_retired'
    with real_client.session_transaction() as session:
        assert 'user_id' not in session


def test_unknown_wrong_and_locked_logins_have_identical_responses(real_client):
    responses = [
        api_login(real_client, username='MISSING_SYNTHETIC_USER'),
        api_login(real_client, password='incorrect synthetic password'),
    ]
    with app.app_context():
        user = User.query.filter_by(username=USERNAME).one()
        user.failed_login_attempts = 4
        db.session.commit()
    responses.extend([
        api_login(real_client),
        api_login(real_client, password='incorrect synthetic password'),
    ])
    for response in responses:
        assert_denied(response)
        assert response.data == responses[0].data
        assert response.content_type == responses[0].content_type
        assert 'Set-Cookie' not in response.headers
    assert failed_attempts() == 4
    with app.app_context():
        assert User.query.count() == 1
        assert audit_log.query.filter_by(event_type='API_LOGIN').count() == 0


def test_fourth_api_failure_locks_account_and_does_not_issue_token(real_client):
    for expected_attempts in range(1, 5):
        assert_denied(api_login(real_client, password='wrong synthetic password'))
        assert failed_attempts() == expected_attempts

    assert_denied(api_login(real_client))
    assert_denied(api_login(real_client, password='wrong synthetic password'))
    assert failed_attempts() == 4
    with app.app_context():
        logs = audit_log.query.order_by(audit_log.id).all()
        assert [log.event_type for log in logs] == ['FAILED_LOGIN'] * 4 + [
            'ACCOUNT_LOCKED', 'ACCOUNT_LOCKED']
        assert all(log.user_id == User.query.one().id for log in logs)
        assert all(PASSWORD not in log.event_message for log in logs)
        assert all('wrong synthetic password' not in log.event_message for log in logs)


def test_locked_account_is_rejected_before_password_verification(real_client, monkeypatch):
    with app.app_context():
        user = User.query.filter_by(username=USERNAME).one()
        user.failed_login_attempts = 4
        db.session.commit()

    def unexpected_verification(*args, **kwargs):
        pytest.fail('Locked accounts must not reach password verification')

    monkeypatch.setattr(pwd_context, 'verify', unexpected_verification)
    assert_denied(api_login(real_client))
    assert failed_attempts() == 4


@pytest.mark.parametrize('api_first', [True, False])
def test_web_and_api_failures_share_the_fourth_failure_threshold(real_client, api_first):
    first, second = (api_login, web_login) if api_first else (web_login, api_login)
    for expected_attempts in range(1, 4):
        response = first(real_client, password='wrong synthetic password')
        assert response.status_code == (401 if api_first else 200)
        assert failed_attempts() == expected_attempts
    response = second(real_client, password='wrong synthetic password')
    assert response.status_code == (200 if api_first else 401)
    assert failed_attempts() == 4

    assert_denied(api_login(real_client))
    web_response = web_login(real_client)
    assert web_response.status_code == 200
    assert b'Invalid username or password' in web_response.data
    assert failed_attempts() == 4
    with real_client.session_transaction() as session:
        assert 'user_id' not in session


@pytest.mark.parametrize('api_success', [True, False])
def test_success_on_either_interface_resets_failures_from_the_other(real_client, api_success):
    failing_login = web_login if api_success else api_login
    for _ in range(3):
        response = failing_login(real_client, password='wrong synthetic password')
        assert response.status_code == (200 if api_success else 401)
    assert failed_attempts() == 3

    response = (api_login if api_success else web_login)(real_client)
    assert response.status_code == (200 if api_success else 302)
    assert failed_attempts() == 0


@pytest.mark.parametrize('body', ['{', '', 'null', '[]', '[{}]', '"text"', '1', 'true'])
def test_malformed_or_non_object_json_is_rejected_without_mutation(real_client, body):
    response = real_client.post('/api/login', data=body, content_type='application/json')
    assert response.status_code == 400
    assert response.get_json() == {'error': 'JSON object required'}
    assert failed_attempts() == 0
    with app.app_context():
        assert audit_log.query.count() == 0


@pytest.mark.parametrize('field', ['username', 'password'])
@pytest.mark.parametrize('value', [None, '', False, 42, [], {}])
def test_invalid_credential_types_are_rejected_without_mutation(real_client, field, value):
    payload = {'username': USERNAME, 'password': PASSWORD, field: value}
    response = real_client.post('/api/login', json=payload)
    assert response.status_code == 400
    assert response.get_json() == {
        'error': 'Username and password must be non-empty strings'}
    assert failed_attempts() == 0
    with app.app_context():
        assert authenticate_and_get_token(payload['username'], payload['password']) is None
        assert audit_log.query.count() == 0


@pytest.mark.parametrize('payload', [{}, {'username': USERNAME}, {'password': PASSWORD}])
def test_missing_credentials_are_rejected(real_client, payload):
    response = real_client.post('/api/login', json=payload)
    assert response.status_code == 400
    assert response.get_json() == {
        'error': 'Username and password must be non-empty strings'}
    assert failed_attempts() == 0


def test_non_json_request_is_rejected(real_client):
    response = real_client.post('/api/login', data=json.dumps({
        'username': USERNAME, 'password': PASSWORD}), content_type='text/plain')
    assert response.status_code == 400
    assert response.get_json() == {'error': 'JSON required'}
    assert failed_attempts() == 0


def test_corrupt_stored_hash_fails_closed(real_client):
    with app.app_context():
        user = User.query.filter_by(username=USERNAME).one()
        user.password = 'synthetic invalid stored hash'
        db.session.commit()
    assert_denied(api_login(real_client))
    assert failed_attempts() == 1


def test_oversized_password_fails_closed(real_client):
    assert_denied(api_login(real_client, password='x' * 5000))
    assert failed_attempts() == 1
