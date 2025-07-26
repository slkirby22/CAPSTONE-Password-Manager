import os, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import pytest
from flask import Flask
from cryptography.fernet import Fernet

from models import db, User, Password, audit_log
from api_functions import add_password_api, update_password_api, delete_password_api, get_dashboard_data, pwd_context


def create_test_app():
    app = Flask(__name__)
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'ENCRYPTION_KEY': Fernet.generate_key(),
    })
    db.init_app(app)
    return app


@pytest.fixture
def app_ctx():
    app = create_test_app()
    with app.app_context():
        db.create_all()
        user = User(username='TESTUSER', password=pwd_context.hash('secret'), role='employee')
        db.session.add(user)
        db.session.commit()
        yield app


def test_add_password_logs_event(app_ctx):
    user = User.query.filter_by(username='TESTUSER').first()
    result = add_password_api(user.id, {
        'service_name': 'email',
        'username': 'me',
        'password': 'pw'
    })
    assert result['message'] == 'Password added successfully'
    log = audit_log.query.filter_by(event_type='API_PASSWORD_ADD').first()
    assert log is not None
    assert log.user_id == user.id


def test_update_password_logs_event(app_ctx):
    user = User.query.filter_by(username='TESTUSER').first()
    add_res = add_password_api(user.id, {
        'service_name': 'email',
        'username': 'me',
        'password': 'pw'
    })
    password_id = add_res['password_id']
    result = update_password_api(user.id, password_id, {'password': 'new'})
    assert result['message'] == 'Password updated successfully'
    log = audit_log.query.filter_by(event_type='API_PASSWORD_UPDATE').first()
    assert log is not None
    assert log.user_id == user.id


def test_delete_password_logs_event(app_ctx):
    user = User.query.filter_by(username='TESTUSER').first()
    add_res = add_password_api(user.id, {
        'service_name': 'email',
        'username': 'me',
        'password': 'pw'
    })
    password_id = add_res['password_id']
    result = delete_password_api(user.id, password_id)
    assert result['message'] == 'Password deleted successfully'
    log = audit_log.query.filter_by(event_type='API_PASSWORD_DELETE').first()
    assert log is not None
    assert log.user_id == user.id


def test_shared_password_visible_via_api(app_ctx):
    owner = User.query.filter_by(username='TESTUSER').first()
    other = User(username='OTHER', password=pwd_context.hash('pw'), role='employee')
    db.session.add(other)
    db.session.commit()
    res = add_password_api(owner.id, {
        'service_name': 'shared',
        'username': 'me',
        'password': 'pw',
        'shared_with': [other.id]
    })
    assert 'password_id' in res

    data = get_dashboard_data(other.id)
    assert len(data['passwords']) == 1
    assert data['passwords'][0]['service_name'] == 'shared'


def test_shared_user_cannot_update(app_ctx):
    owner = User.query.filter_by(username='TESTUSER').first()
    other = User(username='OTHER2', password=pwd_context.hash('pw'), role='employee')
    db.session.add(other)
    db.session.commit()
    res = add_password_api(owner.id, {
        'service_name': 's2',
        'username': 'me',
        'password': 'pw',
        'shared_with': [other.id]
    })
    pid = res['password_id']
    # Attempt update as shared user
    result = update_password_api(other.id, pid, {'username': 'x'})
    assert result['status_code'] == 404

