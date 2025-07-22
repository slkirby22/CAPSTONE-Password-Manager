import os, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import pytest
from flask import Flask
from cryptography.fernet import Fernet

from models import db, User
from functions import create_user, pwd_context


def create_test_app():
    app = Flask(__name__)
    app.config.update({
        'TESTING': True,
        'SECRET_KEY': 'test-secret',
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'ENCRYPTION_KEY': Fernet.generate_key(),
    })
    db.init_app(app)

    @app.route('/')
    def index_route():
        return 'index'

    @app.route('/dashboard')
    def dashboard_route():
        return 'dashboard'

    @app.route('/create_user', methods=['GET', 'POST'])
    def create_user_route():
        return create_user()

    return app


@pytest.fixture
def client():
    app = create_test_app()
    with app.app_context():
        db.create_all()
        admin = User(username='ADMIN', password=pwd_context.hash('adminpass'), role='admin')
        employee = User(username='EMPLOYEE', password=pwd_context.hash('emp'), role='employee')
        db.session.add_all([admin, employee])
        db.session.commit()
    with app.test_client() as client:
        yield client, app


def test_create_user_requires_login(client):
    client, app = client
    response = client.get('/create_user')
    assert response.status_code == 302
    assert response.headers['Location'].endswith('/')


def test_employee_cannot_create_user(client):
    client, app = client
    with client.session_transaction() as sess:
        sess['user_id'] = 2
        sess['username'] = 'EMPLOYEE'
        sess['role'] = 'employee'
    response = client.post('/create_user', data={'username': 'newemp', 'password': 'Secret1!', 'role': 'employee'})
    assert response.status_code == 302
    assert '/dashboard' in response.headers['Location']
    with app.app_context():
        assert User.query.filter_by(username='NEWEMP').first() is None


def test_admin_can_create_user(client, monkeypatch):
    client, app = client
    def fake_render(template, **context):
        return 'rendered'
    monkeypatch.setattr('functions.render_template', fake_render)
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['username'] = 'ADMIN'
        sess['role'] = 'admin'
    response = client.post('/create_user', data={'username': 'newuser', 'password': 'Secret1!', 'role': 'employee'})
    assert response.status_code == 302
    assert '/dashboard' in response.headers['Location']
    with app.app_context():
        user = User.query.filter_by(username='NEWUSER').first()
        assert user is not None
        assert user.role == 'employee'
