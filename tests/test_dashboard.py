import os, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import pytest
from flask import Flask
from cryptography.fernet import Fernet

from models import db, User, Password
from functions import dashboard, pwd_context


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
        return dashboard()

    return app


@pytest.fixture
def client():
    app = create_test_app()
    with app.app_context():
        db.create_all()
        user = User(username='DASHUSER', password=pwd_context.hash('pw'), role='employee')
        other = User(username='OTHER', password=pwd_context.hash('pw'), role='employee')
        db.session.add_all([user, other])
        db.session.commit()
        cipher = Fernet(app.config['ENCRYPTION_KEY'])
        encrypted = cipher.encrypt(b'secretpw')
        pw = Password(service_name='email', username='user', password=encrypted, notes='', user_id=user.id)
        pw.shared_users.append(other)
        db.session.add(pw)
        db.session.commit()
    with app.test_client() as client:
        yield client, app


def test_dashboard_requires_login(client):
    client, app = client
    response = client.get('/dashboard')
    assert response.status_code == 302
    assert response.headers['Location'].endswith('/')


def test_dashboard_displays_passwords(client, monkeypatch):
    client, app = client
    captured = {}

    def fake_render(template, **context):
        captured['template'] = template
        captured['context'] = context
        return 'rendered'

    monkeypatch.setattr('functions.render_template', fake_render)
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['username'] = 'DASHUSER'
        sess['role'] = 'employee'
    response = client.get('/dashboard')
    assert response.status_code == 200
    assert captured['template'] == 'dashboard.html'
    assert len(captured['context']['passwords']) == 1
    assert captured['context']['passwords'][0]['service_name'] == 'email'
    assert captured['context']['passwords'][0]['password'] == 'secretpw'


def test_dashboard_shows_shared_password(client, monkeypatch):
    client, app = client
    captured = {}

    def fake_render(template, **context):
        captured['template'] = template
        captured['context'] = context
        return 'rendered'

    monkeypatch.setattr('functions.render_template', fake_render)
    with client.session_transaction() as sess:
        sess['user_id'] = 2
        sess['username'] = 'OTHER'
        sess['role'] = 'employee'
    response = client.get('/dashboard')
    assert response.status_code == 200
    assert len(captured['context']['passwords']) == 1
    assert captured['context']['passwords'][0]['service_name'] == 'email'
