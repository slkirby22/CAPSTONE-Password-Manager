import os, sys
from datetime import datetime, timedelta
from http.cookies import SimpleCookie

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from flask import Flask
from cryptography.fernet import Fernet

from models import db, User
from functions import login, pwd_context


def create_test_app():
    session_minutes = int(os.environ.get('SESSION_TIMEOUT_MINUTES', '15'))
    app = Flask(__name__)
    app.config.update({
        'TESTING': True,
        'SECRET_KEY': 'test-secret',
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'ENCRYPTION_KEY': Fernet.generate_key(),
        'PERMANENT_SESSION_LIFETIME': timedelta(minutes=session_minutes),
    })
    db.init_app(app)

    @app.route('/login', methods=['GET', 'POST'])
    def login_route():
        return login()

    @app.route('/dashboard')
    def dashboard_route():
        return 'dashboard'

    return app


@pytest.fixture
def client(monkeypatch):
    os.environ['SESSION_TIMEOUT_MINUTES'] = '20'
    app = create_test_app()
    with app.app_context():
        db.create_all()
        user = User(username='LOGUSER', password=pwd_context.hash('pw'), role='employee')
        db.session.add(user)
        db.session.commit()
    with app.test_client() as client:
        yield client, app


def test_session_lifetime(client):
    client, app = client
    resp = client.post('/login', data={'username': 'LOGUSER', 'password': 'pw'})
    assert resp.status_code == 302
    assert '/dashboard' in resp.headers['Location']

    with client.session_transaction() as sess:
        assert sess.permanent is True

    cookie = SimpleCookie()
    cookie.load(resp.headers['Set-Cookie'])
    expires_str = cookie['session']['expires']
    expires_dt = datetime.strptime(expires_str, '%a, %d %b %Y %H:%M:%S GMT')
    delta = expires_dt - datetime.utcnow()
    assert abs(delta.total_seconds() - 20 * 60) < 60
    assert app.permanent_session_lifetime == timedelta(minutes=20)
