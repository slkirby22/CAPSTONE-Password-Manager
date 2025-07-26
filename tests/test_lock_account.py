import os, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import pytest
from flask import Flask
from cryptography.fernet import Fernet

from models import db, User
from functions import lock_account, pwd_context


def create_test_app():
    app = Flask(__name__)
    app.config.update({
        'TESTING': True,
        'SECRET_KEY': 'test-secret',
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'ENCRYPTION_KEY': Fernet.generate_key(),
    })
    db.init_app(app)

    @app.route('/lock_account/<user_id>', methods=['POST'])
    def lock_account_route(user_id):
        return lock_account(user_id)

    @app.route('/')
    def index_route():
        return 'index'

    return app


@pytest.fixture
def client():
    app = create_test_app()
    with app.app_context():
        db.create_all()
        admin = User(username='ADMIN', password=pwd_context.hash('pw'), role='admin')
        user = User(username='EMP', password=pwd_context.hash('pw'), role='employee')
        db.session.add_all([admin, user])
        db.session.commit()
    with app.test_client() as client:
        yield client, app


def test_admin_can_lock_account(client, monkeypatch):
    client, app = client

    def fake_render(template, **context):
        return 'rendered'

    monkeypatch.setattr('functions.render_template', fake_render)

    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['username'] = 'ADMIN'
        sess['role'] = 'admin'
    resp = client.post('/lock_account/2')
    assert resp.status_code == 200
    with app.app_context():
        user = User.query.get(2)
        assert user.failed_login_attempts > 3

