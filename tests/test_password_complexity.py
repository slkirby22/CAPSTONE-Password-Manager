import os, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import pytest
from flask import Flask
from cryptography.fernet import Fernet

from models import db, User, Password
from functions import add_password, update_password, dashboard, pwd_context


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

    @app.route('/add_password', methods=['POST'])
    def add_password_route():
        return add_password()

    @app.route('/update_password/<service>', methods=['POST'])
    def update_password_route(service):
        return update_password(service)

    return app


@pytest.fixture
def client():
    app = create_test_app()
    with app.app_context():
        db.create_all()
        user = User(username='TESTUSER', password=pwd_context.hash('pw'), role='employee')
        db.session.add(user)
        db.session.commit()
        cipher = Fernet(app.config['ENCRYPTION_KEY'])
        encrypted = cipher.encrypt(b'GoodPass1!')
        pw = Password(service_name='email', username='user', password=encrypted, notes='', user_id=user.id)
        db.session.add(pw)
        db.session.commit()
    with app.test_client() as client:
        yield client, app


def test_add_password_rejects_weak(client):
    client, app = client
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['username'] = 'TESTUSER'
        sess['role'] = 'employee'
    resp = client.post('/add_password', data={'service':'svc','username':'u','password':'short','notes':''})
    assert resp.status_code == 302
    with app.app_context():
        assert Password.query.filter_by(service_name='svc').first() is None


def test_update_password_rejects_weak(client):
    client, app = client
    with app.app_context():
        pw = Password.query.filter_by(service_name='email').first()
        pw_id = pw.id
    with client.session_transaction() as sess:
        sess['user_id'] = 1
        sess['username'] = 'TESTUSER'
        sess['role'] = 'employee'
    resp = client.post(f'/update_password/email', data={'pw_id':pw_id,'username':'user','password':'123','notes':''})
    assert resp.status_code == 302
    with app.app_context():
        pw = Password.query.get(pw_id)
        cipher = Fernet(app.config['ENCRYPTION_KEY'])
        decrypted = cipher.decrypt(pw.password).decode()
        assert decrypted == 'GoodPass1!'
