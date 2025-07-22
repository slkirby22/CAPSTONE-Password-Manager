import os, sys
from dotenv import load_dotenv
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Ensure environment variables expected by the application are present
load_dotenv()
os.environ.setdefault('JWT_SECRET_KEY', 'test-secret')
import pytest
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager
from models import db, User
from api_functions import authenticate_and_get_token, pwd_context


def create_test_app():
    app = Flask(__name__)
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'JWT_SECRET_KEY': os.environ['JWT_SECRET_KEY']
    })
    JWTManager(app)
    db.init_app(app)

    @app.route('/api/login', methods=['POST'])
    def api_login():
        if not request.is_json:
            return jsonify({'error': 'JSON required'}), 400
        data = request.get_json()
        result = authenticate_and_get_token(
            username=data.get('username'),
            password=data.get('password')
        )
        if not result:
            return jsonify({'error': 'Invalid credentials'}), 401
        elif isinstance(result, tuple):
            return jsonify(result[0]), result[1]
        elif 'error' in result:
            return jsonify(result), 403
        return jsonify(result), 200

    return app


@pytest.fixture
def client():
    app = create_test_app()
    with app.app_context():
        db.create_all()
        user = User(username='TESTUSER',
                    password=pwd_context.hash('secret'),
                    role='employee')
        db.session.add(user)
        db.session.commit()
    with app.test_client() as client:
        yield client, app
    

def test_successful_login(client):
    client, app = client
    response = client.post('/api/login', json={'username': 'TESTUSER', 'password': 'secret'})
    assert response.status_code == 200
    data = response.get_json()
    assert 'access_token' in data
    assert data['user_id']


def test_invalid_credentials(client):
    client, app = client
    response = client.post('/api/login', json={'username': 'TESTUSER', 'password': 'wrong'})
    assert response.status_code == 401
    assert response.get_json()['error'] == 'Invalid credentials'


def test_locked_account(client):
    client, app = client
    with app.app_context():
        user = User.query.filter_by(username='TESTUSER').first()
        user.failed_login_attempts = 4
        db.session.commit()
    response = client.post('/api/login', json={'username': 'TESTUSER', 'password': 'secret'})
    assert response.status_code == 403
    assert response.get_json()['error'] == 'Account locked'
