import os, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import pytest
from flask import Flask

secret_path = os.path.join(os.path.dirname(__file__), '..', 'secret.key')
if not os.path.exists(secret_path):
    with open(secret_path, 'wb') as f:
        f.write(b'testkey')

from app import apply_csp, apply_security_headers


def create_test_app():
    app = Flask(__name__)
    app.config['TESTING'] = True

    @app.route('/')
    def index():
        return 'index'

    app.after_request(apply_csp)
    app.after_request(apply_security_headers)

    return app


@pytest.fixture
def client():
    app = create_test_app()
    with app.test_client() as client:
        yield client


def test_security_headers_present(client):
    response = client.get('/')
    headers = response.headers
    assert 'Content-Security-Policy' in headers
    assert 'X-Content-Type-Options' in headers
    assert 'X-Frame-Options' in headers
    assert 'X-XSS-Protection' in headers
    assert 'Referrer-Policy' in headers
    assert headers['Strict-Transport-Security'] == 'max-age=63072000; includeSubDomains'
    assert headers['Session-Cookie-SameSite'] == 'Lax'
