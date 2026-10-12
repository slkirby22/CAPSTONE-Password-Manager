"""Runtime-upgrade contracts against real routes and legacy synthetic records.

These public fixtures were generated with cryptography 44.0.1/passlib 1.7.4.
They are deliberately not deployment credentials or real vault data.
"""
import base64
import sys
from datetime import timedelta
from pathlib import Path

# Match existing test modules for direct pytest invocation from a clean checkout.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jwt
import pytest
from cryptography.fernet import Fernet, InvalidToken
from flask_jwt_extended import create_access_token

from api_functions import pwd_context
from app import app, limiter
from models import db, User, Password

LEGACY_HASH = (
    '$scrypt$ln=14,r=8,p=1$wVgLgTAmZCylFAKgNKa0Fg$'
    'UTkdsOhzrvXk0OrLvpXS6gIsn6C61SOTyzSwlSTprRA'
)
LEGACY_CIPHERTEXT = (
    b'gAAAAABoTuGABnQtxxEPujqszw--qO2JxtFNSyAeQu0C9C34b0y90OIu4nAkix0P75HuKkkOzyY'
    b'of0v6FNhLblh_J26mKEoQ82CqLYrLZxfmcHvf-uyHa6JLDntWn6OJ-9In_Q-m76MO'
)


@pytest.fixture
def real_client(monkeypatch):
    monkeypatch.setitem(app.config, 'TESTING', True)
    monkeypatch.setattr(limiter, 'enabled', False)
    with app.app_context():
        db.create_all()
        user = User(username='COMPATIBILITY', password=LEGACY_HASH, role='employee')
        db.session.add(user)
        db.session.flush()
        db.session.add(Password(user_id=user.id, service_name='synthetic legacy',
                                username='synthetic', password=LEGACY_CIPHERTEXT, notes='synthetic'))
        db.session.commit()
    try:
        yield app.test_client()
    finally:
        with app.app_context():
            db.session.remove()
            db.drop_all()


def test_legacy_scrypt_and_fernet_records_survive_upgrade(real_client):
    response = real_client.post('/api/login', json={
        'username': 'compatibility', 'password': 'synthetic legacy login'})
    assert response.status_code == 200
    token = response.get_json()['access_token']
    headers = {'Authorization': f'Bearer {token}'}
    response = real_client.get('/api/dashboard', headers=headers)
    assert response.status_code == 410
    assert response.get_json()['error'] == 'vault_api_retired'
    # Legacy ciphertext compatibility survives without restoring bulk API decrypt.
    assert Fernet(app.config['ENCRYPTION_KEY']).decrypt(LEGACY_CIPHERTEXT).decode() == (
        'synthetic legacy compatibility password')
    assert not pwd_context.verify('incorrect synthetic password', LEGACY_HASH)
    assert real_client.post('/api/logout', headers=headers).status_code == 200
    revoked = real_client.get('/api/dashboard', headers=headers)
    assert revoked.status_code == 401
    assert revoked.get_json() == {'error': 'Token revoked'}


def test_fernet_rejects_corrupted_legacy_record_and_wrong_key():
    raw = bytearray(base64.urlsafe_b64decode(LEGACY_CIPHERTEXT))
    raw[-1] ^= 1
    with pytest.raises(InvalidToken):
        Fernet(app.config['ENCRYPTION_KEY']).decrypt(base64.urlsafe_b64encode(raw))
    with pytest.raises(InvalidToken):
        Fernet(base64.urlsafe_b64encode(b'1' * 32)).decrypt(LEGACY_CIPHERTEXT)


@pytest.mark.parametrize('kind', ['expired', 'wrong-key', 'unsigned', 'malformed'])
def test_real_api_rejects_invalid_tokens(real_client, kind):
    with app.app_context():
        user = User.query.filter_by(username='COMPATIBILITY').one()
        if kind == 'expired':
            token = create_access_token(identity=str(user.id), expires_delta=timedelta(seconds=-1))
        elif kind == 'wrong-key':
            token = jwt.encode({'sub': str(user.id)}, 'synthetic-wrong-signing-key-00000000', algorithm='HS256')
        elif kind == 'unsigned':
            token = jwt.encode({'sub': str(user.id)}, '', algorithm='none')
        else:
            token = 'not.a.valid.jwt'
    response = real_client.get('/api/dashboard', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code in (401, 422)
    assert 'passwords' not in response.get_json()


def test_cors_retains_exact_legacy_origin_without_cookie_credentials(real_client):
    response = real_client.options('/api/passwords', headers={
        'Origin': 'http://localhost:8081',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Authorization,Content-Type',
    })
    assert response.status_code == 200
    assert response.headers['Access-Control-Allow-Origin'] == 'http://localhost:8081'
    assert 'Access-Control-Allow-Credentials' not in response.headers
    assert 'POST' in response.headers['Access-Control-Allow-Methods']
    assert 'Authorization' in response.headers['Access-Control-Allow-Headers']


@pytest.mark.parametrize('origin', [
    'https://attacker.invalid', 'http://localhost:8081.attacker.invalid',
    'http://localhost:80810', 'null',
])
def test_cors_denies_unapproved_origins(real_client, origin):
    response = real_client.options('/api/passwords', headers={
        'Origin': origin, 'Access-Control-Request-Method': 'POST'})
    assert 'Access-Control-Allow-Origin' not in response.headers
    assert 'Access-Control-Allow-Credentials' not in response.headers


def test_cors_does_not_expand_to_non_api_routes(real_client):
    response = real_client.get('/healthz', headers={'Origin': 'http://localhost:8081'})
    assert response.status_code == 200
    assert 'Access-Control-Allow-Origin' not in response.headers
