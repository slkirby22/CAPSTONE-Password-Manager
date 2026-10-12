"""Fail-closed startup and real application readiness, using synthetic values."""
import base64

import pytest
from config import load_config


def settings():
    return dict(APP_ENV='synthetic', SYNTHETIC_DATA_ONLY='true',
                DATABASE_URL='sqlite:////tmp/synthetic-test.db',
                SECRET_KEY='synthetic-session-test-value-000000000',
                JWT_SECRET_KEY='synthetic-jwt-test-value-000000000000',
                ENCRYPTION_KEY=base64.urlsafe_b64encode(b'0' * 32).decode(),
                TRUSTED_HOSTS='localhost,127.0.0.1')


@pytest.mark.parametrize('name', ['SECRET_KEY', 'JWT_SECRET_KEY', 'ENCRYPTION_KEY',
                                 'DATABASE_URL', 'TRUSTED_HOSTS', 'SYNTHETIC_DATA_ONLY'])
def test_synthetic_startup_requires_explicit_config(name):
    env = settings()
    del env[name]
    with pytest.raises(ValueError):
        load_config(env)


@pytest.mark.parametrize(('name', 'value'), [
    ('APP_ENV', 'production'), ('SECRET_KEY', 'short'),
    ('SECRET_KEY', 'REPLACE_WITH_A_SECRET_AT_LEAST_32_CHARACTERS'),
    ('JWT_SECRET_KEY', 'your-256-bit-secret'),
    ('ENCRYPTION_KEY', 'not-a-fernet-key'),
    ('DATABASE_URL', 'postgresql://localhost/not-supported'),
    ('DATABASE_URL', 'mysql://localhost/not-tested-for-hosting'),
    ('DATABASE_URL', 'sqlite:///:memory:'),
    ('DATABASE_URL', 'sqlite:///relative.db'),
    ('SESSION_TIMEOUT_MINUTES', '0'), ('SESSION_TIMEOUT_MINUTES', '1441'),
    ('SYNTHETIC_DATA_ONLY', 'false'),
])
def test_unsafe_config_rejected(name, value):
    env = settings()
    env[name] = value
    with pytest.raises(ValueError):
        load_config(env)


def test_secret_stability_and_cookie_flags():
    env = settings()
    first, second = load_config(env), load_config(env)
    assert first == second
    assert first['DEBUG'] is False
    assert first['SESSION_COOKIE_SECURE'] is True
    assert first['SESSION_COOKIE_HTTPONLY'] is True
    assert first['SESSION_COOKIE_SAMESITE'] == 'Lax'
    assert first['TRUSTED_HOSTS'] == ['localhost', '127.0.0.1']


def test_session_and_jwt_secrets_must_differ():
    env = settings()
    env['JWT_SECRET_KEY'] = env['SECRET_KEY']
    with pytest.raises(ValueError):
        load_config(env)


def test_render_cannot_start_in_development():
    env = settings()
    env.update(APP_ENV='development', RENDER='true')
    with pytest.raises(ValueError):
        load_config(env)


def test_health_endpoint_requires_schema_and_exposes_no_details():
    from app import app
    from models import db, User, Password
    with app.app_context():
        db.drop_all()
    client = app.test_client()
    response = client.get('/healthz')
    assert response.status_code == 503
    assert response.get_json() == {'status': 'unavailable'}
    with app.app_context():
        db.create_all()
        assert User.query.count() == 0
        assert Password.query.count() == 0
    try:
        response = client.get('/healthz')
        assert response.status_code == 200
        assert response.get_json() == {'status': 'ok'}
        assert client.get('/').status_code == 200
        assert client.get('/get_audit_logs').status_code == 401
    finally:
        with app.app_context():
            db.session.remove()
            db.drop_all()


@pytest.mark.parametrize('table_name', ['password', 'password_user', 'audit_log', 'token_blacklist'])
def test_health_rejects_partial_schema(table_name):
    from app import app
    from models import db
    with app.app_context():
        db.create_all()
        db.metadata.tables[table_name].drop(db.engine)
    try:
        response = app.test_client().get('/healthz')
        assert response.status_code == 503
        assert response.get_json() == {'status': 'unavailable'}
    finally:
        with app.app_context():
            db.session.remove()
            db.drop_all()


def test_actual_app_rejects_untrusted_host(monkeypatch):
    from app import app
    monkeypatch.setitem(app.config, 'TRUSTED_HOSTS', ['localhost'])
    response = app.test_client().get('/healthz', base_url='https://untrusted.invalid')
    assert response.status_code == 400
