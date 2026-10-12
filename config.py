"""Explicit configuration for the legacy, synthetic-data-only prototype."""
import os
from datetime import timedelta
from pathlib import Path

from cryptography.fernet import Fernet
from sqlalchemy.engine import URL, make_url


def load_config(env=None):
    env = os.environ if env is None else env
    mode = env.get('APP_ENV', 'development')
    if mode not in {'development', 'testing', 'synthetic'}:
        raise ValueError('APP_ENV must be development, testing, or synthetic; production is unsupported')
    if env.get('RENDER') and mode != 'synthetic':
        raise ValueError('Render requires explicit synthetic mode')
    if mode == 'synthetic' and env.get('SYNTHETIC_DATA_ONLY') != 'true':
        raise ValueError('Synthetic hosting requires SYNTHETIC_DATA_ONLY=true')

    secrets = {}
    for name in ('SECRET_KEY', 'JWT_SECRET_KEY'):
        value = env.get(name, '')
        if len(value) < 32 or value.lower().startswith(('replace', 'change', 'your-')):
            raise ValueError(f'{name} must be an explicit non-placeholder value of at least 32 characters')
        secrets[name] = value
    if secrets['SECRET_KEY'] == secrets['JWT_SECRET_KEY']:
        raise ValueError('Use distinct session and JWT secrets')
    key = env.get('ENCRYPTION_KEY', '')
    if not key and mode == 'development':
        key = Path('secret.key').read_bytes()
    try:
        Fernet(key)
    except (ValueError, TypeError):
        raise ValueError('ENCRYPTION_KEY must be a valid Fernet key') from None

    uri = env.get('DATABASE_URL')
    if not uri:
        if mode != 'development':
            raise ValueError('DATABASE_URL is required outside development')
        required = ('DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_NAME', 'DB_TYPE')
        if any(not env.get(name) for name in required):
            raise ValueError('Set DATABASE_URL or all explicit DB_* connection settings')
        if env['DB_TYPE'].lower() == 'mysql':
            uri = URL.create('mysql', username=env['DB_USER'], password=env['DB_PASSWORD'],
                             host=env['DB_HOST'], database=env['DB_NAME'])
        elif env['DB_TYPE'].lower() == 'mssql':
            uri = URL.create('mssql+pyodbc', username=env['DB_USER'], password=env['DB_PASSWORD'],
                             host=env['DB_HOST'], database=env['DB_NAME'],
                             query={'driver': 'ODBC Driver 17 for SQL Server', 'autocommit': 'True'})
        else:
            raise ValueError('Unsupported DB_TYPE')
    url = make_url(uri)
    if url.get_backend_name() not in {'sqlite', 'mysql', 'mssql'}:
        raise ValueError('Database backend is not validated; PostgreSQL migration is out of scope')
    if mode == 'synthetic' and url.get_backend_name() != 'sqlite':
        raise ValueError('Synthetic hosting currently supports SQLite only')
    if mode == 'synthetic' and (not url.database or not Path(url.database).is_absolute()):
        raise ValueError('Synthetic SQLite requires an absolute database path')
    minutes = int(env.get('SESSION_TIMEOUT_MINUTES', '15'))
    if not 1 <= minutes <= 1440:
        raise ValueError('SESSION_TIMEOUT_MINUTES must be between 1 and 1440')
    hosts = [host.strip() for host in env.get('TRUSTED_HOSTS', '').split(',') if host.strip()]
    if mode == 'synthetic' and not hosts:
        raise ValueError('TRUSTED_HOSTS is required for synthetic hosting')
    return dict(
        **secrets, APP_ENV=mode, SQLALCHEMY_DATABASE_URI=uri,
        SQLALCHEMY_TRACK_MODIFICATIONS=False, ENCRYPTION_KEY=key,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=minutes),
        SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax', JWT_TOKEN_LOCATION=['headers'],
        TRUSTED_HOSTS=hosts or None, DEBUG=False, RATELIMIT_STORAGE_URI='memory://',
    )
