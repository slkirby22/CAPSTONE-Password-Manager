"""Deterministic reset/login interleavings on separate file-backed SQLite sessions.

Each subprocess imports the actual app against one temporary synthetic database.
The reset runs on another app context / DB connection while login is paused at a
precise boundary; no sleeps, live files, or probabilistic concurrency assertions.
"""
import os
from pathlib import Path
import subprocess
import sys

import pytest


SCENARIO = r'''
import sys
from app import app, limiter
import functions
import api_functions
from models import db, User

transport, phase = sys.argv[1:]
app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
limiter.enabled = False
with app.app_context():
    db.create_all()
    hashed = functions.pwd_context.hash('Synthetic!99')
    db.session.add_all([User('ADMIN', hashed, 'admin'), User('TARGET', hashed, 'manager')])
    db.session.commit()
admin = app.test_client()
assert admin.post('/login', data={'username': 'ADMIN', 'password': 'Synthetic!99'}).status_code == 302
client = app.test_client()
active = True
commits = 0
connections = []

def reset():
    global active
    active = False
    # Explicit new app context supplies a distinct scoped SQLAlchemy Session.
    with app.app_context():
        connections.append(db.session.connection().connection.driver_connection)
        result = admin.post('/update_user/2', data={
            'username': 'TARGET', 'password': 'Changed!123', 'role': 'manager'})
        assert result.status_code == 200, result.status_code

context = functions.pwd_context if transport == 'web' else api_functions.pwd_context
original_verify = context.verify
original_commit = db.session.commit

def verify(*args, **kwargs):
    matched = original_verify(*args, **kwargs)
    assert matched
    if active and phase == 'verify':
        connections.append(db.session.connection().connection.driver_connection)
        reset()
    return matched

def commit():
    global commits
    if active:
        commits += 1
        # Web audit commits first, then failed-attempt reset. API commits its
        # failed-attempt reset first, before minting the JWT and audit commit.
        boundary = {'audit': 1, 'counter': 2 if transport == 'web' else 1}[phase] if phase != 'verify' else -1
        this_boundary = commits == boundary
    else:
        this_boundary = False
    original_commit()
    if active and this_boundary:
        reset()

context.verify = verify
db.session.commit = commit
if transport == 'web':
    response = client.post('/login', data={'username': 'TARGET', 'password': 'Synthetic!99'})
    assert response.status_code == 302
    assert client.get('/dashboard').status_code == 302
    assert client.get('/get_audit_logs').status_code == 401
else:
    response = client.post('/api/login', json={'username': 'TARGET', 'password': 'Synthetic!99'})
    assert response.status_code == 200
    token = response.json['access_token']
    assert client.get('/api/dashboard', headers={'Authorization': 'Bearer ' + token}).status_code == 401
assert not active, 'Reset interleaving was not reached'
if phase == 'verify':
    assert len(connections) == 2 and connections[0] is not connections[1]
context.verify = original_verify
db.session.commit = original_commit
with app.app_context():
    assert functions.pwd_context.verify('Changed!123', db.session.get(User, 2).password)
assert client.post('/api/login', json={'username': 'TARGET', 'password': 'Synthetic!99'}).status_code == 401
fresh = client.post('/api/login', json={'username': 'TARGET', 'password': 'Changed!123'})
assert fresh.status_code == 200
assert client.get('/api/dashboard', headers={'Authorization': 'Bearer ' + fresh.json['access_token']}).status_code == 410
print('PASS old login proof remains revoked across reset interleaving')
'''


@pytest.mark.parametrize('transport,phase', [('web', 'verify'), ('web', 'audit'),
                                             ('web', 'counter'), ('jwt', 'verify'),
                                             ('jwt', 'counter')])
def test_old_password_login_cannot_issue_new_generation_after_reset(tmp_path, transport, phase):
    env = dict(os.environ, DATABASE_URL='sqlite:///' + str(tmp_path / 'synthetic.db'))
    result = subprocess.run([sys.executable, '-c', SCENARIO, transport, phase],
        cwd=Path(__file__).resolve().parents[1], env=env, capture_output=True,
        text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'PASS old login proof remains revoked' in result.stdout
