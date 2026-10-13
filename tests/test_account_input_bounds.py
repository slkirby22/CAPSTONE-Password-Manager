"""Account-mutation bounds, using disposable rows and actual form CSRF."""
import re

import pytest
from werkzeug.datastructures import MultiDict

import functions
from account_input import account_fields, USERNAME_LIMIT, MAX_PASSWORD_SIZE
from app import app, limiter
from models import db, User


@pytest.fixture
def client(monkeypatch):
    assert app.config['SQLALCHEMY_DATABASE_URI'] == 'sqlite:///:memory:'
    monkeypatch.setitem(app.config, 'TESTING', True)
    monkeypatch.setitem(app.config, 'WTF_CSRF_ENABLED', True)
    monkeypatch.setattr(limiter, 'enabled', False)
    with app.app_context():
        db.create_all()
        hashed = functions.pwd_context.hash('Synthetic!99')
        db.session.add_all([User('ADMIN', hashed, 'admin'), User('TARGET', hashed, 'employee')])
        db.session.commit()
    c = app.test_client()
    result = post(c, '/login', {'username': 'ADMIN', 'password': 'Synthetic!99'}, '/login')
    assert result.status_code == 302
    yield c
    with app.app_context():
        db.session.remove()
        db.drop_all()


def post(client, path, data, form='/create_user'):
    html = client.get(form, base_url='https://localhost').text
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)[1]
    data = MultiDict(data)
    data.add('csrf_token', token)
    return client.post(path, data=data, base_url='https://localhost',
                       headers={'Referer': 'https://localhost' + form})


def snapshot():
    with app.app_context():
        return [(u.id, u.username, u.password, u.role, u.auth_identity, u.failed_login_attempts)
                for u in User.query.order_by(User.id).all()]


INVALID = [
    {'username': ''}, {'username': ' \t '}, {'username': 'x' * 256},
    {'username': 'ß' * 128}, {'password': 'A1!' + 'x' * MAX_PASSWORD_SIZE},
    {'username': None}, {'password': None},
]


@pytest.mark.parametrize('path', ['/create_user', '/update_user/2'])
@pytest.mark.parametrize('patch', INVALID)
def test_invalid_mutations_are_safe_400_without_hashing_or_changes(client, monkeypatch, path, patch):
    data = {'username': 'CANDIDATE', 'password': 'Candidate!99', 'role': 'manager'}
    data.update(patch)
    data = {k: v for k, v in data.items() if v is not None}
    before = snapshot()
    def unexpected_hash(*args, **kwargs):
        raise AssertionError('Invalid inputs must not reach hashing')
    monkeypatch.setattr(functions.pwd_context, 'hash', unexpected_hash)
    response = post(client, path, data)
    assert response.status_code == 400
    assert 'class="error"' in response.text
    assert 'Candidate!99' not in response.text
    assert snapshot() == before
    assert client.get('/view_users').status_code == 200


@pytest.mark.parametrize('path', ['/create_user', '/update_user/2'])
@pytest.mark.parametrize('field', ['username', 'password'])
def test_ambiguous_scalar_fields_are_rejected(client, path, field):
    data = MultiDict({'username': 'CANDIDATE', 'password': 'Candidate!99', 'role': 'employee'})
    data.add(field, 'OTHER!99')
    before = snapshot()
    assert post(client, path, data).status_code == 400
    assert snapshot() == before


def test_blank_update_password_preserves_hash_and_identity(client):
    before = snapshot()[1]
    response = post(client, '/update_user/2', {'username': 'Renamed', 'password': '', 'role': 'employee'})
    assert response.status_code == 200
    after = snapshot()[1]
    assert after[1] == 'RENAMED'
    assert after[2:] == before[2:]


def test_normalized_username_boundary_and_unicode_password_are_supported(client):
    # 128 raw characters expand to exactly255; password is4096characters but>4096UTF8bytes.
    username = 'ß' * 127 + 'a'
    password = 'A1!' + '😀' * (MAX_PASSWORD_SIZE - 3)
    response = post(client, '/create_user', {'username': username, 'password': password, 'role': 'employee'})
    assert response.status_code == 302
    with app.app_context():
        user = User.query.filter_by(username=username.upper()).one()
        assert len(user.username) == USERNAME_LIMIT
        assert functions.pwd_context.verify(password, user.password)


@pytest.mark.parametrize('field', ['username', 'password'])
def test_invalid_unicode_does_not_reach_database_or_hash(field):
    form = MultiDict({'username': 'OK', 'password': 'Synthetic!99'})
    form[field] = '\ud800'
    assert account_fields(form)[2] == 'Username and password must contain valid Unicode text.'


def test_password_contents_are_not_normalized():
    password = '  A1!e\u0301\x00  '
    assert account_fields(MultiDict({'username': 'Name', 'password': password}))[:2] == ('NAME', password)
