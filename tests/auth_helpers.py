"""Explicit bound identities for legacy route-matrix fixtures, never auto-injected."""
from models import User, db


def auth_identity_for(client, user_id):
    with client.application.app_context():
        user = db.session.get(User, user_id)
        return user.auth_identity if user else '0' * 32


def credential_binding_for(client, user_id):
    from authorization import credential_binding
    with client.application.app_context():
        user = db.session.get(User, user_id)
        return credential_binding(user, 'web') if user else '0' * 64
