"""Narrow current-identity vault access; numeric database keys stay internal."""
from item_identity import is_item_id
from authorization import valid_auth_identity
from models import Password, User


def valid_item_id(value):
    return is_item_id(value)


def access_filter(actor):
    return ((Password.user_id == actor.id) |
            Password.shared_users.any(id=actor.id))


def item_metadata(actor, item_id=None):
    # SQL projection, not an ORM object with a hidden password attribute.
    query = Password.query.with_entities(
        Password.item_id, Password.service_name, Password.username,
        Password.notes, Password.user_id).filter(access_filter(actor))
    if item_id is not None:
        if not valid_item_id(item_id):
            return []
        query = query.filter(Password.item_id == item_id)
    return [{'item_id': row.item_id, 'service_name': row.service_name,
             'username': row.username, 'notes': row.notes,
             'can_edit': row.user_id == actor.id} for row in query.all()]


def resolve_item(actor, item_id, owner_only=False):
    if not valid_item_id(item_id):
        return None
    permission = Password.user_id == actor.id if owner_only else access_filter(actor)
    return Password.query.filter(Password.item_id == item_id, permission).first()


def resolve_recipients(identities):
    # A stale form cannot share with a replacement account reusing an integer PK.
    if any(not valid_auth_identity(value) for value in identities):
        return None
    identities = set(identities)
    users = User.query.filter(User.auth_identity.in_(identities)).all() if identities else []
    if {user.auth_identity for user in users} != identities:
        return None
    return users
