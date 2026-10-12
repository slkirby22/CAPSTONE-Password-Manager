"""Current database identity and legacy role policies (not v2 team ownership)."""
from functools import wraps
import re

from flask import current_app, g, jsonify, redirect, request, session, url_for
from models import User, db
from audit_events import log_event

ROLES = frozenset({'admin', 'manager', 'employee'})
USER_MANAGERS = ('admin', 'manager')


def valid_auth_identity(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{32}', value) is not None


def current_web_user():
    """Bind every cookie to its original account, never a recycled numeric ID."""
    user_id = session.get('user_id')
    binding = session.get('auth_identity')
    user = None
    if (type(user_id) is int and 0 < user_id <= 2**63 - 1
            and valid_auth_identity(binding)):
        user = User.query.filter_by(id=user_id, auth_identity=binding).first()
    if user is None and ('user_id' in session or 'auth_identity' in session):
        # Legacy sessions deliberately sign out rather than being upgraded by ID.
        session.clear()
    return user


def require_web_user(*roles, json_response=False, search_response=False,
                     error='You are not authorized to perform this action.'):
    def decorate(view):
        @wraps(view)
        def protected(*args, **kwargs):
            try:
                user = current_web_user()
            except Exception:
                db.session.rollback()
                current_app.logger.error('Account lookup failed.')
                return jsonify({'error': 'Service unavailable'}), 503
            if user is None:
                if search_response:
                    return jsonify({'found': False})
                if json_response:
                    return jsonify({'error': 'Authentication required'}), 401
                return redirect(url_for('index_route'))
            if roles and user.role not in roles:
                if json_response:
                    return jsonify({'error': 'Administrator access required'}), 403
                log_event(f'User {user.username} attempted restricted action {request.endpoint}.',
                          'UNAUTHORIZED_ACTION', user.id)
                return redirect(url_for('dashboard_route', error=error))
            g.authenticated_user = user
            # These values support display only; authorization above is DB-backed.
            session['role'] = user.role
            session['username'] = user.username
            return view(*args, **kwargs)
        return protected
    return decorate


def can_manage_user(actor, target, operation):
    """Preserve the prototype's manager/peer scope; never allow admin targets."""
    if actor.role not in USER_MANAGERS or target.role not in ROLES:
        return False
    if actor.id == target.id:
        return operation == 'update'
    return actor.role == 'admin' or target.role in ('manager', 'employee')


def can_assign_role(actor, role, target=None):
    if role not in ROLES:
        return False
    if target is not None:
        if not can_manage_user(actor, target, 'update'):
            return False
        if actor.id == target.id:
            return role == target.role
    if actor.role == 'admin':
        return True
    if actor.role != 'manager':
        return False
    # Retaining a peer manager's existing role does not grant a new privilege.
    return role == 'employee' or (target is not None and role == target.role)


def register_jwt_current_user(jwt):
    """A signed token must match the current account incarnation on every request."""
    @jwt.user_lookup_loader
    def lookup_user(header, payload):
        identity = payload.get('sub')
        binding = payload.get('auth_identity')
        if (not isinstance(identity, str)
                or re.fullmatch(r'[1-9][0-9]{0,18}', identity) is None
                or int(identity) > 2**63 - 1
                or not valid_auth_identity(binding)):
            return None
        return User.query.filter_by(id=int(identity), auth_identity=binding).first()

    @jwt.user_lookup_error_loader
    def unknown_user(header, payload):
        return jsonify({'error': 'Authentication required'}), 401
