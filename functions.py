from flask import Flask, render_template, request, redirect, url_for, session, current_app, jsonify, g
from models import db, User, Password, audit_log
from datetime import datetime, timedelta
from passlib.context import CryptContext
from cryptography.fernet import Fernet
import re
import pytz
from audit_events import log_event
from diagnostics import report_failure, rollback_safely
from authorization import current_web_user, require_web_user, USER_MANAGERS, can_manage_user, can_assign_role, authentication_claims
from account_input import account_fields
from vault_access import item_metadata, resolve_item, resolve_recipients, valid_item_id

pwd_context = CryptContext(schemes=["scrypt"], scrypt__default_rounds=14)
est = pytz.timezone('US/Eastern')

# Helper for password policy checks
def password_meets_requirements(password: str) -> bool:
    """Return True if the password satisfies complexity rules."""
    if len(password) < 8:
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    return True

def index():
    return render_template('index.html')



def login():
    # Check if user is already logged in
    if current_web_user() is not None:
        return redirect(url_for('dashboard_route'))
    
    # Handle login form submission
    if request.method == 'POST':
        username = request.form['username'].upper()
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        error_message = "Invalid username or password"
        if user:
            # Check if the account is locked
            if user.failed_login_attempts <= 3:
                try:
                    claims = authentication_claims(user, 'web')
                    if pwd_context.verify(password, user.password):
                        log_event(f"User {user.username} logged in.", "USER_LOGIN", user.id)

                        user.failed_login_attempts = 0
                        db.session.commit()

                        session.clear()
                        session.update(claims)
                        session['username'] = user.username
                        session['user_id'] = user.id
                        session['role'] = user.role
                        session.permanent = True

                        return redirect(url_for('dashboard_route'))
                    else:
                        log_event(f"Failed login attempt for user {user.username}.", "FAILED_LOGIN", user.id)
                        user.failed_login_attempts += 1
                        db.session.commit()
                        return render_template('login.html', error=error_message)

                except Exception:
                    rollback_safely()
                    session.clear()
                    report_failure('web_login_failed')
                    return render_template('login.html', error=error_message)
            else:
                log_event(
                    f"Account locked for user {user.username} due to too many failed login attempts.",
                    "ACCOUNT_LOCKED",
                    user.id,
                )
                return render_template('login.html', error=error_message)
        else:
            return render_template('login.html', error=error_message)
   
    return render_template('login.html')


@require_web_user()
def dashboard():
    try:
        return render_template('dashboard.html',
                               passwords=item_metadata(g.authenticated_user),
                               error=request.args.get('error'))
    except Exception:
        db.session.rollback()
        current_app.logger.error('Vault metadata request failed.')
        return 'Vault unavailable.', 500


@require_web_user()
def select_password_for_edit(item_id):
    if not valid_item_id(item_id):
        return 'Item unavailable.', 404
    try:
        actor = g.authenticated_user
        selected = item_metadata(actor, item_id)
        if not selected:
            return 'Item unavailable.', 404
        selected = selected[0]
        if selected['can_edit']:
            # Explicit projection: no Password object or encrypted field enters
            # template context, including this owner-only recipient metadata.
            users = User.query.with_entities(User.auth_identity, User.username).join(Password.shared_users).filter(
                Password.item_id == item_id, Password.user_id == actor.id).all()
            selected['shared_users'] = [
                {'auth_identity': user.auth_identity, 'username': user.username}
                for user in users]
        return render_template('dashboard.html', selected_password=selected,
                               passwords=item_metadata(actor),
                               error=request.args.get('error'))
    except Exception:
        db.session.rollback()
        current_app.logger.error('Vault metadata request failed.')
        return 'Vault unavailable.', 500


@require_web_user(json_response=True)
def reveal_password(item_id):
    try:
        item = resolve_item(g.authenticated_user, item_id)
        if item is None:
            return jsonify({'error': 'Item unavailable'}), 404
        value = Fernet(current_app.config['ENCRYPTION_KEY']).decrypt(item.password).decode()
        return jsonify({'item_id': item.item_id, 'password': value})
    except Exception:
        db.session.rollback()
        current_app.logger.error('Item reveal failed.')
        return jsonify({'error': 'Unable to reveal item'}), 500


@require_web_user()
def retired_web_vault():
    return 'This vault route is retired. Open the dashboard to select an item.', 410


def logout():
    # An old cookie must not attribute an event to a recycled account ID.
    user = current_web_user()
    if user is not None:
        log_event(f"User {user.username} logged out.", "USER_LOGOUT", user.id)
    session.clear()
    return redirect(url_for('index_route'))


@require_web_user(*USER_MANAGERS)
def create_user():
    
    current_user = g.authenticated_user
    current_user_role = current_user.role

    
    if request.method == 'POST':
        username, password, field_error = account_fields(request.form)
        if field_error:
            return render_template('create_user.html', error=field_error,
                                   current_user_role=current_user_role), 400
        role = request.form['role']

        if not can_assign_role(current_user, role):
            log_event(f'User {current_user.username} attempted a restricted account action.',
                      'UNAUTHORIZED_ACTION', current_user.id)
            return render_template('create_user.html', error="Invalid role, please try again.", current_user_role=current_user_role)


        # Password Policies
        if len(password) < 8:
            log_event(f"{current_user.username} attempted to create a user with an invalid password.", "INVALID_PASSWORD", current_user.id)
            return render_template('create_user.html', error="Password must be at least 8 characters long.", username=username, role=role)
        if not re.search(r"\d", password):
            log_event(f"{current_user.username} attempted to create a user with an invalid password.", "INVALID_PASSWORD", current_user.id)
            return render_template('create_user.html', error="Password must contain at least one number.", username=username, role=role)
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            log_event(f"{current_user.username} attempted to create a user with an invalid password.", "INVALID_PASSWORD", current_user.id)
            return render_template('create_user.html', error="Password must contain at least one special character.", username=username, role=role)
        if not re.search(r"[A-Z]", password):
            log_event(f"{current_user.username} attempted to create a user with an invalid password.", "INVALID_PASSWORD", current_user.id)
            return render_template('create_user.html', error="Password must contain at least one uppercase letter.", username=username, role=role)

        # Hash the password before storing it
        password = pwd_context.hash(password)

        if User.query.filter_by(username=username).first():
            return render_template('create_user.html', error="User already exists, please try again.")
        
        # Commit the new user to the database
        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()

        log_event(f"User {current_user.username} created user {username}.", "USER_CREATE", current_user.id)

        return redirect(url_for('dashboard_route'))
        
    return render_template('create_user.html', current_user_role=current_user_role)


@require_web_user(*USER_MANAGERS)
def view_users():

    # Get current user and their role for authorization
    current_user = g.authenticated_user
    current_user_role = current_user.role

    users = User.query.all()

    # Handle form submission for selecting a user to edit
    selected_user = None
    if request.method == 'POST':
        selected_user_id = request.form.get('selected_user_id')
        selected_user = User.query.filter_by(id=selected_user_id).first()

    if selected_user and not can_manage_user(current_user, selected_user, 'update'):
        log_event(f'User {current_user.username} attempted a restricted account action.',
                  'UNAUTHORIZED_ACTION', current_user.id)
        return redirect(url_for('view_users_route', error="You are not authorized to edit this user."))

    log_event(f"User {current_user.username} viewed or selected user to edit.", "USER_VIEW", current_user.id)

    return render_template('view_users.html', users=users, selected_user=selected_user, current_user_role=current_user_role)


@require_web_user(*USER_MANAGERS)
def select_user_for_edit():
    # Keep the legacy URL as an alias of the working selection form.
    return view_users()


@require_web_user(*USER_MANAGERS)
def update_user(user_id):

    # Get current user and their role for authorization
    current_user = g.authenticated_user
    current_user_role = current_user.role

    
    # Fetch the user to be updated
    db_user = User.query.filter_by(id=user_id).first()

    # Make sure the form is passed correctly
    if not db_user:
        return redirect(url_for('view_users_route'))

    if not can_manage_user(current_user, db_user, 'update'):
        log_event(f'User {current_user.username} attempted a restricted account action.',
                  'UNAUTHORIZED_ACTION', current_user.id)
        return redirect(url_for('view_users_route', error="You are not authorized to update this user."))
    # Self profile updates preserve the current role even with a crafted field.
    new_role = (db_user.role if current_user.id == db_user.id
                else request.form.get('role', db_user.role))
    if not can_assign_role(current_user, new_role, db_user):
        log_event(f'User {current_user.username} attempted a restricted account action.',
                  'UNAUTHORIZED_ACTION', current_user.id)
        return redirect(url_for('view_users_route', error="Invalid role assignment."))

    new_username, submitted_password, field_error = account_fields(
        request.form, allow_empty_password=True)
    if field_error:
        return render_template('view_users.html', error=field_error,
                               users=User.query.all(), selected_user=db_user,
                               erroronuser=db_user.username,
                               current_user_role=current_user_role), 400

    # Handle password update and validation
    password_changed = bool(submitted_password)
    if password_changed:
        new_password = submitted_password

        if len(new_password) < 8:
            log_event(f"{current_user.username} attempted to update user {user_id} with an invalid password.", "INVALID_PASSWORD", current_user.id)
            return render_template('view_users.html', error="Password must be at least 8 characters long.", users=User.query.all(), erroronuser=new_username, selected_user=db_user)

        if not re.search(r"\d", new_password):
            log_event(f"{current_user.username} attempted to update user {user_id} with an invalid password.", "INVALID_PASSWORD", current_user.id)
            return render_template('view_users.html', error="Password must contain at least one number.", users=User.query.all(), erroronuser=new_username, selected_user=db_user)

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", new_password):
            log_event(f"{current_user.username} attempted to update user {user_id} with an invalid password.", "INVALID_PASSWORD", current_user.id)
            return render_template('view_users.html', error="Password must contain at least one special character.", users=User.query.all(), erroronuser=new_username, selected_user=db_user)

        if not re.search(r"[A-Z]", new_password):
            log_event(f"{current_user.username} attempted to update user {user_id} with an invalid password.", "INVALID_PASSWORD", current_user.id)
            return render_template('view_users.html', error="Password must contain at least one uppercase letter.", users=User.query.all(), erroronuser=new_username, selected_user=db_user)

        new_password = pwd_context.hash(new_password)
    else:
        new_password = db_user.password

    # Ensure the username is not taken
    if new_username != db_user.username and User.query.filter_by(username=new_username).first():
        return render_template('view_users.html', error="Username taken, please try again.", users=User.query.all(), erroronuser=new_username, selected_user=db_user)

    # Update the user in the database
    db_user.username = new_username
    db_user.password = new_password
    db_user.role = new_role
    db.session.commit()

    # Fetch the updated user from the database again (ensure the latest data)
    updated_user = User.query.filter_by(id=user_id).first()

    # If the logged-in user is updating their own account, log them out
    if session['user_id'] == updated_user.id:
        if password_changed:
            # Clear this cookie immediately; all copies and JWTs are invalid as
            # soon as the password transaction commits, even without this redirect.
            session.clear()
        else:
            session['username'] = updated_user.username
        log_event(f"User {current_user.username} updated their own account.", "USER_UPDATE", current_user.id)
        return redirect(url_for('logout_route'))

    else:
        log_event(f"User {current_user.username} updated user {new_username}.", "USER_UPDATE", current_user.id)
        # Make sure the updated user data is passed to the template
        return render_template('view_users.html', message="User updated successfully!", users=User.query.all(), messageonuser=updated_user.username, selected_user=updated_user)


@require_web_user(*USER_MANAGERS)
def delete_user(user_id):
    
    # Get current user and their role for authorization
    current_user = g.authenticated_user
    current_user_role = current_user.role
    

    # Fetch the user to be deleted
    db_user = User.query.filter_by(id=user_id).first()

    if db_user and not can_manage_user(current_user, db_user, 'delete'):
        log_event(f'User {current_user.username} attempted a restricted account action.',
                  'UNAUTHORIZED_ACTION', current_user.id)
        return redirect(url_for('view_users_route', error="You are not authorized to delete this user."))

    if db_user:
        # Delete all passwords associated with the user
        user_passwords = Password.query.filter_by(user_id=user_id).all()

        for password in user_passwords:
            db.session.delete(password)
        
        db.session.delete(db_user)
        db.session.commit()

        log_event(f"User {current_user.username} deleted user {db_user.username}.", "USER_DELETE", current_user.id)

        return redirect(url_for('view_users_route'))
    
    return redirect(url_for('view_users_route', error="User not found."))


def _set_account_lock(user_id, locked):
    current_user = g.authenticated_user
    target = User.query.filter_by(id=user_id).first()
    if target is None:
        return redirect(url_for('view_users_route', error="User not found."))
    operation = 'lock' if locked else 'unlock'
    if not can_manage_user(current_user, target, operation):
        log_event(f'User {current_user.username} attempted a restricted account action.',
                  'UNAUTHORIZED_ACTION', current_user.id)
        return redirect(url_for('view_users_route', error="You are not authorized to change this account."))
    if (target.failed_login_attempts > 3) == locked:
        return render_template('view_users.html',
                               error="Account already locked." if locked else "Account is not locked.",
                               users=User.query.all(), erroronuser=target.username,
                               selected_user=target, current_user_role=current_user.role)
    target.failed_login_attempts = 4 if locked else 0
    db.session.commit()
    log_event(f"User {current_user.username} {operation}ed user {target.username}.",
              'ACCOUNT_LOCK' if locked else 'ACCOUNT_UNLOCK', current_user.id)
    return render_template('view_users.html', message="Account locked" if locked else "Account unlocked",
                           users=User.query.all(), messageonuser=target.username,
                           selected_user=target, current_user_role=current_user.role)


@require_web_user(*USER_MANAGERS)
def unlock_account(user_id):
    return _set_account_lock(user_id, False)


@require_web_user(*USER_MANAGERS)
def lock_account(user_id):
    return _set_account_lock(user_id, True)


@require_web_user(search_response=True)
def search_user():
    username = request.args.get('username', '').upper()
    if not username:
        return jsonify({'found': False})

    user = User.query.filter_by(username=username).first()
    if user and user.id != session['user_id']:
        return jsonify({'found': True, 'auth_identity': user.auth_identity, 'username': user.username})
    return jsonify({'found': False})


@require_web_user()
def add_password():
    from audit_events import stage_event
    if any(key in request.form for key in ('item_id', 'pw_id', 'id')):
        return 'Invalid password creation.', 400
    if any(request.form.get(field) is None for field in ('service', 'username', 'password')):
        return 'Invalid password creation.', 400
    actor = g.authenticated_user
    try:
        recipients = resolve_recipients(request.form.getlist('shared_users'))
        if recipients is None:
            return 'Invalid password creation.', 400
        encrypted = Fernet(current_app.config['ENCRYPTION_KEY']).encrypt(
            request.form['password'].encode())
        item = Password(service_name=request.form['service'],
                        username=request.form['username'], password=encrypted,
                        notes=request.form.get('notes'), user_id=actor.id,
                        shared_users=recipients)
        db.session.add(item)
        stage_event(f'User {actor.username} added a password.', 'PASSWORD_ADD', actor.id)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.error('Password creation failed; transaction rolled back.')
        return 'Unable to add password.', 500
    return redirect(url_for('dashboard_route'))


@require_web_user()
def update_password(item_id):
    from audit_events import stage_event
    # The canonical path is the sole selector. Reject legacy/caller identity fields.
    if any(key in request.form for key in ('item_id', 'pw_id', 'id')):
        return 'Invalid password update.', 400
    username = request.form.get('username')
    replace = request.form.get('replace_password')
    if (username is None or replace not in (None, '1')
            or (replace == '1' and 'password' not in request.form)):
        return 'Invalid password update.', 400
    actor = g.authenticated_user
    try:
        item = resolve_item(actor, item_id, owner_only=True)
        if item is None:
            return 'Item unavailable.', 404
        recipients = resolve_recipients(request.form.getlist('shared_users'))
        if recipients is None:
            return 'Invalid password update.', 400
        encrypted = None
        if replace == '1':
            encrypted = Fernet(current_app.config['ENCRYPTION_KEY']).encrypt(
                request.form['password'].encode())
        item.username = username
        item.notes = request.form.get('notes')
        if encrypted is not None:
            item.password = encrypted
        item.shared_users = recipients
        stage_event(f'User {actor.username} updated password {item.item_id}.',
                    'PASSWORD_SHARE', actor.id)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.error('Password update failed; transaction rolled back.')
        return 'Unable to update password.', 500
    return redirect(url_for('dashboard_route'))


@require_web_user()
def delete_password(item_id):
    from audit_events import stage_event
    if any(key in request.form for key in ('item_id', 'pw_id', 'id')):
        return 'Invalid password deletion.', 400
    actor = g.authenticated_user
    try:
        item = resolve_item(actor, item_id, owner_only=True)
        if item is None:
            return 'Item unavailable.', 404
        db.session.delete(item)
        stage_event(f'User {actor.username} deleted a password.', 'PASSWORD_DELETE', actor.id)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.error('Password deletion failed; transaction rolled back.')
        return 'Unable to delete password.', 500
    return redirect(url_for('dashboard_route'))


@require_web_user('admin', error='You are not authorized to view the audit log.')
def audit_log_viewer():
    
    # Get current user and their role for authorization
    current_user = g.authenticated_user
    current_user_role = current_user.role

    
    log_event(f"User {current_user.username} viewed the audit log.", "AUDIT_LOG_VIEW", current_user.id)

    # Only show the past day of logs by default
    default_start_date = datetime.now(est) - timedelta(days=1)
    audit_logs = audit_log.query.filter(audit_log.event_time >= default_start_date).all()

    return render_template('audit_log.html', audit_logs=audit_logs, current_user_role=current_user_role, default_start_date=default_start_date.strftime('%Y-%m-%d'))


@require_web_user('admin', json_response=True)
def get_audit_logs():
    # Get the start and end dates from the request
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = audit_log.query
    if start_date:
        query = query.filter(audit_log.event_time >= start_date)
    if end_date:
        query = query.filter(audit_log.event_time <= end_date)

    # Fetch the logs from the database and return them as JSON
    logs = query.all()
    return jsonify([{
        'id': log.id,
        'event_time': log.event_time.strftime('%Y-%m-%d %H:%M:%S'),
        'event_message': log.event_message,
        'event_type': log.event_type,
        'user_id': log.user_id
    } for log in logs])
