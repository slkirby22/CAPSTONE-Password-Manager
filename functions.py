from flask import Flask, render_template, request, redirect, url_for, session, current_app, jsonify, g
from models import db, User, Password, audit_log
from datetime import datetime, timedelta
from passlib.context import CryptContext
from cryptography.fernet import Fernet
import re
import pytz
from audit_events import log_event
from authorization import current_web_user, require_web_user, USER_MANAGERS, can_manage_user, can_assign_role

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
                    if pwd_context.verify(password, user.password):
                        session.clear()
                        session['auth_identity'] = user.auth_identity
                        session['username'] = user.username
                        session['user_id'] = user.id
                        session['role'] = user.role
                        session.permanent = True

                        log_event(f"User {user.username} logged in.", "USER_LOGIN", user.id)

                        user.failed_login_attempts = 0
                        db.session.commit()

                        return redirect(url_for('dashboard_route'))
                    else:
                        log_event(f"Failed login attempt for user {user.username}.", "FAILED_LOGIN", user.id)
                        user.failed_login_attempts += 1
                        db.session.commit()
                        return render_template('login.html', error=error_message)

                except Exception as e:
                    print(f"Error verifying password: {e}")
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

    error_msg = request.args.get('error')

    key = current_app.config['ENCRYPTION_KEY']
    cipher_suite = Fernet(key)

    current_user = g.authenticated_user

    # Display the dashboard with decrypted passwords if the user is found
    if current_user:
        user_role = current_user.role
        user_passwords = Password.query.filter(
            (Password.user_id == current_user.id) |
            (Password.shared_users.any(id=current_user.id))
        ).all()

        decrypted_passwords = []
        for pw in user_passwords:
            decrypted_passwords.append({
                'id': pw.id,
                'service_name': pw.service_name,
                'username': pw.username,
                'password': cipher_suite.decrypt(pw.password).decode(),  # Decrypt here
                'notes': pw.notes
            })
            
        return render_template('dashboard.html', passwords=decrypted_passwords, error=error_msg)
    else:
        return redirect(url_for('index_route'))


@require_web_user()
def select_password_for_edit():

    service_name = request.args.get('service_name')
    error_msg = request.args.get('error')
    
    if not service_name:
        return redirect(url_for('dashboard_route'))

    key = current_app.config['ENCRYPTION_KEY']
    cipher_suite = Fernet(key)

    current_user = g.authenticated_user

    if current_user:
        # Fetch the selected password for editing (owned or shared)
        selected_password = Password.query.filter(
            (Password.user_id == current_user.id) |
            (Password.shared_users.any(id=current_user.id)),
            Password.service_name == service_name
        ).first()

        if selected_password:
            
            user_passwords = Password.query.filter(
                (Password.user_id == current_user.id) |
                (Password.shared_users.any(id=current_user.id))
            ).all()

            # Decrypt the password
            decrypted_password = cipher_suite.decrypt(selected_password.password).decode()

            # Pass decrypted data to template
            return render_template(
                'dashboard.html',
                selected_password={
                    'id': selected_password.id,
                    'service_name': selected_password.service_name,
                    'username': selected_password.username,
                    'password': decrypted_password,
                    'notes': selected_password.notes,
                    'shared_users': [{'id': u.id, 'username': u.username} for u in selected_password.shared_users],
                    'owner_id': selected_password.user_id
                },
                passwords=user_passwords,
                error=error_msg
                )
        
        else:
            return redirect(url_for('dashboard_route'))
    else:
        return redirect(url_for('index_route'))


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
        username = request.form['username'].upper()
        password = request.form['password']
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

    new_username = request.form['username'].upper()

    # Handle password update and validation
    if request.form['password']:
        new_password = request.form['password']

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
        session['username'] = updated_user.username  # Ensure session reflects updated username
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
        return jsonify({'found': True, 'id': user.id, 'username': user.username})
    return jsonify({'found': False})


@require_web_user()
def add_password():
    
    key = current_app.config['ENCRYPTION_KEY']
    cipher_suite = Fernet(key)

    # Get the form data
    service = request.form['service']
    password = request.form['password']
    new_username = request.form['username']
    notes = request.form['notes']
    shared_user_ids = request.form.getlist('shared_users')

    # Get the current user
    current_user = g.authenticated_user

    if current_user:
        encrypted_password = cipher_suite.encrypt(password.encode())
        shared_users = []
        if shared_user_ids:
            shared_users = User.query.filter(User.id.in_(shared_user_ids)).all()

        new_password = Password(service_name=service, username=new_username, password=encrypted_password, notes=notes, user_id=current_user.id, shared_users=shared_users)
        db.session.add(new_password)
        db.session.commit()

        log_event(f"User {current_user.username} added a password.", "PASSWORD_ADD", current_user.id)
        if shared_user_ids:
            log_event(f"User {current_user.username} shared password for {service} with users: {', '.join(shared_user_ids)}", "PASSWORD_SHARE", current_user.id)

    return redirect(url_for('dashboard_route'))


@require_web_user()
def update_password(service):
    from audit_events import stage_event

    password_id = request.form.get('pw_id')
    username = request.form.get('username')
    password = request.form.get('password')
    notes = request.form.get('notes')
    shared_user_ids = request.form.getlist('shared_users')

    # Validate all submitted identifiers and required fields before any writes.
    # Empty stored credentials remain allowed under the legacy vault policy;
    # account-password complexity rules do not apply to stored credentials.
    if username is None or password is None or password_id is None:
        return 'Invalid password update.', 400
    try:
        identifiers = [password_id, *shared_user_ids]
        if any(not re.fullmatch(r'[0-9]+', value) for value in identifiers):
            return 'Invalid password update.', 400
        password_id = int(password_id)
        shared_ids = {int(value) for value in shared_user_ids}
        if password_id <= 0 or any(value <= 0 for value in shared_ids):
            return 'Invalid password update.', 400
    except ValueError:
        return 'Invalid password update.', 400

    current_user = g.authenticated_user
    try:
        password_to_update = Password.query.filter_by(id=password_id).first()
        if not password_to_update or password_to_update.user_id != current_user.id:
            return redirect(url_for('dashboard_route'))

        shared_users = User.query.filter(User.id.in_(shared_ids)).all() if shared_ids else []
        if {user.id for user in shared_users} != shared_ids:
            return 'Invalid password update.', 400

        # Finish encryption before changing fields or share relationships.
        cipher_suite = Fernet(current_app.config['ENCRYPTION_KEY'])
        encrypted_password = cipher_suite.encrypt(password.encode())
        password_to_update.username = username
        password_to_update.notes = notes
        password_to_update.password = encrypted_password
        password_to_update.shared_users = shared_users
        stage_event(
            f"User {current_user.username} updated password share for {password_id}. "
            f"Password now shared with {sorted(shared_ids)}",
            'PASSWORD_SHARE', current_user.id,
        )
        # The credential, shares and success audit are one deliberate transaction.
        db.session.commit()
    except Exception:
        db.session.rollback()
        # Neither response nor diagnostic should include secret-bearing exception text.
        current_app.logger.error('Password update failed; transaction rolled back.')
        return 'Unable to update password.', 500

    return redirect(url_for('dashboard_route'))


@require_web_user()
def delete_password(service):
    
    # Get the password ID from the form and find it in the database
    password_id = request.form['pw_id']
    password_entry = Password.query.filter_by(id=password_id).first()
    current_user = g.authenticated_user

    # Delete the password entry if it exists and belongs to the user
    if password_entry and password_entry.user_id == current_user.id:
        db.session.delete(password_entry)
        db.session.commit()

        log_event(f"User {session['username']} deleted a password.", "PASSWORD_DELETE", session['user_id'])
    
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
