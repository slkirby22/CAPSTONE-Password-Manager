from flask import Flask, render_template, request, redirect, url_for, session, current_app, jsonify
from models import db, User, Password, audit_log
from datetime import datetime, timedelta
from passlib.context import CryptContext
from cryptography.fernet import Fernet
import re
import pytz

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


def log_event(message, event_type, user_id=None):
    try:
        new_log = audit_log(
            event_time = datetime.now(est),
            user_id = user_id,
            event_message = message,
            event_type = event_type
        )
        db.session.add(new_log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error logging event: {e}")


def login():
    # Check if user is already logged in
    if 'user_id' in session:
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


def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index_route'))

    error_msg = request.args.get('error')

    key = current_app.config['ENCRYPTION_KEY']
    cipher_suite = Fernet(key)

    current_user = User.query.filter_by(id=session['user_id']).first()

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
            
        other_users = User.query.filter(User.id != current_user.id).all()
        return render_template('dashboard.html', passwords=decrypted_passwords, all_users=other_users, error=error_msg)
    else:
        return redirect(url_for('index_route'))


def select_password_for_edit():
    if 'user_id' not in session:
        return redirect(url_for('index_route'))

    service_name = request.args.get('service_name')
    error_msg = request.args.get('error')
    
    if not service_name:
        return redirect(url_for('dashboard_route'))

    key = current_app.config['ENCRYPTION_KEY']
    cipher_suite = Fernet(key)

    current_user = User.query.filter_by(id=session['user_id']).first()

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

            other_users = User.query.filter(User.id != current_user.id).all()

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
                    'shared_ids': [u.id for u in selected_password.shared_users]
                },
                passwords=user_passwords,
                all_users=other_users,
                error=error_msg
                )
        
        else:
            return redirect(url_for('dashboard_route'))
    else:
        return redirect(url_for('index_route'))


def logout():
    user_id = session.get('user_id')
    username = session.get('username')
    
    # Only log event if a user_id exists in the session
    if session.get('user_id'):
        log_event(f"User {username} logged out.", "USER_LOGOUT", user_id)
   
    # Clear session after logging the event to avoid issues with logging.
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    
    return redirect(url_for('index_route'))


def create_user():
    if 'user_id' not in session:
        return redirect(url_for('index_route'))
    
    current_user = User.query.filter_by(id=session['user_id']).first()
    current_user_role = current_user.role

    if current_user_role not in ['admin', 'manager']:
        log_event(f"User {current_user.username} attempted to create a user.", "UNAUTHORIZED_ACTION", current_user.id)
        return redirect(url_for('dashboard_route', error="You are not authorized to create users."))
    
    if request.method == 'POST':
        username = request.form['username'].upper()
        password = request.form['password']
        role = request.form['role']

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

        # Only allow certain roles based on the current user's role
        if current_user_role == 'admin' and role not in ['admin', 'manager', 'employee']:
            return render_template('create_user.html', error="Invalid role, please try again.")
        if current_user_role == 'manager' and role not in ['employee']:
            return render_template('create_user.html', error="Cannot create user with {role} role, please try again.")
        
        if User.query.filter_by(username=username).first():
            return render_template('create_user.html', error="User already exists, please try again.")
        
        # Commit the new user to the database
        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()

        log_event(f"User {current_user.username} created user {username}.", "USER_CREATE", current_user.id)

        return redirect(url_for('dashboard_route'))
        
    return render_template('create_user.html', current_user_role=current_user_role)


def view_users():
    if 'user_id' not in session:
        return redirect(url_for('index_route'))

    # Get current user and their role for authorization
    current_user = User.query.filter_by(id=session['user_id']).first()
    current_user_role = current_user.role

    if current_user_role not in ['admin', 'manager']:
        log_event(f"User {current_user.username} attempted to view users.", "UNAUTHORIZED_ACTION", current_user.id)
        return redirect(url_for('dashboard_route', error="You are not authorized to view users."))
    
    users = User.query.all()

    # Handle form submission for selecting a user to edit
    selected_user = None
    if request.method == 'POST':
        selected_user_id = request.form.get('selected_user_id')
        selected_user = User.query.filter_by(id=selected_user_id).first()

    log_event(f"User {current_user.username} viewed or selected user to edit.", "USER_VIEW", current_user.id)

    return render_template('view_users.html', users=users, selected_user=selected_user, current_user_role=current_user_role)


def select_user_for_edit():
    if 'user_id' not in session:
        return redirect(url_for('index_route'))

    # Get current user and their role for authorization
    current_user = User.query.filter_by(id=session['user_id']).first()
    current_user_role = current_user.role

    if current_user_role not in ['admin', 'manager']:
        log_event(f"User {current_user.username} attempted to edit a user without permission.", "UNAUTHORIZED_ACTION", current_user.id)
        return redirect(url_for('dashboard_route', error="You are not authorized to edit users."))

    if request.method == 'POST':
        selected_user_id = request.form['selected_user_id']
        return redirect(url_for('update_user', user_id=selected_user_id))

    # Query all users and render the user selection page
    users = User.query.all()

    log_event(f"User {current_user.username} is viewing the user selection page.", "USER_VIEW", current_user.id)

    return render_template('select_user_for_edit.html', users=users)


def update_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('index_route'))

    # Get current user and their role for authorization
    current_user = User.query.filter_by(id=session['user_id']).first()
    current_user_role = current_user.role

    if current_user_role not in ['admin', 'manager']:
        log_event(f"User {current_user.username} attempted to update a user.", "UNAUTHORIZED_ACTION", current_user.id)
        return redirect(url_for('dashboard_route', error="You are not authorized to update users."))
    
    # Fetch the user to be updated
    db_user = User.query.filter_by(id=user_id).first()

    # Make sure the form is passed correctly
    if not db_user:
        return redirect(url_for('view_users_route'))

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

    # Determine if user is updating their own account or someone else's
    if session['user_id'] != int(user_id):
        new_role = request.form.get('role', db_user.role)  # Role comes from the form
    else:
        new_role = current_user_role  # Keep the current role for self updates
        session['username'] = new_username  # Update session with new username if updating own account

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


def delete_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('index_route'))
    
    # Get current user and their role for authorization
    current_user = User.query.filter_by(id=session['user_id']).first()
    current_user_role = current_user.role
    
    if current_user_role not in ['admin', 'manager']:
        log_event(f"User {current_user.username} attempted to delete a user.", "UNAUTHORIZED_ACTION", current_user.id)
        return redirect(url_for('dashboard_route', error="You are not authorized to delete users."))

    # Fetch the user to be deleted
    db_user = User.query.filter_by(id=user_id).first()

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


def unlock_account(user_id):
    if 'user_id' not in session:
        return redirect(url_for('index_route'))
    
    # Find the user to unlock
    db_user = User.query.filter_by(id=user_id).first()

    if db_user:
        if session['role'] in ['admin', 'manager']:
            if db_user.failed_login_attempts > 3:
                db_user.failed_login_attempts = 0
                db.session.commit()

                log_event(f"User {session['username']} unlocked user {db_user.username}.", "ACCOUNT_UNLOCK", session['user_id'])
                return render_template('view_users.html', message="Account unlocked", users=User.query.all(), messageonuser=db_user.username, selected_user=db_user)
            else:
                return render_template('view_users.html', error="Account is not locked.", users=User.query.all(), erroronuser=db_user.username, selected_user=db_user)
        else:
            log_event(f"User {session['username']} attempted to unlock user {db_user.username} without proper authorization.", "UNAUTHORIZED_ACTION", session['user_id'])
            return render_template('view_users.html', error="You are not authorized to unlock accounts.", users=User.query.all(), erroronuser=db_user.username, selected_user=db_user)
    else:
        return render_template('view_users.html', error="User not found in database", users=User.query.all(), erroronuser=db_user.username, selected_user=db_user)


def lock_account(user_id):
    if 'user_id' not in session:
        return redirect(url_for('index_route'))

    # Find the user to lock
    db_user = User.query.filter_by(id=user_id).first()

    if db_user:
        if session['role'] in ['admin', 'manager']:
            if db_user.failed_login_attempts <= 3:
                db_user.failed_login_attempts = 4
                db.session.commit()

                log_event(f"User {session['username']} locked user {db_user.username}.", "ACCOUNT_LOCK", session['user_id'])
                return render_template('view_users.html', message="Account locked", users=User.query.all(), messageonuser=db_user.username, selected_user=db_user)
            else:
                return render_template('view_users.html', error="Account already locked.", users=User.query.all(), erroronuser=db_user.username, selected_user=db_user)
        else:
            log_event(f"User {session['username']} attempted to lock user {db_user.username} without proper authorization.", "UNAUTHORIZED_ACTION", session['user_id'])
            return render_template('view_users.html', error="You are not authorized to lock accounts.", users=User.query.all(), erroronuser=db_user.username, selected_user=db_user)
    else:
        return render_template('view_users.html', error="User not found in database", users=User.query.all(), erroronuser=db_user.username, selected_user=db_user)


def add_password():
    if 'user_id' not in session:
        return redirect(url_for('index_route'))
    
    key = current_app.config['ENCRYPTION_KEY']
    cipher_suite = Fernet(key)

    # Get the form data
    service = request.form['service']
    password = request.form['password']
    new_username = request.form['username']
    notes = request.form['notes']

    # Get the current user
    current_user = User.query.filter_by(id=session['user_id']).first()

    if current_user:
        if not password_meets_requirements(password):
            log_event(f"User {current_user.username} attempted to add weak password.", "INVALID_PASSWORD", current_user.id)
            return redirect(url_for('dashboard_route', error="Password does not meet complexity requirements."))

        encrypted_password = cipher_suite.encrypt(password.encode())

        new_password = Password(service_name=service, username=new_username, password=encrypted_password, notes=notes, user_id=current_user.id)
        db.session.add(new_password)
        db.session.commit()

        log_event(f"User {current_user.username} added a password.", "PASSWORD_ADD", current_user.id)

    return redirect(url_for('dashboard_route'))


def update_password(service):
    if 'user_id' not in session:
        return redirect(url_for('index_route'))

    # Get the form data
    password_id = request.form.get('pw_id')
    username = request.form.get('username')
    password = request.form.get('password')
    notes = request.form.get('notes')
    shared_user_ids = request.form.getlist('shared_users')

    # Get the selected password to update
    password_to_update = Password.query.filter_by(id=password_id).first()
    current_user = User.query.filter_by(id=session['user_id']).first()

    if password_to_update and password_to_update.user_id != current_user.id:
        return redirect(url_for('dashboard_route'))

    if password_to_update:
        if not password_meets_requirements(password):
            log_event("Weak password rejected during update.", "INVALID_PASSWORD", session.get('user_id'))
            return redirect(url_for('dashboard_route', error="Password does not meet complexity requirements."))

        # Update the password's fields
        password_to_update.username = username
        password_to_update.notes = notes
        if shared_user_ids is not None:
            password_to_update.shared_users = User.query.filter(User.id.in_(shared_user_ids)).all()

        # Encrypt the password before saving it back to the database
        key = current_app.config['ENCRYPTION_KEY']
        cipher_suite = Fernet(key)
        encrypted_password = cipher_suite.encrypt(password.encode())
        password_to_update.password = encrypted_password

        # Commit changes to the database
        db.session.commit()

    return redirect(url_for('dashboard_route'))


def delete_password(service):
    if 'user_id' not in session:
        return redirect(url_for('index_route'))
    
    # Get the password ID from the form and find it in the database
    password_id = request.form['pw_id']
    password_entry = Password.query.filter_by(id=password_id).first()
    current_user = User.query.filter_by(id=session['user_id']).first()

    # Delete the password entry if it exists and belongs to the user
    if password_entry and password_entry.user_id == current_user.id:
        db.session.delete(password_entry)
        db.session.commit()

        log_event(f"User {session['username']} deleted a password.", "PASSWORD_DELETE", session['user_id'])
    
    return redirect(url_for('dashboard_route'))


def audit_log_viewer():
    if 'user_id' not in session:
        return redirect(url_for('index_route'))
    
    # Get current user and their role for authorization
    current_user = User.query.filter_by(id=session['user_id']).first()
    current_user_role = current_user.role

    if current_user_role not in ['admin']:
        log_event(f"User {current_user.username} attempted to view the audit log.", "UNAUTHORIZED_ACTION", current_user.id)
        return redirect(url_for('dashboard_route', error="You are not authorized to view the audit log."))
    
    log_event(f"User {current_user.username} viewed the audit log.", "AUDIT_LOG_VIEW", current_user.id)

    # Only show the past day of logs by default
    default_start_date = datetime.now(est) - timedelta(days=1)
    audit_logs = audit_log.query.filter(audit_log.event_time >= default_start_date).all()

    return render_template('audit_log.html', audit_logs=audit_logs, current_user_role=current_user_role, default_start_date=default_start_date.strftime('%Y-%m-%d'))


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