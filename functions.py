from flask import Flask, render_template, request, redirect, url_for, session, current_app, jsonify
from models import db, User, Password, audit_log
from datetime import datetime, timedelta
from passlib.context import CryptContext
from cryptography.fernet import Fernet
import re
import pytz

pwd_context = CryptContext(schemes=["scrypt"], scrypt__default_rounds=14)
est = pytz.timezone('US/Eastern')

def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard_route'))
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
    if request.method == 'POST':
        username = request.form['username'].upper()
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user:
            if user.failed_login_attempts <= 3:
                try:
                    if pwd_context.verify(password, user.password):
                        session['username'] = user.username
                        session['user_id'] = user.id
                        session['role'] = user.role

                        log_event(f"User {user.username} logged in.", "USER_LOGIN", user.id)

                        user.failed_login_attempts = 0
                        db.session.commit()

                        return redirect(url_for('dashboard_route'))
                    else:
                        log_event(f"Failed login attempt for user {user.username}.", "FAILED_LOGIN", user.id)
                        user.failed_login_attempts += 1
                        db.session.commit()
                        return render_template('login.html', error="Invalid password, please try again.")
                        
                except Exception as e:
                    print(f"Error verifying password: {e}")
            else:
                log_event(f"Account locked for user {user.username} due to too many failed login attempts.", "ACCOUNT_LOCKED", user.id)
                return render_template('login.html', error="Account locked due to too many failed login attempts.")
        else:
            return render_template('login.html', error="User not found, please try again.")
   
    return render_template('login.html')


def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index_route'))

    key = current_app.config['ENCRYPTION_KEY']
    cipher_suite = Fernet(key)

    current_user = User.query.filter_by(id=session['user_id']).first()

    if current_user:
        user_role = current_user.role
        user_passwords = Password.query.filter_by(user_id=current_user.id).all()

        for password_entry in user_passwords:
            password_entry.password = cipher_suite.decrypt(password_entry.password).decode()
    
        return render_template('dashboard.html', user_role=user_role, passwords=user_passwords)
    else:
        return redirect(url_for('index_route'))


def logout():
    user_id = session.get('user_id')
    log_event(f"User {session['username']} logged out.", "USER_LOGOUT", user_id)
    session.pop('user_id', None)
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

        if len(password) < 8:
            log_event(f"{current_user.username} attempted to create a user with an invalid password.", "INVALID_PASSWORD", current_user.id)
            return render_template('create_user.html', error="Password must be at least 8 characters long.", usernmame=username, role=role)
        if not re.search(r"\d", password):
            log_event(f"{current_user.username} attempted to create a user with an invalid password.", "INVALID_PASSWORD", current_user.id)
            return render_template('create_user.html', error="Password must contain at least one number.", usernmame=username, role=role)
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            log_event(f"{current_user.username} attempted to create a user with an invalid password.", "INVALID_PASSWORD", current_user.id)
            return render_template('create_user.html', error="Password must contain at least one special character.", usernmame=username, role=role)
        if not re.search(r"[A-Z]", password):
            log_event(f"{current_user.username} attempted to create a user with an invalid password.", "INVALID_PASSWORD", current_user.id)
            return render_template('create_user.html', error="Password must contain at least one uppercase letter.", usernmame=username, role=role)

        password = pwd_context.hash(password)

        if current_user_role == 'admin' and role not in ['admin', 'manager', 'employee']:
            return render_template('create_user.html', error="Invalid role, please try again.")
        if current_user_role == 'manager' and role not in ['employee']:
            return render_template('create_user.html', error="Cannot create user with {role} role, please try again.")
        
        if User.query.filter_by(username=username).first():
            return render_template('create_user.html', error="User already exists, please try again.")
        
        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()

        log_event(f"User {current_user.username} created user {username}.", "v", current_user.id)

        return redirect(url_for('dashboard_route'))
        
    return render_template('create_user.html', current_user_role=current_user_role)


def view_users():
    if 'user_id' not in session:
        return redirect(url_for('index_route'))

    current_user = User.query.filter_by(id=session['user_id']).first()
    current_user_role = current_user.role

    if current_user_role not in ['admin', 'manager']:
        log_event(f"User {current_user.username} attempted to view users.", "UNAUTHORIZED_ACTION", current_user.id)
        return redirect(url_for('dashboard_route', error="You are not authorized to view users."))
    
    users = User.query.all()

    log_event(f"User {current_user.username} viewed users.", "USER_VIEW", current_user.id)

    return render_template('view_users.html', users=users, current_user_role=current_user_role)


def update_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('index_route'))

    current_user = User.query.filter_by(id=session['user_id']).first()
    current_user_role = current_user.role

    if current_user_role not in ['admin', 'manager']:
        log_event(f"User {current_user.username} attempted to update a user.", "UNAUTHORIZED_ACTION", current_user.id)
        return redirect(url_for('dashboard_route', error="You are not authorized to update users."))
    
    db_user = User.query.filter_by(id=user_id).first()

    user_id = request.form['user_id']
    new_username = request.form['username'].upper()

    if request.form['password']:
        new_password = request.form['password']

        if len(new_password) < 8:
            log_event(f"{current_user.username} attempted to update user {user_id} with an invalid password.", "INVALID_PASSWORD", current_user.id)
            return render_template('view_users.html', error="Password must be at least 8 characters long.", users=User.query.all(), erroronuser=new_username)
        if not re.search(r"\d", new_password):
            log_event(f"{current_user.username} attempted to update user {user_id} with an invalid password.", "INVALID_PASSWORD", current_user.id)
            return render_template('view_users.html', error="Password must contain at least one number.", users=User.query.all(), erroronuser=new_username)
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", new_password):
            log_event(f"{current_user.username} attempted to update user {user_id} with an invalid password.", "INVALID_PASSWORD", current_user.id)
            return render_template('view_users.html', error="Password must contain at least one special character.", users=User.query.all(), erroronuser=new_username)
        if not re.search(r"[A-Z]", new_password):
            log_event(f"{current_user.username} attempted to update user {user_id} with an invalid password.", "INVALID_PASSWORD", current_user.id)
            return render_template('view_users.html', error="Password must contain at least one uppercase letter.", users=User.query.all(), erroronuser=new_username)

        new_password = pwd_context.hash(new_password)
    else:
        new_password = db_user.password

    if session['user_id'] != user_id:
        new_role = request.form.get('role', current_user_role)
    else:
        new_role = current_user_role
        session['username'] = new_username

    if db_user:
        db_user.username = new_username
        db_user.password = new_password
        db_user.role = new_role
        db.session.commit()

    if session['user_id'] == db_user.id:
        session['username'] = db_user.username
        log_event(f"User {current_user.username} updated their own account.", "USER_UPDATE", current_user.id)
        return redirect(url_for('logout_route'))
    else:
        log_event(f"User {current_user.username} updated user {new_username}.", "USER_UPDATE", current_user.id)
        return redirect(url_for('view_users_route'))


def delete_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('index_route'))
    
    current_user = User.query.filter_by(id=session['user_id']).first()
    current_user_role = current_user.role
    print(current_user_role)
    
    if current_user_role not in ['admin', 'manager']:
        log_event(f"User {current_user.username} attempted to delete a user.", "UNAUTHORIZED_ACTION", current_user.id)
        return redirect(url_for('dashboard_route', error="You are not authorized to delete users."))

    db_user = User.query.filter_by(id=user_id).first()
    print(db_user)

    if db_user:
        user_passwords = Password.query.filter_by(user_id=user_id).all()
        print(user_passwords)

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
    
    db_user = User.query.filter_by(id=user_id).first()

    if db_user:
        if session['role'] in ['admin', 'manager']:
            if db_user.failed_login_attempts > 3:
                db_user.failed_login_attempts = 0
                db.session.commit()

                log_event(f"User {session['username']} unlocked user {db_user.username}.", "ACCOUNT_UNLOCK", session['user_id'])
                return render_template('view_users.html', message="Account unlocked", users=User.query.all(), messageonuser=db_user.username)
            else:
                return render_template('view_users.html', error="Account is not locked.", users=User.query.all(), erroronuser=db_user.username)
        else:
            log_event(f"User {session['username']} attempted to unlock user {db_user.username} without proper authorization.", "UNAUTHORIZED_ACTION", session['user_id'])
            return render_template('view_users.html', error="You are not authorized to unlock accounts.", users=User.query.all(), erroronuser=db_user.username)
    else:
        return render_template('view_users.html', error="User not found in database", users=User.query.all(), erroronuser=db_user.username)


def add_password():
    if 'user_id' not in session:
        return redirect(url_for('index_route'))
    
    key = current_app.config['ENCRYPTION_KEY']
    cipher_suite = Fernet(key)

    service = request.form['service']
    password = request.form['password']
    new_username = request.form['username']
    notes = request.form['notes']

    current_user = User.query.filter_by(id=session['user_id']).first()

    if current_user:

        encrypted_password = cipher_suite.encrypt(password.encode())

        new_password = Password(service_name=service, username=new_username, password=encrypted_password, notes=notes, user_id=current_user.id)
        db.session.add(new_password)
        db.session.commit()

        log_event(f"User {current_user.username} added a password.", "PASSWORD_ADD", current_user.id)

    return redirect(url_for('dashboard_route'))


def update_password(service):
    if 'user_id' not in session:
        return redirect(url_for('index_route'))
    
    key = current_app.config['ENCRYPTION_KEY']
    cipher_suite = Fernet(key)

    password_id = request.form['pw_id']
    new_username = request.form['username']
    new_password = request.form['password']
    new_notes = request.form['notes']

    password_entry = Password.query.filter_by(id=password_id).first()

    if password_entry:
        encrypted_password = cipher_suite.encrypt(new_password.encode())

        password_entry.username = new_username
        password_entry.password = encrypted_password
        password_entry.notes = new_notes
        db.session.commit()

        log_event(f"User {session['username']} updated a password.", "PASSWORD_UPDATE", session['user_id'])
    else:
        return redirect(url_for('dashboard_route', error="Password entry not found."))

    return redirect(url_for('dashboard_route'))


def delete_password(service):
    if 'user_id' not in session:
        return redirect(url_for('index_route'))
    
    password_id = request.form['pw_id']

    password_entry = Password.query.filter_by(id=password_id).first()

    if password_entry:
        db.session.delete(password_entry)
        db.session.commit()

        log_event(f"User {session['username']} deleted a password.", "PASSWORD_DELETE", session['user_id'])
    
    return redirect(url_for('dashboard_route'))


def audit_log_viewer():
    if 'user_id' not in session:
        return redirect(url_for('index_route'))
    
    current_user = User.query.filter_by(id=session['user_id']).first()
    current_user_role = current_user.role

    if current_user_role not in ['admin']:
        log_event(f"User {current_user.username} attempted to view the audit log.", "UNAUTHORIZED_ACTION", current_user.id)
        return redirect(url_for('dashboard_route', error="You are not authorized to view the audit log."))
    
    default_start_date = datetime.now(est) - timedelta(days=7)
    audit_logs = audit_log.query.filter(audit_log.event_time >= default_start_date).all()

    log_event(f"User {current_user.username} viewed the audit log.", "AUDIT_LOG_VIEW", current_user.id)

    return render_template('audit_log.html', audit_logs=audit_logs, current_user_role=current_user_role, default_start_date=default_start_date.strftime('%Y-%m-%d'))


def get_audit_logs():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = audit_log.query
    if start_date:
        query = query.filter(audit_log.event_time >= start_date)
    if end_date:
        query = query.filter(audit_log.event_time <= end_date)

    logs = query.all()
    return jsonify([{
        'id': log.id,
        'event_time': log.event_time.strftime('%Y-%m-%d %H:%M:%S'),
        'event_message': log.event_message,
        'event_type': log.event_type,
        'user_id': log.user_id
    } for log in logs])