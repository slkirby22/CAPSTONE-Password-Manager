from flask import Flask, render_template, request, redirect, url_for, session, current_app
from models import db, User, Password, audit_log
from datetime import datetime
from passlib.context import CryptContext
from cryptography.fernet import Fernet

pwd_context = CryptContext(schemes=["scrypt"])

def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard_route'))
    return render_template('index.html')


def log_event(message, event_type, user_id=None):
    try:
        new_log = audit_log(
            event_time = datetime.utcnow(),
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
            try:
                if pwd_context.verify(password, user.password):
                    session['username'] = user.username
                    session['user_id'] = user.id
                    session['role'] = user.role

                    log_event(f"User {user.username} logged in.", "USER_LOGIN", user.id)

                    return redirect(url_for('dashboard_route'))
                else:
                    log_event(f"Failed login attempt for user {user.username}.", "FAILED_LOGIN", user.id)
                    
                    return render_template('login.html', error="Invalid password, please try again.")
                    
            except Exception as e:
                print(f"Error verifying password: {e}")
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
    log_event(f"User {session['username']} logged out.", "USER_LOGOUT", session['user_id'])
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
        password = pwd_context.hash(request.form['password'])
        role = request.form['role']

        if current_user_role == 'admin' and role not in ['admin', 'manager', 'employee']:
            return render_template('create_user.html', error="Invalid role, please try again.")
        if current_user_role == 'manager' and role not in ['employee']:
            return render_template('create_user.html', error="Cannot create user with {role} role, please try again.")
        
        if User.query.filter_by(username=username).first():
            return render_template('create_user.html', error="User already exists, please try again.")
        
        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()

        log_event(f"User {current_user.username} created user {username}.", "USER_CREATE", current_user.id)

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

    if not request.form['password']:
        new_password = db_user.password
    else:
        new_password = pwd_context.hash(request.form['password'])

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
    
    if current_user_role not in ['admin', 'manager']:
        log_event(f"User {current_user.username} attempted to delete a user.", "UNAUTHORIZED_ACTION", current_user.id)
        return redirect(url_for('dashboard_route', error="You are not authorized to delete users."))

    db_user = User.query.filter_by(id=user_id).first()

    if db_user:
        user_passwords = Password.query.filter_by(user_id=user_id).all()

        for password in user_passwords:
            db.session.delete(password)
        
        db.session.delete(db_user)
        db.session.commit()

        log_event(f"User {current_user.username} deleted user {db_user.username}.", "USER_DELETE", current_user.id)

        return redirect(url_for('view_users_route'))
    
    return redirect(url_for('view_users_route', error="User not found."))


def list_user_passwords(user_id):
    if 'user_id' not in session:
        return redirect(url_for('index_route'))

    key = current_app.config['ENCRYPTION_KEY']
    cipher_suite = Fernet(key)

    current_user = User.query.filter_by(id=session['user_id']).first()
    current_user_role = current_user.role

    if current_user_role not in ['admin', 'manager']:
        log_event(f"User {current_user.username} attempted to view passwords.", "UNAUTHORIZED_ACTION", current_user.id)
        return redirect(url_for('dashboard_route', error="You are not authorized to view passwords."))

    user = User.query.filter_by(id=user_id).first()
    user_passwords = Password.query.filter_by(user_id=user_id).all()

    for password_entry in user_passwords:
        password_entry.password = cipher_suite.decrypt(password_entry.password).decode()

    log_event(f"User {current_user.username} viewed passwords for user {user.username}.", "PASSWORD_VIEW", current_user.id)

    return render_template('list_user_passwords.html', user=user.username, user_passwords=user_passwords)


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