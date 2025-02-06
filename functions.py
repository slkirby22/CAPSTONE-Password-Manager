from flask import Flask, render_template, request, redirect, url_for, session
from models import db, User, Password
from werkzeug.security import generate_password_hash, check_password_hash

def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard_route'))
    return render_template('index.html')


def login():
    if request.method == 'POST':
        username = request.form['username'].upper()
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            session['user_id'] = user.id
            session['role'] = user.role
            return redirect(url_for('dashboard_route'))
        else:
            return render_template('login.html', error="Invalid credentials, please try again.")
    
    return render_template('login.html')


def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index_route'))

    current_user = User.query.filter_by(id=session['user_id']).first()

    if current_user:
        user_role = current_user.role
        user_passwords = Password.query.filter_by(user_id=current_user.id).all()
    
        return render_template('dashboard.html', user_role=user_role, passwords=user_passwords)
    else:
        return redirect(url_for('index_route'))


def logout():
    session.pop('user_id', None)
    return redirect(url_for('index_route'))


def create_user():
    if 'user_id' not in session:
        return redirect(url_for('index_route'))
    
    current_user = User.query.filter_by(id=session['user_id']).first()
    current_user_role = current_user.role

    if current_user_role not in ['admin', 'manager']:
        return redirect(url_for('dashboard_route', error="You are not authorized to create users."))
    
    if request.method == 'POST':
        username = request.form['username'].upper()
        password = generate_password_hash(request.form['password'])
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

        return redirect(url_for('dashboard_route'))
        
    return render_template('create_user.html', current_user_role=current_user_role)


def view_users():
    if 'user_id' not in session:
        return redirect(url_for('index_route'))

    current_user = User.query.filter_by(id=session['user_id']).first()
    current_user_role = current_user.role

    if current_user_role not in ['admin', 'manager']:
        return redirect(url_for('dashboard_route', error="You are not authorized to view users."))
    
    users = User.query.all()

    return render_template('view_users.html', users=users, current_user_role=current_user_role)


def update_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('index_route'))

    current_user = User.query.filter_by(id=session['user_id']).first()
    current_user_role = current_user.role

    if current_user_role not in ['admin', 'manager']:
        return redirect(url_for('dashboard_route', error="You are not authorized to update users."))
    
    db_user = User.query.filter_by(id=user_id).first()

    user_id = request.form['user_id']
    new_username = request.form['username'].upper()

    if not request.form['password']:
        new_password = db_user.password
    else:
        new_password = generate_password_hash(request.form['password'])

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
        return redirect(url_for('logout_route'))
    else:
        return redirect(url_for('view_users_route'))


def delete_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('index_route'))
    
    current_user = User.query.filter_by(id=session['user_id']).first()
    current_user_role = current_user.role
    
    if current_user_role not in ['admin', 'manager']:
        return redirect(url_for('dashboard_route', error="You are not authorized to delete users."))

    db_user = User.query.filter_by(id=user_id).first()

    if db_user:
        user_passwords = Password.query.filter_by(user_id=user_id).all()

        for password in user_passwords:
            db.session.delete(password)
        
        db.session.delete(db_user)
        db.session.commit()

        return redirect(url_for('view_users_route'))
    
    return redirect(url_for('view_users_route', error="User not found."))


def list_user_passwords(user_id):
    if 'user_id' not in session:
        return redirect(url_for('index_route'))

    current_user = User.query.filter_by(id=session['user_id']).first()
    current_user_role = current_user.role

    if current_user_role not in ['admin', 'manager']:
        return redirect(url_for('dashboard_route', error="You are not authorized to view passwords."))

    user = User.query.filter_by(id=user_id).first()
    user_passwords = Password.query.filter_by(user_id=user_id).all()

    return render_template('list_user_passwords.html', user=user.username, user_passwords=user_passwords)


def add_password():
    if 'user_id' not in session:
        return redirect(url_for('index_route'))
    
    service = request.form['service']
    password = request.form['password']
    new_username = request.form['username']

    current_user = User.query.filter_by(id=session['user_id']).first()

    if current_user:
        new_password = Password(service_name=service, username=new_username, password=password, user_id=current_user.id)
        db.session.add(new_password)
        db.session.commit()

    return redirect(url_for('dashboard_route'))


def update_password(service):
    if 'user_id' not in session:
        return redirect(url_for('index_route'))
    
    password_id = request.form['pw_id']
    new_username = request.form['username']
    new_password = request.form['password']

    password_entry = Password.query.filter_by(id=password_id).first()

    if password_entry:
        password_entry.username = new_username
        password_entry.password = new_password
        db.session.commit()
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
    
    return redirect(url_for('dashboard_route'))