from flask import Flask, render_template, request, redirect, url_for, session
from data_management import load_users, load_passwords, save_users, save_passwords

users = load_users()
passwords = load_passwords()


def index():
    if 'username' in session:
        return redirect(url_for('dashboard_route'))
    return render_template('index.html')


def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        username = username.upper()

        if username in users and users[username]['password'] == password:
            session['username'] = username
            session['role'] = users[username]['role']
            return redirect(url_for('dashboard_route'))
        else:
            return render_template('login.html', error="Invalid credentials, please try again.")
    
    return render_template('login.html')


def dashboard():
    if 'username' not in session:
        return redirect(url_for('index_route'))
    
    username = session['username']
    user_role = users[username]['role']
    user_passwords = passwords.get(username, {})
    
    return render_template('dashboard.html', user_role=user_role, passwords=user_passwords)


def logout():
    session.pop('username', None)
    return redirect(url_for('index_route'))


def create_user():
    if 'username' not in session:
        return redirect(url_for('index_route'))
    
    current_user_role = users[session['username']]['role']

    if current_user_role not in ['admin', 'manager']:
        return redirect(url_for('dashboard_route', error="You are not authorized to create users."))
    
    if request.method == 'POST':
        username = request.form['username']
        username = username.upper()
        password = request.form['password']
        role = request.form['role']

        if current_user_role == 'admin' and role not in ['admin', 'manager', 'employee']:
            return render_template('create_user.html', error="Invalid role, please try again.")
        if current_user_role == 'manager' and role not in ['employee']:
            return render_template('create_user.html', error="Cannot create user with {role} role, please try again.")
        
        if username not in users:
            users[username] = {"password": password, "role": role}
            save_users(users)
            return redirect(url_for('dashboard_route'))
        else:
            return render_template('create_user.html', error="Username already exists.")
        
    return render_template('create_user.html', current_user_role=current_user_role)


def view_users():
    if 'username' not in session:
        return redirect(url_for('index_route'))
    
    current_user_role = users[session['username']]['role']

    if current_user_role not in ['admin', 'manager']:
        return redirect(url_for('dashboard_route', error="You are not authorized to view users."))
    
    return render_template('view_users.html', users=users, current_user_role=current_user_role)


def update_user(user):
    if 'username' not in session:
        return redirect(url_for('index_route'))
    
    current_user_role = users.get(session['username'], {}).get('role')
    if current_user_role not in ['admin', 'manager']:
        return redirect(url_for('dashboard_route', error="You are not authorized to update users."))
    
    new_username = request.form['username']
    new_username = new_username.upper()
    new_password = request.form['password']
    
    if session['username'] != user:
        new_role = request.form['role']
    else:
        new_role = users.get(session['username'], {}).get('role')

    if user in users:
        if user != new_username:
            del users[user]
            users[new_username] = {"username": new_username, "password": new_password, "role": new_role}
        else:
            users[user] = {"username": new_username, "password": new_password, "role": new_role}
        
        save_users(users)

    return redirect(url_for('view_users_route'))


def delete_user(user):
    if 'username' not in session:
        return redirect(url_for('index_route'))
    
    current_user_role = users.get(session['username'], {}).get('role')
    if current_user_role not in ['admin', 'manager']:
        return redirect(url_for('dashboard_route', error="You are not authorized to update users."))

    if user in users:
        del users[user]
        save_users(users)
    
    return redirect(url_for('view_users_route'))


def list_user_passwords(user):
    if 'username' not in session:
        return redirect(url_for('index_route'))
    
    current_user_role = users.get(session['username'], {}).get('role')
    if current_user_role not in ['admin', 'manager']:
        return redirect(url_for('dashboard_route', error="You are not authorized to view passwords."))
    
    user_passwords = passwords.get(user, {})
    return render_template('list_user_passwords.html', user=user, user_passwords=user_passwords)


def add_password():
    if 'username' not in session:
        return redirect(url_for('index_route'))
    
    username = session['username']
    service = request.form['service']
    password = request.form['password']
    new_username = request.form['username']

    if username not in passwords:
        passwords[username] = {}

    if service not in passwords[username]:
        passwords[username][service] = {"username": new_username, "password": password}
        save_passwords(passwords)

    return redirect(url_for('dashboard_route'))


def update_password(service):
    if 'username' not in session:
        return redirect(url_for('index_route'))
    
    username = session['username']
    new_username = request.form['username']
    new_password = request.form['password']

    if service in passwords[username]:
        passwords[username][service] = {"username": new_username, "password": new_password}
        save_passwords(passwords)

    return redirect(url_for('dashboard_route'))


def delete_password(service):
    if 'username' not in session:
        return redirect(url_for('index_route'))
    
    username = session['username']

    if service in passwords[username]:
        del passwords[username][service]
        save_passwords(passwords)
    
    return redirect(url_for('dashboard_route'))