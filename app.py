from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from functions import index, login, dashboard, logout, create_user, view_users, update_user, delete_user, unlock_account, add_password, update_password, delete_password, log_event, audit_log_viewer, get_audit_logs
from models import db, User, Password
import os
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address)
# db = SQLAlchemy(app)

def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        print("Encryption key file not found.")
        log_event("Encryption key file not found.", "error", 0)
        raise

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root@localhost/password_manager'
# app.config['SQLALCHEMY_DATABASE_URI'] = (
#     'mssql+pyodbc://pm_server:pwmanager@localhost/password_manager?'
#     'driver=ODBC+Driver+17+for+SQL+Server&'
#     'autocommit=True&'
#     'TrustServerCertificate=yes'  # For development only
# )
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24)
app.config['ENCRYPTION_KEY'] = load_key()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

db.init_app(app)


@app.before_request
def ensure_db_exists():
    try:
        User.query.limit(1).first()
        print("Database connection established.")
    except Exception as e:
        print(f"Error connecting to the database {e}")
        raise


@app.after_request
def apply_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    return response
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.route('/')
def index_route():
    return index()


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("6 per minute")
def login_route():
    return login()


@app.route('/dashboard')
def dashboard_route():
    return dashboard()

@app.route('/logout')
def logout_route():
    return logout()

@app.route('/create_user', methods=['GET', 'POST'])
def create_user_route():
    return create_user()

@app.route('/view_users')
def view_users_route():
    return view_users()

@app.route('/update_user/<user_id>', methods=['POST'])
def update_user_route(user_id):
    return update_user(user_id)

@app.route('/delete_user/<user_id>', methods=['POST'])
def delete_user_route(user_id):
    return delete_user(user_id)

@app.route('/unlock_account/<user_id>', methods=['POST'])
def unlock_account_route(user_id):
    return unlock_account(user_id)

@app.route('/add_password', methods=['POST'])
def add_password_route():
    return add_password()

@app.route('/update_password/<service>', methods=['POST'])
def update_password_route(service):
    return update_password(service)

@app.route('/delete_password/<service>', methods=['POST'])
def delete_password_route(service):
    return delete_password(service)

@app.route('/audit_log_viewer')
def audit_log_viewer_route():
    return audit_log_viewer()

@app.route('/get_audit_logs')
def get_audit_logs_route():
    return get_audit_logs()

if __name__ == '__main__':
    app.run(debug=True)
