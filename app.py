from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from functions import index, login, dashboard, logout, create_user, view_users, update_user, delete_user, list_user_passwords, add_password, update_password, delete_password
from models import db, User, Password
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root@localhost/password_manager'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24)

db.init_app(app)


@app.before_request
def ensure_db_exists():
    try:
        db.session.execute(text("SELECT 1"))
        print("Database connection established.")
    except Exception as e:
        print(f"Error connection to the database {e}")
        raise


@app.route('/')
def index_route():
    return index()


@app.route('/login', methods=['GET', 'POST'])
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

@app.route('/list_user_passwords/<user_id>', methods=['GET'])
def list_user_passwords_route(user_id):
    return list_user_passwords(user_id)

@app.route('/add_password', methods=['POST'])
def add_password_route():
    return add_password()

@app.route('/update_password/<service>', methods=['POST'])
def update_password_route(service):
    return update_password(service)

@app.route('/delete_password/<service>', methods=['POST'])
def delete_password_route(service):
    return delete_password(service)


if __name__ == '__main__':
    app.run(debug=True)
