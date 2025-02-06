from app import app
from models import db, User, Password

with app.app_context():
    users = User.query.all()
    passwords = Password.query.all()

    for user in users:
        print(f"ID: {user.id}, Username: {user.username}, Password: {user.password}, Role: {user.role}")

    for password in passwords:
        print(f"ID: {password.id}, Service Name: {password.service_name}, Username: {password.username}, Password: {password.password}")
