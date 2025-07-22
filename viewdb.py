import os
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

from app import app
from models import db, User, Password

# Used to view all user and password data from the database
# This is useful for testing purposes to view the database
# Should be removed in production environment

with app.app_context():
    users = User.query.all()
    passwords = Password.query.all()

    for user in users:
        print(f"ID: {user.id}, Username: {user.username}, Password: {user.password}, Role: {user.role}")

    for password in passwords:
        print(f"ID: {password.id}, Service Name: {password.service_name}, Username: {password.username}, Password: {password.password}")
