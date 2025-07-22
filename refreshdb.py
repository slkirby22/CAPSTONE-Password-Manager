import os

# Ensure environment variables exist when running this utility script
os.environ.setdefault('DB_USER', 'root')
os.environ.setdefault('DB_PASSWORD', 'root')
os.environ.setdefault('DB_HOST', 'localhost')
os.environ.setdefault('DB_NAME', 'password_manager')
os.environ.setdefault('DB_TYPE', 'mysql')

from app import app
from models import db, User, Password

# Used to delete all user and password data from the database
# This is useful for testing purposes to refresh the database
# Should be removed in production environment

with app.app_context():
    try:
        db.session.query(User).delete()
        db.session.query(Password).delete()
        db.session.commit()
        print("All user and password data deleted successfully.")
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting user and password data: {e}")