import os
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

from app import app
from diagnostics import report_failure, rollback_safely
from models import db, User, Password, password_user

# Used to delete all user and password data from the database
# This is useful for testing purposes to refresh the database
# Should be removed in production environment

with app.app_context():
    try:
        db.session.execute(password_user.delete())
        db.session.query(User).delete()
        db.session.query(Password).delete()
        db.session.commit()
        print("All user and password data deleted successfully.")
    except Exception:
        rollback_safely()
        report_failure('database_reset_failed')