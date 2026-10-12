from flask import jsonify, current_app
from functions import log_event
from models import db, User, Password, TokenBlacklist
from cryptography.fernet import Fernet
from flask_jwt_extended import create_access_token, get_jwt_identity, get_jwt
from passlib.context import CryptContext
from datetime import datetime

pwd_context = CryptContext(schemes=["scrypt"], scrypt__default_rounds=14)

def authenticate_and_get_token(username, password):
    """Return a JWT on success, or None for every authentication failure."""
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    if not username or not password:
        return None

    user = User.query.filter_by(username=username.upper()).first()
    if not user:
        return None

    # Match the web login's existing fourth-failure lockout threshold without
    # revealing either account existence or lock state in the API response.
    if user.failed_login_attempts > 3:
        log_event(
            f"Account locked for user {user.username} during API login.",
            "ACCOUNT_LOCKED",
            user.id,
        )
        return None

    try:
        password_matches = pwd_context.verify(password, user.password)
    except (TypeError, ValueError):
        # Unsupported/corrupt stored hashes and oversized passwords fail closed.
        password_matches = False

    if not password_matches:
        # Increment in the database so concurrent API failures are not lost.
        user.failed_login_attempts = User.failed_login_attempts + 1
        db.session.commit()
        log_event(
            f"Failed API login attempt for user {user.username}.",
            "FAILED_LOGIN",
            user.id,
        )
        return None

    # Reset failed attempts on success
    user.failed_login_attempts = 0
    db.session.commit()

    access_token = create_access_token(
        identity=str(user.id), additional_claims={'auth_identity': user.auth_identity})

    log_event(
        f"User {user.username} authenticated via API.",
        "API_LOGIN",
        user.id,
    )

    return {
        "access_token": access_token,
        "user_id": user.id
    }

def revoke_token():
    """Adds the current JWT to the blacklist"""
    jti = get_jwt()["jti"]
    expires_at = datetime.fromtimestamp(get_jwt()["exp"])
    
    # Check if already revoked
    if TokenBlacklist.query.filter_by(jti=jti).first():
        return {"error": "Token already revoked"}, 400
    
    # Add to blacklist
    db.session.add(TokenBlacklist(jti=jti, expires_at=expires_at))
    db.session.commit()
    return {"message": "Successfully logged out"}

def get_dashboard_data(user_id):
    """Reusable function to get dashboard data for API responses."""
    key = current_app.config['ENCRYPTION_KEY']
    cipher_suite = Fernet(key)
    current_user = User.query.filter_by(id=user_id).first()

    if not current_user:
        return None  # Let the route handle the error
    
    # Get and decrypt passwords (owned or shared)
    user_passwords = Password.query.filter(
        (Password.user_id == user_id) |
        (Password.shared_users.any(id=user_id))
    ).all()
    passwords_data = []
    for pw in user_passwords:
        passwords_data.append({
            "id": pw.id,
            "service_name": pw.service_name,
            "username": pw.username,
            "password": cipher_suite.decrypt(pw.password).decode(),
            "notes": pw.notes
        })
    
    return {
        "user": {
            "id": current_user.id,
            "username": current_user.username,
            "role": current_user.role
        },
        "passwords": passwords_data
    }

def add_password_api(user_id, data):
    """Add a new password with validation"""
    required_fields = ['service_name', 'username', 'password']
    if not all(field in data for field in required_fields):
        return {"error": "Missing required fields", "status_code": 400}
    
    try:
        cipher_suite = Fernet(current_app.config['ENCRYPTION_KEY'])
        encrypted_password = cipher_suite.encrypt(data['password'].encode())

        shared_ids = data.get('shared_with', [])
        shared_users = []
        if shared_ids:
            shared_users = User.query.filter(User.id.in_(shared_ids)).all()

        new_password = Password(
            user_id=user_id,
            service_name=data['service_name'],
            username=data['username'],
            password=encrypted_password,
            notes=data.get('notes', ''),
            shared_users=shared_users
        )

        db.session.add(new_password)
        db.session.commit()

        user = User.query.get(user_id)
        log_event(
            f"User {user.username} added a password via API.",
            "API_PASSWORD_ADD",
            user_id,
        )

        return {
            "message": "Password added successfully",
            "password_id": new_password.id
        }
    except Exception as e:
        db.session.rollback()
        return {"error": str(e), "status_code": 500}

def update_password_api(user_id, password_id, data):
    """Update password with partial updates"""
    if not data:
        return {"error": "No fields to update", "status_code": 400}
        
    password_entry = Password.query.filter_by(id=password_id, user_id=user_id).first()
    if not password_entry:
        return {"error": "Password not found", "status_code": 404}
    
    try:
        cipher_suite = Fernet(current_app.config['ENCRYPTION_KEY'])
        
        if 'password' in data:
            password_entry.password = cipher_suite.encrypt(data['password'].encode())
        if 'service_name' in data:
            password_entry.service_name = data['service_name']
        if 'username' in data:
            password_entry.username = data['username']
        if 'notes' in data:
            password_entry.notes = data['notes']
        if 'shared_with' in data:
            password_entry.shared_users = User.query.filter(
                User.id.in_(data['shared_with'])
            ).all()
            
        db.session.commit()

        user = User.query.get(user_id)
        log_event(
            f"User {user.username} updated a password via API.",
            "API_PASSWORD_UPDATE",
            user_id,
        )
        return {"message": "Password updated successfully"}
    except Exception as e:
        db.session.rollback()
        return {"error": str(e), "status_code": 500}

def delete_password_api(user_id, password_id):
    """Delete password with validation"""
    password_entry = Password.query.filter_by(id=password_id, user_id=user_id).first()
    if not password_entry:
        return {"error": "Password not found", "status_code": 404}
    
    try:
        db.session.delete(password_entry)
        db.session.commit()

        user = User.query.get(user_id)
        log_event(
            f"User {user.username} deleted a password via API.",
            "API_PASSWORD_DELETE",
            user_id,
        )
        return {"message": "Password deleted successfully"}
    except Exception as e:
        db.session.rollback()
        return {"error": str(e), "status_code": 500}
