from flask import jsonify, current_app
from functions import log_event
from models import db, User, Password, TokenBlacklist
from cryptography.fernet import Fernet
from flask_jwt_extended import create_access_token, get_jwt_identity, get_jwt
from passlib.context import CryptContext
from datetime import datetime

pwd_context = CryptContext(schemes=["scrypt"], scrypt__default_rounds=14)

def authenticate_and_get_token(username, password):
    """Authenticate user and return JWT if valid"""
    user = User.query.filter_by(username=username.upper()).first()
    if not user or not pwd_context.verify(password, user.password):
        return None
    
    if user.failed_login_attempts > 3:
        return {"error": "Account locked"}, 403
    
    # Reset failed attempts on success
    user.failed_login_attempts = 0
    db.session.commit()

    access_token = create_access_token(identity=str(user.id))
    
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
    
    # Get and decrypt passwords
    user_passwords = Password.query.filter_by(user_id=user_id).all()
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