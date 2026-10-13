from authorization import authentication_claims
from functions import log_event
from models import db, User, TokenBlacklist
from flask_jwt_extended import create_access_token, get_jwt
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

    claims = authentication_claims(user, 'jwt')
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
        identity=str(user.id), additional_claims=claims)

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


def retired_vault_api():
    """Return the authenticated legacy vault retirement contract without data access."""
    return {
        "error": "vault_api_retired",
        "message": (
            "Vault API retired. Use the web interface; this version does not "
            "support the historical mobile client."
        ),
    }, 410
