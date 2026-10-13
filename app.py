from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from functions import index, login, dashboard, select_password_for_edit, logout, create_user, view_users, select_user_for_edit, update_user, delete_user, unlock_account, lock_account, add_password, update_password, delete_password, log_event, audit_log_viewer, get_audit_logs, search_user
from api_functions import authenticate_and_get_token, revoke_token, retired_vault_api
from functions import reveal_password, retired_web_vault
from item_identity import validate_item_schema
from models import db, User, Password, TokenBlacklist
import os
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_jwt_extended import jwt_required, current_user, get_jwt_identity, JWTManager
from flask_bootstrap import Bootstrap
from flask_cors import CORS
from dotenv import load_dotenv
from config import load_config
from authorization import register_jwt_current_user
from diagnostics import report_failure, rollback_safely
from werkzeug.exceptions import HTTPException, default_exceptions
from flask_wtf.csrf import CSRFError


# Initialize Flask app, extensions, and configuration
load_dotenv()
app = Flask(__name__)
app.config.update(load_config())
Bootstrap(app)
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address)
cors = CORS(app, 
    resources={
        r"/api/*": {
            "origins": [
                "http://localhost:8081",  # Mobile app domain
            ],
            "methods": ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": False,
            "max_age": 86400
        }
    }
)

jwt = JWTManager(app)
register_jwt_current_user(jwt)

db.init_app(app)


@app.errorhandler(Exception)
def handle_request_failure(error):
    """Catch before Flask logs a traceback (which can include SQL parameters).

    Never interpolate exception text, URL, body, headers, or account/item data.
    Preserve HTTP status and protocol headers, but use class-level descriptions.
    """
    if isinstance(error, HTTPException):
        response = error.get_response()
        description = default_exceptions.get(error.code, HTTPException).description
        # Existing CSRF reasons are fixed library strings, never token values.
        if isinstance(error, CSRFError):
            reasons = {'The CSRF token is missing.', 'The CSRF session token is missing.',
                       'The CSRF token has expired.', 'The CSRF token is invalid.',
                       'The CSRF tokens do not match.', 'The referrer header is missing.',
                       'The referrer does not match the host.'}
            description = error.description if error.description in reasons else 'Invalid CSRF request.'
        response.set_data(jsonify({'error': description}).get_data())
        response.content_type = 'application/json'
        return response
    rollback_safely()
    report_failure('request_failed')
    return jsonify({'error': 'Request could not be completed'}), 500


@jwt.invalid_token_loader
def invalid_token(reason):
    return jsonify({'msg': 'Invalid token'}), 422


@jwt.unauthorized_loader
def missing_token(reason):
    return jsonify({'msg': 'Authentication required'}), 401

# Monolithic Web App Routes
@app.before_request
def ensure_db_exists():
    if request.routing_exception is not None or request.endpoint == 'healthz':
        return
    try:
        User.query.limit(1).first()
        validate_item_schema(db.session.connection())
    except Exception:
        db.session.rollback()
        app.logger.error("Database readiness check failed")
        return jsonify({"error": "Service unavailable"}), 503

@app.after_request
def apply_csp(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; script-src-attr 'none'; "
        "style-src 'self'; style-src-attr 'none'; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self';"
    )
    return response

@app.after_request
def set_security_headers(response):
    return apply_security_headers(response)
def apply_security_headers(response):
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains'
    response.headers['Session-Cookie-SameSite'] = 'Lax'
    return response


@app.route('/healthz')
def healthz():
    # Validate mapped tables/columns without fetching rows or exposing errors.
    try:
        validate_item_schema(db.session.connection())
        for table in db.metadata.sorted_tables:
            db.session.execute(table.select().limit(0))
    except Exception:
        db.session.rollback()
        return jsonify({'status': 'unavailable'}), 503
    return jsonify({'status': 'ok'}), 200


# Routes for Web App
@app.route('/')
def index_route():
    return index()

@app.route('/favicon.ico')
def favicon():
    try:
        return send_from_directory(
            os.path.join(app.root_path, 'static'),
            'favicon.ico', mimetype='image/vnd.microsoft.icon'
        )
    except FileNotFoundError:
        log_event("Favicon not found.", "error", 0)
        return "", 204

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login_route():
    return login()

@app.route('/dashboard')
def dashboard_route():
    return dashboard()

@app.route('/select_password_for_edit', methods=['GET', 'POST'])
def select_password_for_edit_route():
    return retired_web_vault()

@app.route('/logout')
def logout_route():
    return logout()

@app.route('/create_user', methods=['GET', 'POST'])
def create_user_route():
    return create_user()

@app.route('/view_users', methods=['GET', 'POST'])
def view_users_route():
    return view_users()

@app.route('/select_user_for_edit', methods=['GET', 'POST'])
def select_user_for_edit_route():
    return select_user_for_edit()

@app.route('/update_user/<user_id>', methods=['POST'])
def update_user_route(user_id):
    return update_user(user_id)

@app.route('/delete_user/<user_id>', methods=['POST'])
def delete_user_route(user_id):
    return delete_user(user_id)

@app.route('/unlock_account/<user_id>', methods=['POST'])
def unlock_account_route(user_id):
    return unlock_account(user_id)

@app.route('/lock_account/<user_id>', methods=['POST'])
def lock_account_route(user_id):
    return lock_account(user_id)

@app.route('/search_user')
def search_user_route():
    return search_user()

@app.route('/add_password', methods=['POST'])
def add_password_route():
    return add_password()

@app.route('/update_password/<service>', methods=['POST'])
def legacy_update_password_route(service):
    return retired_web_vault()

@app.route('/delete_password/<service>', methods=['POST'])
def legacy_delete_password_route(service):
    return retired_web_vault()


@app.route('/passwords/<item_id>')
def item_detail_route(item_id):
    return select_password_for_edit(item_id)


@app.route('/passwords/<item_id>/reveal', methods=['POST'])
def reveal_password_route(item_id):
    return reveal_password(item_id)


@app.route('/passwords/<item_id>/update', methods=['POST'])
def update_password_route(item_id):
    return update_password(item_id)


@app.route('/passwords/<item_id>/delete', methods=['POST'])
def delete_password_route(item_id):
    return delete_password(item_id)

@app.route('/audit_log_viewer')
def audit_log_viewer_route():
    return audit_log_viewer()

@app.route('/get_audit_logs')
def get_audit_logs_route():
    return get_audit_logs()


# API Routes for Mobile App
@app.route('/api/login', methods=['POST'])
@csrf.exempt 
@limiter.limit("10 per minute")
def api_login():
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
        
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON object required"}), 400

    if any(not isinstance(data.get(field), str) or not data[field]
           for field in ('username', 'password')):
        return jsonify({"error": "Username and password must be non-empty strings"}), 400

    result = authenticate_and_get_token(
        username=data.get('username'),
        password=data.get('password')
    )
    
    if not result:
        return jsonify({"error": "Invalid credentials"}), 401
    
    return jsonify(result), 200

@app.route('/api/logout', methods=['POST'])
@csrf.exempt
@jwt_required()
def api_logout():
    return jsonify(revoke_token())

# Callback to check if a token is revoked
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return TokenBlacklist.query.filter_by(jti=jti).first() is not None

# Error handler for revoked tokens
@jwt.revoked_token_loader
def handle_revoked_token(jwt_header, jwt_payload):
    return jsonify({"error": "Token revoked"}), 401

# Historical mobile vault contract is intentionally retired, not upgraded by ID.
@app.route('/api/dashboard')
@jwt_required()
def api_dashboard():
    return retired_vault_api()


@app.route('/api/passwords', methods=['POST'])
@csrf.exempt
@jwt_required()
def api_add_password():
    return retired_vault_api()


@app.route('/api/passwords/<password_id>', methods=['PATCH', 'DELETE'])
@csrf.exempt
@jwt_required()
def api_retired_password(password_id):
    return retired_vault_api()


if __name__ == '__main__':
    app.run(debug=False)
