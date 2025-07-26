from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from functions import index, login, dashboard, select_password_for_edit, logout, create_user, view_users, select_user_for_edit, update_user, delete_user, unlock_account, add_password, update_password, delete_password, log_event, audit_log_viewer, get_audit_logs
from api_functions import get_dashboard_data, authenticate_and_get_token, revoke_token, add_password_api, update_password_api, delete_password_api
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


# Initialize Flask app, extensions, and configuration
load_dotenv()
app = Flask(__name__)
Bootstrap(app)
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address)
cors = CORS(app, 
    resources={
        r"/api/*": {
            "origins": [
                "http://localhost:8081",  # Mobile app domain
            ],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True,
            "max_age": 86400
        }
    }
)

def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        print("Encryption key file not found.")
        log_event("Encryption key file not found.", "error", 0)
        raise

# Configure database connection from environment variables
db_user = os.environ.get('DB_USER', 'root')
db_password = os.environ.get('DB_PASSWORD', 'root')
db_host = os.environ.get('DB_HOST', 'localhost')
db_name = os.environ.get('DB_NAME', 'password_manager')
db_type = os.environ.get('DB_TYPE', 'mysql')

if db_type.lower() == 'mssql':
    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f"mssql+pyodbc://{db_user}:{db_password}@{db_host}/{db_name}?"
        "driver=ODBC+Driver+17+for+SQL+Server&"
        "autocommit=True&"
        "TrustServerCertificate=yes"
    )
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f"mysql://{db_user}:{db_password}@{db_host}/{db_name}")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(24)
app.config['ENCRYPTION_KEY'] = load_key()
session_timeout = int(os.environ.get('SESSION_TIMEOUT_MINUTES', '15'))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=session_timeout)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-256-bit-secret')
app.config['JWT_TOKEN_LOCATION'] = ['headers']  # Look for JWT in headers

jwt = JWTManager(app)

db.init_app(app)

# Monolithic Web App Routes
@app.before_request
def ensure_db_exists():
    try:
        User.query.limit(1).first()
    except Exception as e:
        print(f"Error connecting to the database {e}")
        raise

@app.after_request
def apply_csp(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://code.jquery.com https://stackpath.bootstrapcdn.com; "
        "style-src 'self' 'unsafe-inline' https://stackpath.bootstrapcdn.com;"
    )
    return response

@app.after_request
def set_security_headers(response):
    return apply_security_headers(response)
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains'
    response.headers['Session-Cookie-SameSite'] = 'Lax'
    return response


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
    return select_password_for_edit()

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


# API Routes for Mobile App
@app.route('/api/login', methods=['POST'])
@csrf.exempt 
@limiter.limit("10 per minute")
def api_login():
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
        
    data = request.get_json()
    result = authenticate_and_get_token(
        username=data.get('username'),
        password=data.get('password')
    )
    
    if not result:
        return jsonify({"error": "Invalid credentials"}), 401
    elif "error" in result:
        return jsonify(result), 403
    
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

@app.route('/api/dashboard')
@jwt_required()
@limiter.limit("10 per minute")
def api_dashboard():
    if not get_jwt_identity():
        return jsonify({"error": "Unauthorized"}), 401
    user_id = get_jwt_identity()
    
    data = get_dashboard_data(user_id)
    if not data:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify(data)

@app.route('/api/passwords', methods=['POST'])
@csrf.exempt
@jwt_required()
@limiter.limit("10 per minute")
def api_add_password():
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    
    result = add_password_api(get_jwt_identity(), request.get_json())
    return jsonify(result), result.get("status_code", 200)

@app.route('/api/passwords/<int:password_id>', methods=['PATCH'])
@csrf.exempt
@jwt_required()
@limiter.limit("10 per minute")
def api_update_password(password_id):
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400
    
    result = update_password_api(get_jwt_identity(), password_id, request.get_json())
    return jsonify(result), result.get("status_code", 200)

@app.route('/api/passwords/<int:password_id>', methods=['DELETE'])
@csrf.exempt
@jwt_required()
@limiter.limit("10 per minute")
def api_delete_password(password_id):
    result = delete_password_api(get_jwt_identity(), password_id)
    return jsonify(result), result.get("status_code", 200)

if __name__ == '__main__':
    app.run(debug=True)
