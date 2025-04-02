from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import pytz

est = pytz.timezone('US/Eastern')

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)

    def __init__(self, username, password, role):
        self.username = username
        self.password = password
        self.role = role
    
class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    notes = db.Column(db.String(500), nullable=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('passwords', lazy=True))

    def __init__(self, service_name, username, password, notes, user_id):
        self.service_name = service_name
        self.username = username
        self.password = password
        self.notes = notes
        self.user_id = user_id

class audit_log(db.Model):
    __tablename__ = 'audit_log'

    id = db.Column(db.Integer, primary_key=True)
    event_time = db.Column(db.DateTime, nullable=False, default = datetime.now(est))
    event_message = db.Column(db.Text, nullable=False)
    event_type = db.Column(db.String(255), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref=db.backref('audit_logs', lazy=True))

    def __repr__(self):
        return f'<Audit Log Entry: {self.id}>'
    
class TokenBlacklist(db.Model):
    __tablename__ = 'token_blacklist'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True)  # JWT ID
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<BlacklistedToken {self.jti}>'