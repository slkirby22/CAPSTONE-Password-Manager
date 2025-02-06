from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(50), nullable=False)

    def __init__(self, username, password, role):
        self.username = username
        self.password = password
        self.role = role

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('passwords', lazy=True))

    def __init__(self, service_name, username, password, user_id):
        self.service_name = service_name
        self.username = username
        self.password = password
        self.user_id = user_id