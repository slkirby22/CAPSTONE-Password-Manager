from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import pytz
from uuid import uuid4
from sqlalchemy import CheckConstraint, DDL, event
from sqlalchemy.orm.attributes import NO_VALUE
from item_identity import ITEM_ID_CHECK, ITEM_TRIGGERS, is_item_id

est = pytz.timezone('US/Eastern')

db = SQLAlchemy()

# Association table for password sharing
password_user = db.Table(
    'password_user',
    db.Column('password_id', db.Integer, db.ForeignKey('password.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

# Class models for User, Password, Audit Log, and Token Blacklist
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Account incarnation, independent of recyclable numeric database IDs.
    auth_identity = db.Column(db.String(32), unique=True, nullable=False,
                              default=lambda: uuid4().hex)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)

    def __init__(self, username, password, role):
        self.username = username
        self.password = password
        self.role = role
    
class Password(db.Model):
    __table_args__ = (CheckConstraint(ITEM_ID_CHECK, name='ck_password_item_identity'),)
    item_id = db.Column(db.String(32), unique=True, nullable=False,
                        default=lambda: uuid4().hex)
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    notes = db.Column(db.String(500), nullable=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('passwords', lazy=True))
    shared_users = db.relationship('User', secondary=password_user,
                                   backref=db.backref('shared_passwords', lazy='dynamic'))

    def __init__(self, service_name, username, password, notes, user_id, shared_users=None):
        self.item_id = uuid4().hex
        self.service_name = service_name
        self.username = username
        self.password = password
        self.notes = notes
        self.user_id = user_id
        if shared_users:
            self.shared_users = shared_users

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


@event.listens_for(Password.item_id, 'set', retval=True, active_history=True)
def _immutable_item_id(target, value, oldvalue, initiator):
    if not is_item_id(value):
        raise ValueError('Invalid item identity')
    if oldvalue is not NO_VALUE and oldvalue != value:
        raise ValueError('Immutable item identity')
    return value


# Direct SQL/bulk ORM updates are guarded too; create_all never upgrades old tables.
for _trigger_sql in ITEM_TRIGGERS.values():
    event.listen(Password.__table__, 'after_create',
                 DDL(_trigger_sql).execute_if(dialect='sqlite'))
