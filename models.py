from datetime import datetime
from config import db

class User(db.Model):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    # Stores the secret key for Google/Microsoft Authenticator
    totp_secret = db.Column(db.String(32), nullable=True)

class AuditLog(db.Model):
    __bind_key__ = 'audit'
    id = db.Column(db.Integer, primary_key=True)

    # allow null because failed login may not map to a real user
    user_id = db.Column(db.Integer, nullable=True)

    # e.g. "LOGIN_FAILED", "LOGIN_SUCCESS", "UPLOAD", "DOWNLOAD"
    action = db.Column(db.String(50), nullable=False)

    # file actions
    filename = db.Column(db.String(200), nullable=True)

    # login actions
    username_entered = db.Column(db.String(80), nullable=True)
    success = db.Column(db.Boolean, nullable=True)
    details = db.Column(db.String(255), nullable=True)

    # context
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(256), nullable=True)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)