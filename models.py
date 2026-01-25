from datetime import datetime
from config import db

class User(db.Model):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    # Stores the secret key for Google/Microsoft Authenticator
    totp_secret = db.Column(db.String(32), nullable=True)

class File(db.Model):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    original_filename = db.Column(db.String(200), nullable=False)
    storage_name = db.Column(db.String(200), unique=True, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    __bind_key__ = 'audit'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(50), nullable=False)
    filename = db.Column(db.String(200), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)