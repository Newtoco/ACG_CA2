"""
Database Models

Defines the database schema for users, files, and audit logs.

Security Design:
1. User Model:
   - Passwords hashed with bcrypt (never stored in plaintext)
   - TOTP secrets for 2FA authentication
   - RSA keypairs (2048-bit) for digital signatures and non-repudiation
   - Brute force protection with failed attempt tracking and account lockouts

2. File Model:
   - UUID-based storage names prevent enumeration attacks
   - Digital signatures link files to specific users (non-repudiation)
   - Metadata tracking for audit trail

3. AuditLog Model:
   - Comprehensive logging of all security-relevant events
   - Immutable audit trail for forensic analysis
   - Tracks authentication attempts, file operations, and security violations

Separate Databases:
- users.db: User credentials and file metadata
- audit.db: Tamper-evident audit logs (isolated for security)
"""

from datetime import datetime
from config import db

class User(db.Model):
    """User account with authentication and non-repudiation support"""
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    # Stores the secret key for Authenticators
    totp_secret = db.Column(db.String(32), nullable=True)

    # Non-Repudiation: User's RSA Keys
    # SECURITY: Private keys encrypted with password-derived keys (PBKDF2 + AES-256-GCM)
    # Old plaintext storage (deprecated - kept for backward compatibility)
    private_key_pem = db.Column(db.Text, nullable=True)
    
    # NEW: Encrypted private key storage (recommended)
    encrypted_private_key = db.Column(db.Text, nullable=True)  # Base64-encoded encrypted key
    private_key_salt = db.Column(db.Text, nullable=True)        # Base64-encoded PBKDF2 salt
    
    # Public key (stored in plaintext - not sensitive)
    public_key_pem = db.Column(db.Text, nullable=True)

    # Brute Force Protection
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

# File Storage System
class File(db.Model):
    __bind_key__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    original_filename = db.Column(db.String(200), nullable=False)
    storage_name = db.Column(db.String(200), unique=True, nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    signature = db.Column(db.Text, nullable=True)

# Enhanced Audit Logs
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