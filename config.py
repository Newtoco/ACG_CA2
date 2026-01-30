"""
Configuration Module

Centralized configuration for the Secure File Vault application.
Handles database setup, encryption key management, and Flask app initialization.

Security Configuration:
- Dual database architecture: Separate databases for user data and audit logs
- AES-256-GCM for symmetric file encryption (authenticated encryption)
- Bcrypt for password hashing with adaptive cost factor
- JWT tokens for stateless session management
- HTTPOnly cookies to prevent XSS attacks

Critical Security Note:
- FILE_ENCRYPTION_KEY must be kept secure and backed up
- Losing this key means all encrypted files become unrecoverable
- In production, use environment variables for SECRET_KEY
"""

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

# Basic Configuration
# WARNING: Change SECRET_KEY in production - used for JWT signing
app.config['SECRET_KEY'] = 'super-secret-key-change-in-prod'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///users.db',
    'audit': 'sqlite:///audit.db'
}

# Server-side session storage for decrypted private keys
# Keys only exist in memory during active session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes

from flask_session import Session
Session(app)

# Encryption Key Setup
KEY_PATH = os.path.join("certs", "file_key.key")
if os.path.exists(KEY_PATH):
    with open(KEY_PATH, "rb") as f:
        FILE_ENCRYPTION_KEY = f.read()

# GCM Cipher Helper
def get_gcm_cipher(nonce, tag=None):
    """
    Returns a GCM cipher.
    During encryption, tag is None.
    During decryption, the stored tag must be provided.
    """
    return Cipher(
        algorithms.AES(FILE_ENCRYPTION_KEY),
        modes.GCM(nonce, tag)
    )

# File Storage Setup
UPLOAD_FOLDER = 'secure_vault_storage'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)