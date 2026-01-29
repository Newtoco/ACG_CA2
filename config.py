import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. Initialize the Flask Application
app = Flask(__name__)

# 2. Basic Configuration
#Change Secret key in a production environment
app.config['SECRET_KEY'] = 'super-secret-key-change-in-prod'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 3. Database Configuration
# set a default URI to satisfy Flask-SQLAlchemy, even if we use binds.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# Define the two separate databases, one for user data and another for audit logs
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///users.db',
    'audit': 'sqlite:///audit.db'
}

# Encryption Key Setup for ensuring security at rest
# Load the raw 32-byte key for AES-256-GCM
KEY_PATH = "file_key.key"
if os.path.exists(KEY_PATH):
    with open(KEY_PATH, "rb") as f:
        FILE_ENCRYPTION_KEY = f.read()

# Initialize AES-256-GCM (provides encryption + authentication)
def get_gcm_cipher():
    """Returns AESGCM cipher for authenticated encryption"""
    return AESGCM(FILE_ENCRYPTION_KEY)

# File Storage Setup for secure file management
UPLOAD_FOLDER = 'secure_vault_storage'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)