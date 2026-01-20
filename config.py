import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet

# 1. Initialize the Flask Application
app = Flask(__name__)

# 2. Basic Configuration
# SECURITY WARNING: Change this key in a production environment
app.config['SECRET_KEY'] = 'super-secret-key-change-in-prod'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 3. Database Configuration
# FIX: We must set a default URI to satisfy Flask-SQLAlchemy, even if we use binds.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# Define the two separate databases as requested
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///users.db',
    'audit': 'sqlite:///audit.db'
}

# 4. Encryption Key Setup
# Checks if a key exists; if not, generates a new one for file encryption.
KEY_FILE = 'file_key.key'
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'wb') as f:
        f.write(Fernet.generate_key())

# Load the key
with open(KEY_FILE, 'rb') as f:
    FILE_ENCRYPTION_KEY = f.read()

# Initialize the Cipher Suite (AES)
cipher_suite = Fernet(FILE_ENCRYPTION_KEY)

# 5. File Storage Setup
UPLOAD_FOLDER = 'secure_vault_storage'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# 6. Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)