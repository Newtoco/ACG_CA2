import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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

# Load the raw 32-byte key
KEY_PATH = "file_key.key"
if os.path.exists(KEY_PATH):
    with open(KEY_PATH, "rb") as f:
        FILE_ENCRYPTION_KEY = f.read()
# Initialize AES-256-CTR
def get_ctr_cipher(nonce):
    return Cipher(algorithms.AES(FILE_ENCRYPTION_KEY), modes.CTR(nonce))

# 5. File Storage Setup
UPLOAD_FOLDER = 'secure_vault_storage'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# 6. Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)