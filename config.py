import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

# Basic Configuration
app.config['SECRET_KEY'] = 'super-secret-key-change-in-prod'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///users.db',
    'audit': 'sqlite:///audit.db'
}

# Encryption Key Setup
KEY_PATH = "file_key.key"
if os.path.exists(KEY_PATH):
    with open(KEY_PATH, "rb") as f:
        FILE_ENCRYPTION_KEY = f.read()

# --- CHANGED FOR GCM ---
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