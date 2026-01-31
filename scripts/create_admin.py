"""
Admin User Creation Script

Creates an initial admin user with full vault access and 2FA enabled.

Security Setup:
1. Strong default password (must be changed on first login)
2. Bcrypt password hashing (adaptive cost factor)
3. TOTP secret generation for 2FA
4. RSA-2048 keypair generation for non-repudiation
5. QR code display for authenticator app setup

Default Credentials:
- Username: admin
- Password: AdminPassword123!
- 2FA: Scan QR code with authenticator app

IMPORTANT SECURITY NOTES:
- Change the default password immediately after first login
- Save the TOTP secret as backup (if you lose authenticator access)
- The QR code is displayed only once (scan it before closing)
- Admin has full access to all vault operations

Usage:
  python scripts/create_admin.py

This script will:
- Reset existing admin account if present
- Generate new RSA keypair
- Display QR code for 2FA setup
- Show TOTP secret for manual entry (backup)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import app, db, bcrypt
from models import User
from utils.crypto_utils import generate_user_keypair
from utils.key_encryption import encrypt_private_key
import pyotp
import qrcode
import base64

def create_admin():
    """
    Creates admin user with full security features.
    
    Security features enabled:
    - Password hashing (bcrypt)
    - 2FA via TOTP
    - RSA keypair for digital signatures
    - Brute force protection (inherited from User model)
    """
    with app.app_context():
        # Ensure database tables exist before querying
        db.create_all()

        # Check if admin already exists
        existing_user = User.query.filter_by(username='admin').first()
        if existing_user:
            print("Admin user already exists. Resetting credentials...")
            db.session.delete(existing_user)
            db.session.commit()

        # Admin credentials
        username = "admin"
        password = "AdminPassword123!"  # Change this immediately after login!
        
        # Generate security secrets
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        totp_secret = pyotp.random_base32()
        
        # Generate RSA keypair for non-repudiation
        print("Generating RSA keypair for admin...")
        private_pem, public_pem = generate_user_keypair()
        
        # SECURITY: Encrypt private key with password-derived key
        print("Encrypting private key with password...")
        encrypted_key, salt = encrypt_private_key(private_pem, password)
        
        # Encode for database storage
        encrypted_key_b64 = base64.b64encode(encrypted_key).decode('utf-8')
        salt_b64 = base64.b64encode(salt).decode('utf-8')

        # Create and save user with encrypted private key
        new_admin = User(
            username=username, 
            password=hashed_pw, 
            totp_secret=totp_secret,
            encrypted_private_key=encrypted_key_b64,  # Encrypted with password
            private_key_salt=salt_b64,                # Salt for key derivation
            public_key_pem=public_pem,
            failed_attempts=0,
            locked_until=None
        )
        db.session.add(new_admin)
        db.session.commit()

        print(f"Admin user created successfully!")
        print(f"Username: {username}")
        print(f"Password: {password}")
        print(f"RSA Keypair: Generated and encrypted")
        print(f"Encryption: PBKDF2 (600k iterations) + AES-256-GCM")
        print("-" * 40)
        
        # Generate and display QR code in the terminal
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="SecureVault")
        qr = qrcode.QRCode()
        qr.add_data(totp_uri)
        qr.print_ascii()

        print("\n[IMPORTANT] Scan the QR code with an authenticator app (e.g., Google Authenticator).")
        print("[IMPORTANT] Change your password after logging in for the first time.")
        print(f"[IMPORTANT] TOTP Secret (backup): {totp_secret}")

if __name__ == "__main__":
    create_admin()
