import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import app, db, bcrypt
from models import User
from utils.crypto_utils import generate_user_keypair
import pyotp
import qrcode

def create_admin():
    """
    Programmatically create an admin user if one does not exist.
    Useful for initial setup or resetting the admin account.
    """
    with app.app_context():
        # Ensure database tables exist before querying
        db.create_all()

        # Check if admin already exists
        existing_user = User.query.filter_by(username='admin').first()
        if existing_user:
            print("[-] Admin user already exists. Resetting credentials...")
            db.session.delete(existing_user)
            db.session.commit()

        # Admin credentials
        username = "admin"
        password = "AdminPassword123!"  # Change this immediately after login!
        
        # Generate security secrets
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        totp_secret = pyotp.random_base32()
        
        # Generate RSA keypair for non-repudiation
        print("[*] Generating RSA keypair for admin...")
        private_pem, public_pem = generate_user_keypair()

        # Create and save user
        new_admin = User(
            username=username, 
            password=hashed_pw, 
            totp_secret=totp_secret,
            private_key_pem=private_pem,
            public_key_pem=public_pem,
            failed_attempts=0,
            locked_until=None
        )
        db.session.add(new_admin)
        db.session.commit()

        print(f"[+] Admin user created successfully!")
        print(f"[+] Username: {username}")
        print(f"[+] Password: {password}")
        print(f"[+] RSA Keypair: Generated ✓")
        print("-" * 40)
        
        # Generate and display QR code in the terminal
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="SecureVault")
        qr = qrcode.QRCode()
        qr.add_data(totp_uri)
        qr.print_ascii()

        print("\n[!] IMPORTANT: Scan the QR code with an authenticator app (e.g., Google Authenticator).")
        print("[!] Change your password after logging in for the first time.")
        print(f"[!] TOTP Secret (backup): {totp_secret}")

if __name__ == "__main__":
    create_admin()
