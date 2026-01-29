from config import app, db, bcrypt
from models import User
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

        # Create and save user
        new_admin = User(username=username, password=hashed_pw, totp_secret=totp_secret)
        db.session.add(new_admin)
        db.session.commit()

        print(f"[+] Admin user created successfully!")
        print(f"[+] Username: {username}")
        print(f"[+] Password: {password}")
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
