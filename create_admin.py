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
        
        print("[+] Scan the QR code with your authenticator app:")
        qr = qrcode.QRCode(border=1)
        qr.add_data(totp_uri)
        qr.print_ascii(invert=True)
        
        print("-" * 40)
        print(f"[+] Or, enter this secret manually: {totp_secret}")
        print("-" * 40)

if __name__ == "__main__":
    create_admin()