from config import app, db
from routes_auth import auth_bp
from routes_vault import vault_bp
import os

app.register_blueprint(auth_bp)
app.register_blueprint(vault_bp)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("System: Databases Ready.")

    # Paths to your RSA-4096 certificates
    cert_path = 'cert.pem'
    key_path = 'key.pem'

    # Check if certificates exist before trying to run
    if os.path.exists(cert_path) and os.path.exists(key_path):
        print(">>> STARTING SECURE VAULT (HTTPS/TLS - Port 443) <<<")
        print(f"Using Certificates: {cert_path} (RSA-4096)")
        try:
            # Note: Running on Port 443 often requires Administrator/Sudo privileges.
            # If it fails, change port to 5000 but keep ssl_context.
            app.run(host='0.0.0.0', port=443, ssl_context=(cert_path, key_path), debug=True)
        except Exception as e:
            print(f">>> ERROR starting on Port 443: {e}")
            print(">>> Attempting to run on Port 5000 with SSL instead...")
            app.run(host='0.0.0.0', port=5000, ssl_context=(cert_path, key_path), debug=True)
    else:
        print(">>> CRITICAL WARNING: SSL Certs not found. Running in INSECURE mode <<<")
        print(">>> Run your certificate generation script first! <<<")
        app.run(host='0.0.0.0', port=5000, debug=True)