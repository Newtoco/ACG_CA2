import os
from config import app, db

# Import from new organized structure
try:
    from app.routes import auth_bp, vault_bp
except ImportError:
    # Fallback to old structure for backward compatibility
    from routes_auth import auth_bp
    from routes_vault import vault_bp

# Import view_logs from scripts
try:
    from scripts.view_logs import view_logs_bp
except ImportError:
    from view_logs import view_logs_bp

app.register_blueprint(auth_bp)
app.register_blueprint(vault_bp)
app.register_blueprint(view_logs_bp)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("System: Databases & Keys Ready.")

    # Try to use SSL for Secure Tunnel
    try:
        print(">>> STARTING SECURE VAULT (Port 443) <<<")
        cert_path = os.path.join('certs', 'cert.pem')
        key_path = os.path.join('certs', 'key.pem')
        app.run(host='0.0.0.0', port=443, ssl_context=(cert_path, key_path), debug=True)
    except FileNotFoundError:
        print(">>> WARNING: SSL Certs not found. Running in INSECURE mode (Port 5000) <<<")
        print(">>> Please run: python scripts/generate_cert.py <<<")
        app.run(host='0.0.0.0', port=5000, debug=True)