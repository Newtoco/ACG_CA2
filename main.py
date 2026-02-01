"""
Main Application Entry Point

Secure File Vault Web Server with:
- TLS/SSL encryption for data in transit (Port 443)
- User authentication with TOTP-based 2FA
- AES-256-GCM encryption for data at rest
- RSA-2048 digital signatures for non-repudiation
- Comprehensive audit logging

Security Features:
- Defense in depth: Multiple layers of security controls
- Non-repudiation: All file operations are digitally signed by users
- Brute force protection: Account lockouts after failed login attempts
- Input sanitization: Prevents injection attacks
- Magic number validation: Detects file type spoofing
"""

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
    # SECURITY: Check for required certificates and encryption keys
    # Do NOT auto-generate - user must explicitly run generation script
    cert_path = os.path.join('certs', 'cert.pem')
    key_path = os.path.join('certs', 'key.pem')
    file_key_path = os.path.join('certs', 'file_key.key')
    
    missing_files = []
    if not os.path.exists(cert_path):
        missing_files.append(cert_path)
    if not os.path.exists(key_path):
        missing_files.append(key_path)
    if not os.path.exists(file_key_path):
        missing_files.append(file_key_path)
    
    if missing_files:
        print("=" * 60)
        print("ERROR: REQUIRED SECURITY FILES NOT FOUND")
        print("=" * 60)
        print("\nMissing files:")
        for f in missing_files:
            print(f"  - {f}")
        print("\n" + "=" * 60)
        print("CRITICAL: File encryption key required!")
        print("=" * 60)
        print("\nThe file encryption key (file_key.key) encrypts ALL vault files.")
        print("Without this key, encrypted files CANNOT be recovered.")
        print("\nBefore proceeding:")
        print("  1. Run: python scripts/generate_cert.py")
        print("  2. BACKUP the generated files (especially file_key.key)")
        print("  3. Set permissions: chmod 600 certs/* (on Unix)")
        print("  4. Keep keys secure and NEVER commit to git")
        print("\n" + "=" * 60)
        exit(1)
    
    with app.app_context():
        db.create_all()
        print("System: Databases & Keys Ready.")

    # Start server with SSL
    try:
        print(">>> STARTING SECURE VAULT (Port 443) <<<")
        app.run(host='0.0.0.0', port=443, ssl_context=(cert_path, key_path), debug=True)
    except PermissionError:
        print(">>> Permission denied for port 443. Trying port 5000 <<<")
        app.run(host='0.0.0.0', port=5000, ssl_context=(cert_path, key_path), debug=True)
    except Exception as e:
        print(f">>> Error starting with SSL: {e} <<<")
        print(">>> Falling back to HTTP mode (INSECURE) <<<")
        app.run(host='0.0.0.0', port=5000, debug=True)