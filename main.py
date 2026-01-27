from config import app, db
from routes_auth import auth_bp
from routes_vault import vault_bp
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
        app.run(host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'), debug=True)
    except FileNotFoundError:
        print(">>> WARNING: SSL Certs not found. Running in INSECURE mode (Port 5000) <<<")
        print(">>> Please run the OpenSSL command. <<<")
        app.run(host='0.0.0.0', port=5000, debug=True)