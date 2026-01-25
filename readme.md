# Secure File Vault

A secure, web-based file storage application built with Python and Flask. This system implements military-grade AES encryption for file storage, a dual-layer authentication system (Password + TOTP), and full audit logging.

##  Features

* **Dual-Layer Authentication:**
    * Traditional Username/Password (Bcrypt hashed).
    * **MFA/2FA:** Time-based One-Time Password (TOTP) compatible with Google/Microsoft Authenticator.
* **End-to-End Encryption:**
    * **In-Transit:** HTTPS/TLS Tunnel using SSL certificates.
    * **At-Rest:** Files are encrypted with Fernet (AES-128) before being saved to disk.
* **Session Management:** Secure, HTTPOnly cookies using JSON Web Tokens (JWT).
* **Non-Repudiation:** All actions (Login, Upload, Delete) are recorded in an immutable Audit Log.
* **User Isolation:** Users can only access and decrypt their own uploaded files.

##  Project Structure

```text
SecureVault/
├── secure_vault_storage/   # Encrypted files are stored here
├── templates/              # HTML Frontend
│   └── index.html
├── config.py               # Database & App Configuration
├── generate_cert.py        # Script to create SSL Certificates
├── main.py                 # Application Entry Point
├── models.py               # Database Models (User, AuditLog)
├── routes_auth.py          # Authentication Logic (Login/Register/MFA)
├── routes_vault.py         # File Operations (Upload/Download)
├── utils.py                # Helper functions (Logging, Token decoders)
└── requirements.txt        # Python Dependencies

Installation & Setup
1. Prerequisites
Ensure you have Python 3.8+ installed.

2. Install Dependencies
Open your terminal in the project folder and run:

Bash
python reset.py
This resets the folder to it's original state, without key, logs, saved files stored.

Bash
python -m pip install -r requirements.txt
3. Generate Security Certificates
The system requires an SSL certificate to create a secure HTTPS tunnel. Run this script once to generate self-signed keys (cert.pem and key.pem):

Bash
python generate_cert.py
🏃‍♂️ How to Run
Start the Server:

Bash
python main.py
You should see: >>> STARTING SECURE VAULT (Port 443) <<<

Access the Application: Open your web browser and navigate to: https://www.google.com/search?q=https://127.0.0.1:443

Note: Because we are using a self-signed certificate, your browser will show a "Not Secure" warning. Click Advanced > Proceed to localhost (unsafe) to access the login page.

Usage Guide
Register:

Click "Register New Account".

Create a username and password.

Scan the QR Code with your Authenticator App (Google/Microsoft).

Login:

Enter your credentials.

Enter the 6-digit code from your Authenticator App.

Dashboard:

Upload: Select a file to encrypt and store it.

Download: Click a file to decrypt and retrieve it.

Delete: Permanently remove a file.

🛡️ Security Details
Database: Uses SQLite (users.db for credentials, audit.db for logs).

Encryption Key: A unique key is generated in file_key.key on first run. Do not lose this file, or all encrypted data will be unrecoverable.

Network: All traffic is forced over HTTPS (Port 443).