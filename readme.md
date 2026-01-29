# Secure File Vault

A secure, web-based file storage application built with Python and Flask. This system implements strong AES-CTR encryption for file storage, a multi-factor authentication system (Password + TOTP), audit logging with admin dashboard, and support for both symmetric and hybrid cryptographic operations.

##  Features

- **Dual-Layer Authentication:**
  - Traditional Username/Password (Bcrypt hashed with salt)
  - **MFA/2FA:** Time-based One-Time Password (TOTP) compatible with Google/Microsoft Authenticator
  - QR Code generation for easy authenticator app setup
  - **Brute Force Protection:** Account locking mechanism after failed login attempts
  
- **Advanced Encryption Architecture:**
  - **In-Transit:** HTTPS/TLS Tunnel using SSL certificates (cert.pem & key.pem)
  - **At-Rest (Symmetric):** Files are encrypted with AES-256 in CTR mode before being saved to disk
  - **Hybrid Cryptography Support:** RSA + AES hybrid encryption utilities for advanced scenarios
  - **Digital Signatures:** RSA-PSS signature generation and verification for non-repudiation
  - **File Type Validation:** Magic byte inspection to prevent malicious file uploads
  
- **Session Management:**
  - Secure, HTTPOnly cookies using JSON Web Tokens (JWT)
  - 30-minute session expiry with automatic token validation
  - IP address and user agent tracking for enhanced security
  
- **Comprehensive Audit System:**
  - All actions (Login Success/Failure, Upload, Download, Delete) recorded in immutable Audit Log
  - Separate audit database for security compliance and forensic analysis
  - **Admin Dashboard:** Dedicated interface for administrators to view system-wide audit logs
  - **Advanced Log Filtering:** Filter by username, action type, and limit results
  - Failed login tracking with detailed username and IP logging
  
- **User Isolation & Security:**
  - Users can only access and decrypt their own uploaded files
  - UUID-based file storage prevents filename collisions and unauthorized access
  - Duplicate file handling with automatic replacement
  - Secure filename sanitization to prevent path traversal attacks
  
- **Backup & Maintenance:**
  - Automated audit database backup script with rotation (keeps 10 most recent backups)
  - System reset utility for complete data cleanup
  - Admin user creation script for programmatic setup

##  Project Structure

### Initial Files (Repository)

````text
ACG_CA2/
├── scripts/               # Utility and maintenance scripts
│   ├── backup_audit_db.py # Audit database backup with rotation
│   ├── create_admin.py    # Admin user creation script
│   ├── generate_cert.py   # SSL certificate & encryption key generator
│   └── reset.py           # System reset (cleans all data)
├── static/                # Frontend assets
│   ├── css/
│   │   └── style.css     # Application styling
│   └── js/
│       └── main.js        # Client-side JavaScript
├── templates/             # HTML templates
│   └── index.html         # Main SPA (Single Page Application)
├── utils/                 # Cryptographic utilities
│   ├── crypto_utils.py    # Hybrid encryption & digital signature functions
│   └── keygen.py          # RSA key pair generation script
├── .gitignore             # Git ignore file (prevents committing sensitive data)
├── config.py              # Database & App Configuration
├── main.py                # Application Entry Point
├── models.py              # Database Models (User, File, AuditLog)
├── readme.md              # This file
├── requirements.txt       # Python Dependencies
├── routes_auth.py         # Authentication Logic (Login/Register/MFA)
├── routes_vault.py        # File Operations (Upload/Download/Delete/List)
├── utils.py               # Helper functions (Logging, Token validation)
└── view_logs.py           # Admin audit log viewing endpoints
````

### Generated Files & Directories

These are created automatically by scripts or when the application runs:

````text
# Created by scripts/generate_cert.py:
├── cert.pem               # SSL certificate (self-signed)
├── key.pem                # SSL private key
└── file_key.key           # AES-256 master encryption key (32 bytes)
                           #  These files are in .gitignore - never commit to version control!

# Created by utils/keygen.py (optional):
└── keys/                  # RSA key pairs directory
    ├── server_private.pem # Server RSA private key (2048-bit)
    ├── server_public.pem  # Server RSA public key
    ├── client_private.pem # Client RSA private key (2048-bit)
    └── client_public.pem  # Client RSA public key
                           #  These files are also in .gitignore

# Auto-created on first run (by config.py & models):
├── secure_vault_storage/  # Encrypted files storage directory
└── instance/              # SQLite database files
    ├── users.db          # User credentials, TOTP secrets, file mappings
    └── audit.db          # Immutable audit logs
                          #  Databases contain sensitive user data - protected by .gitignore

# Created by scripts/backup_audit_db.py (on-demand):
└── backups/               # Audit database backups with timestamps
    └── audit_YYYYMMDD_HHMMSS.db  # Timestamped backup files (keeps last 10)
                                  #  Backups are also protected by .gitignore

##  Installation & Setup

### 1. Prerequisites
* Python 3.8+ installed
* pip (Python package manager)
* Git (for version control - optional but recommended)

** Security Note:** The project includes a `.gitignore` file that prevents accidentally committing sensitive files (certificates, keys, databases, uploaded files) to version control. Never remove or modify this file without understanding the security implications.

### 2. Install Dependencies
Open your terminal in the project folder and run:

```bash
python -m pip install -r requirements.txt
````

### 3. Generate Security Certificates

The system requires an SSL certificate to create a secure HTTPS tunnel. Run this script once to generate self-signed keys (cert.pem and key.pem):

```bash
python scripts/generate_cert.py
```

### 4. (Optional) Generate RSA Key Pairs

For hybrid cryptography operations (RSA + AES), generate server and client key pairs:

```bash
python utils/keygen.py
```

This creates RSA key pairs in the `keys/` directory for advanced encryption scenarios.

### 5. (Optional) Reset Application

To reset the application to its original state (removes all databases, keys, logs, and saved files):

```bash
python scripts/reset.py
```

** Warning:** This will permanently delete all user accounts, uploaded files, and audit logs!

### 6. (Optional) Create Admin User

To programmatically create an admin account (useful for initial setup):

```bash
python scripts/create_admin.py
```

This will output the admin credentials and the **TOTP Secret** which you must manually enter into your Authenticator App.

### 7. (Optional) Backup Audit Database

To create a backup of the audit database with automatic rotation:

```bash
python scripts/backup_audit_db.py
```

This maintains up to 10 most recent backups in the `backups/` directory.

## How to Run

### Start the Server:

```bash
python main.py
```

You should see: `>>> STARTING SECURE VAULT (Port 443) <<<`

### Access the Application:

Open your web browser and navigate to: **https://127.0.0.1:443**

**Note:** Because we are using a self-signed certificate, your browser will show a "Not Secure" warning. Click **Advanced** > **Proceed to 127.0.0.1 (unsafe)** to access the login page.

If SSL certificates are not found, the application will fallback to running on **http://127.0.0.1:5000** (insecure mode).

##  Usage Guide

### Register:

1. Click **"Register New Account"**.
2. Create a username and password.
3. **Scan the QR Code** with your Authenticator App (Google Authenticator / Microsoft Authenticator).
4. Save your TOTP secret (backup) in a secure location.

### Login:

1. Enter your **username** and **password**.
2. Enter the **6-digit code** from your Authenticator App.
3. Upon successful authentication, you'll be redirected to the dashboard.

### Dashboard:

- **Upload:** Select a file to encrypt and store securely (supports: TXT, PDF, PNG, JPG with magic byte validation)
- **Download:** Click a file to decrypt and retrieve it
- **Delete:** Permanently remove a file from storage
- **List Files:** View all files you've uploaded (displays original filenames)
- **View Audit Logs:** (Admin Only) Access the system-wide audit log
  - Monitor all user activity (Login Success/Failure, Upload, Download, Delete)
  - View timestamps, IP addresses, and user agents
  - Filter by username and action type
  - View failed login attempts with attempted usernames

### Admin Features:

- Access to `/logs/all` endpoint - View all audit logs with filtering
- Access to `/logs/failed-logins` endpoint - View failed login attempts
- Create backups of audit database for compliance and forensics

## Security Details

### Encryption:

**Symmetric Encryption (File Storage):**
- **Algorithm:** AES-256 in CTR (Counter) mode
- **Nonce:** Unique 16-byte random nonce for each file
- **Storage Format:** `[16-byte nonce][encrypted data]`
- **Key Storage:** Master encryption key stored in environment/configuration
- **CRITICAL:** Do not lose the encryption key or all encrypted data will be unrecoverable!

**Hybrid Encryption (Available via crypto_utils):**
- **RSA-OAEP:** 2048-bit RSA keys for encrypting AES session keys
- **AES-Fernet:** Symmetric encryption for file data
- **Use Case:** Confidentiality with key exchange capabilities

**Digital Signatures:**
- **RSA-PSS with SHA-256:** For non-repudiation and integrity verification
- **Signature Validation:** Verify data authenticity using sender's public key

### File Security:

- **Magic Byte Inspection:** Validates actual file content against allowed types
- **Allowed Types:** TXT, PDF, PNG, JPEG only
- **Secure Filename Handling:** Werkzeug's secure_filename prevents path traversal
- **UUID Storage Names:** Prevents filename-based attacks and collisions
- **Automatic Duplicate Handling:** Replaces existing files with same name per user

### Database Architecture:

- **users.db** (User & File Database):
  - **User Table:** Stores usernames, bcrypt-hashed passwords, TOTP secrets, failed login attempts, and account lock status
  - **File Table:** Maps original filenames to UUID-based storage names for each user with upload timestamps
  - Located in `instance/` directory
  
- **audit.db** (Audit Log Database):
  - **Immutable** log of all user actions (LOGIN_SUCCESS, LOGIN_FAILED, UPLOAD, DOWNLOAD, DELETE)
  - Records: user_id, action, filename, username_entered (for failed logins), IP address, user agent, timestamp
  - Separate database for security compliance and forensic analysis
  - **Backup Strategy:** Use `backup_audit_db.py` to create timestamped backups with automatic rotation

### Network Security:

- **Protocol:** HTTPS with TLS 1.2+
- **Port:** 443 (default HTTPS port)
- **Certificates:** Self-signed (for development) - Use CA-signed certs in production!

### Session Management:

- **Technology:** JWT (JSON Web Tokens)
- **Storage:** HTTPOnly, Secure cookies (prevents XSS attacks)
- **Expiry:** 30 minutes of inactivity
- **Secret Key:** Configurable in `config.py` ( Change in production!)

### File Isolation:

- Files are stored with UUID-based names (e.g., `a3f5b2c1-4d8e-4a9b-8c7f-123456789abc.pdf`)
- Database tracks mapping between original filenames and storage names per user
- Prevents filename collisions when multiple users upload files with the same name
- Users can only access files they uploaded (enforced by JWT token validation)
- Unauthorized access attempts are logged in audit database
- Duplicate filename handling: automatic replacement with audit trail

### Authentication Security:

- **Password Storage:** Bcrypt with automatic salting (cost factor optimized for security)
- **TOTP Implementation:** pyotp library with 30-second time windows
- **Brute Force Protection:** Account locking after failed attempts with cooldown period
- **Failed Login Logging:** All attempts logged with username, IP, and timestamp for threat analysis

## Configuration

### Files Generated by Scripts

**By `scripts/generate_cert.py` (Run before first start):**
- `cert.pem` - SSL certificate (self-signed, 4096-bit RSA, valid 365 days)
- `key.pem` - SSL private key
- `file_key.key` - AES-256 master encryption key (32 random bytes)

**By `utils/keygen.py` (Optional, for hybrid cryptography):**
- `keys/server_private.pem` - RSA 2048-bit private key for server
- `keys/server_public.pem` - RSA public key for server
- `keys/client_private.pem` - RSA 2048-bit private key for client
- `keys/client_public.pem` - RSA public key for client

**By `scripts/backup_audit_db.py` (Run on-demand):**
- `backups/audit_YYYYMMDD_HHMMSS.db` - Timestamped backup (keeps 10 most recent)

### Files Auto-Generated on Application Startup

**By `config.py` (when imported):**
- `secure_vault_storage/` - Directory for encrypted file storage

**By `main.py` via `db.create_all()` (first run):**
- `instance/users.db` - User database (credentials, TOTP secrets, file mappings)
- `instance/audit.db` - Audit log database (immutable activity records)

### Files Removed by `scripts/reset.py`

When you run `python scripts/reset.py`, it removes:
- `cert.pem`, `key.pem`, `file_key.key` (certificates and encryption key)
- All files in `secure_vault_storage/` (encrypted user files)
- All `.db` files in `instance/` (databases)
- All files in `__pycache__/` (Python cache)

**Note:** `reset.py` does NOT delete:
- RSA keys in `keys/` directory
- Audit backups in `backups/` directory

### Important Settings in `config.py`:

```python
SECRET_KEY = 'super-secret-key-change-in-prod'  # Change in production!
SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
SQLALCHEMY_BINDS = {
    'users': 'sqlite:///users.db',
    'audit': 'sqlite:///audit.db'
}
```

## Dependencies

The application requires the following Python packages (from `requirements.txt`):

- **Flask** - Web framework for routing and HTTP handling
- **Flask-SQLAlchemy** - ORM for database management (SQLite)
- **Flask-Bcrypt** - Password hashing with bcrypt algorithm
- **PyJWT** - JSON Web Token implementation for session management
- **cryptography** - AES-CTR encryption, RSA operations, and signature generation
- **Werkzeug** - Secure filename handling and utilities
- **pyotp** - TOTP (Time-based OTP) implementation for 2FA
- **qrcode** - QR code generation for authenticator app setup
- **pillow** - Image processing library (required by qrcode)
- **python-magic-bin** - File type detection via magic byte inspection

## Security Warnings

### For Development:

This configuration is made for learning and testing as according to assignment requirements.

### For Production:

- [ ] Replace self-signed certificates with CA-signed certificates
- [ ] Change `SECRET_KEY` in `config.py` to a strong, random value (use secrets.token_hex(32))
- [ ] Use environment variables for sensitive configuration (12-factor app principles)
- [ ] Implement rate limiting for authentication endpoints (prevent brute force at network level)
- [ ] Add CSRF protection for state-changing operations
- [ ] Use a production-grade database (PostgreSQL/MySQL with replication)
- [ ] Implement proper backup strategy for encryption keys and databases
- [ ] Set `debug=False` in `main.py`
- [ ] Use a production WSGI server (Gunicorn/uWSGI with multiple workers)
- [ ] Implement proper logging and monitoring (Sentry, ELK stack, etc.)
- [ ] Enable HSTS (HTTP Strict Transport Security) headers
- [ ] Implement Content Security Policy (CSP) headers
- [ ] Regular security audits and penetration testing
- [ ] Set up automated audit log backups with offsite storage
- [ ] Implement file size limits and upload quotas per user
- [ ] Add malware scanning for uploaded files (ClamAV integration)
- [ ] Consider implementing file versioning for audit purposes

##  Troubleshooting

### Certificate Errors:

- **Problem:** Browser shows "Not Secure" warning
- **Solution:** This is expected with self-signed certificates. Click "Advanced" and proceed, or use CA-signed certificates for production.

### Port 443 Already in Use:

- **Problem:** Error binding to port 443
- **Solution:** Run as administrator (Windows) or use `sudo` (Linux/Mac). Alternatively, change port in `main.py` to 5000 or 8443.

### Missing Dependencies:

- **Problem:** ImportError when running application
- **Solution:** Run `python -m pip install -r requirements.txt` to install all dependencies.

### File Upload Fails:

- **Problem:** "Invalid file type detected" error
- **Solution:** Only TXT, PDF, PNG, and JPEG files are allowed. The system uses magic byte inspection, so renaming extensions won't work.

### Lost Encryption Key:

- **Problem:** Encryption key configuration lost or corrupted
- **Solution:**  All encrypted files are unrecoverable without the key. Run `python scripts/reset.py` to start fresh (deletes all data).

### Admin Cannot See Logs:

- **Problem:** Admin user cannot access `/logs/all` or `/logs/failed-logins`
- **Solution:** Ensure the username is exactly "admin" (case-sensitive). Verify JWT token is valid and not expired.

### Database Lock Errors:

- **Problem:** SQLite database is locked
- **Solution:** SQLite doesn't handle concurrent writes well. Consider using PostgreSQL for production or ensure only one process accesses the database.

##  License

This project is for educational purposes (ACG Y2S2 CA2).

##  Author

DCDF/FT/2A/21 Group 1 , 2026
Anson, Denzel, Cedric, Junjie, Ewean.
Created as part of ACG (Applied Cryptography) coursework at Singapore Polytechnic.
