# Secure File Vault

A secure, web-based file storage application built with Python and Flask. This system implements military-grade AES encryption for file storage, a dual-layer authentication system (Password + TOTP), and full audit logging with complete session management.

## 🔐 Features

- **Dual-Layer Authentication:**
  - Traditional Username/Password (Bcrypt hashed).
  - **MFA/2FA:** Time-based One-Time Password (TOTP) compatible with Google/Microsoft Authenticator.
  - QR Code generation for easy authenticator app setup.
- **End-to-End Encryption:**
  - **In-Transit:** HTTPS/TLS Tunnel using SSL certificates (cert.pem & key.pem).
  - **At-Rest:** Files are encrypted with Fernet (AES-256 CTR) before being saved to disk.
- **Session Management:**
  - Secure, HTTPOnly cookies using JSON Web Tokens (JWT).
  - 30-minute session expiry with automatic token validation.
- **Non-Repudiation:**
  - All actions (Login, Upload, Delete) are recorded in an immutable Audit Log.
  - Separate audit database for security compliance.
  - **Admin Dashboard:** Dedicated interface for administrators to view system-wide audit logs..
- **User Isolation:**
  - Users can only access and decrypt their own uploaded files.
  - UUID-based file storage prevents filename collisions and unauthorized access.

## 📁 Project Structure

````text
ACG_CA2/
├── secure_vault_storage/   # Encrypted files storage directory
├── instance/               # SQLite database files (auto-generated)
│   ├── users.db           # User credentials & TOTP secrets
│   └── audit.db           # Audit logs (immutable)
├── static/                # Frontend assets
│   ├── css/
│   │   └── style.css     # Application styling
│   └── js/
│       └── main.js        # Client-side JavaScript
├── templates/             # HTML templates
│   └── index.html         # Main SPA (Single Page Application)
├── utils/                 # Utility scripts
│   └── keygen.py          # Key generation utilities
├── config.py              # Database & App Configuration
├── generate_cert.py       # Script to create SSL Certificates
├── main.py                # Application Entry Point
├── models.py              # Database Models (User, File, AuditLog)
├── routes_auth.py         # Authentication Logic (Login/Register/MFA)
├── routes_vault.py        # File Operations (Upload/Download/Delete/List)
├── utils.py               # Helper functions (Logging, Token validation)
├── create_admin.py        # Script to create admin user programmatically
├── reset.py               # System reset script (cleans all data)
└── requirements.txt       # Python Dependencies

## 🚀 Installation & Setup

### 1. Prerequisites
* Python 3.8+ installed
* pip (Python package manager)

### 2. Install Dependencies
Open your terminal in the project folder and run:

```bash
python -m pip install -r requirements.txt
````

### 3. Generate Security Certificates

The system requires an SSL certificate to create a secure HTTPS tunnel. Run this script once to generate self-signed keys (cert.pem and key.pem):

```bash
python generate_cert.py
```

### 4. (Optional) Reset Application

To reset the application to its original state (removes all databases, keys, logs, and saved files):

```bash
python reset.py
```

**⚠️ Warning:** This will permanently delete all user accounts, uploaded files, and audit logs!

### 5. (Optional) Create Admin User

To programmatically create an admin account (useful for initial setup):

```bash
python create_admin.py
```

This will output the admin credentials and the **TOTP Secret** which you must manually enter into your Authenticator App.

## 🏃‍♂️ How to Run

### Start the Server:

```bash
python main.py
```

You should see: `>>> STARTING SECURE VAULT (Port 443) <<<`

### Access the Application:

Open your web browser and navigate to: **https://127.0.0.1:443**

**Note:** Because we are using a self-signed certificate, your browser will show a "Not Secure" warning. Click **Advanced** > **Proceed to 127.0.0.1 (unsafe)** to access the login page.

If SSL certificates are not found, the application will fallback to running on **http://127.0.0.1:5000** (insecure mode).

## 📖 Usage Guide

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

- **Upload:** Select a file to encrypt and store securely.
- **Download:** Click a file to decrypt and retrieve it.
- **Delete:** Permanently remove a file from storage.
- **List Files:** View all files you've uploaded.
- **View Audit Logs:** (Admin Only) Access the system-wide audit log to monitor user activity (Login/Upload/Delete), timestamps, and IP addresses.

## 🛡️ Security Details

### Encryption:

- **Algorithm:** Fernet (AES-128 CBC with HMAC authentication)
- **Key Storage:** Unique encryption key stored in `file_key.key`
- **⚠️ CRITICAL:** Do not lose `file_key.key` or all encrypted data will be unrecoverable!

### Database Architecture:

- **users.db** (User Database):
  - **User Table:** Stores usernames, bcrypt-hashed passwords, and TOTP secrets
  - **File Table:** Maps original filenames to UUID-based storage names for each user
  - Located in `instance/` directory
- **audit.db** (Audit Log Database):
  - Immutable log of all user actions (LOGIN, UPLOAD, DELETE)
  - Timestamp-based for forensic analysis

### Network Security:

- **Protocol:** HTTPS with TLS 1.2+
- **Port:** 443 (default HTTPS port)
- **Certificates:** Self-signed (for development) - Use CA-signed certs in production!

### Session Management:

- **Technology:** JWT (JSON Web Tokens)
- **Storage:** HTTPOnly, Secure cookies (prevents XSS attacks)
- **Expiry:** 30 minutes of inactivity
- **Secret Key:** Configurable in `config.py` (⚠️ Change in production!)

### File Isolation:

- Files are stored with UUID-based names (e.g., `a3f5b2c1-4d8e-4a9b-8c7f-123456789abc.pdf`)
- Database tracks mapping between original filenames and storage names per user
- Prevents filename collisions when multiple users upload files with the same name
- Users can only access files they uploaded
- Unauthorized access attempts are logged

## 🔧 Configuration

### Key Files Generated on First Run:

- `file_key.key` - Fernet encryption key (⚠️ BACKUP THIS FILE!)
- `cert.pem` - SSL certificate
- `key.pem` - SSL private key
- `instance/users.db` - User database
- `instance/audit.db` - Audit log database

### Important Settings in `config.py`:

```python
SECRET_KEY = 'super-secret-key-change-in-prod'  # ⚠️ Change in production!
SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
SQLALCHEMY_BINDS = {
    'users': 'sqlite:///users.db',
    'audit': 'sqlite:///audit.db'
}
```

## 📦 Dependencies

The application requires the following Python packages (from `requirements.txt`):

- **Flask** - Web framework
- **Flask-SQLAlchemy** - ORM for database management
- **Flask-Bcrypt** - Password hashing
- **PyJWT** - JSON Web Token implementation
- **cryptography** - Fernet encryption
- **Werkzeug** - Secure filename handling
- **pyotp** - TOTP implementation
- **qrcode** - QR code generation
- **pillow** - Image processing for QR codes

## ⚠️ Security Warnings

### For Development:

✅ This configuration is suitable for learning and testing.

### For Production:

- [ ] Replace self-signed certificates with CA-signed certificates
- [ ] Change `SECRET_KEY` in `config.py` to a strong, random value
- [ ] Use environment variables for sensitive configuration
- [ ] Implement rate limiting for authentication endpoints
- [ ] Add CSRF protection
- [ ] Use a production-grade database (PostgreSQL/MySQL)
- [ ] Implement proper backup strategy for `file_key.key`
- [ ] Set `debug=False` in `main.py`
- [ ] Use a production WSGI server (Gunicorn/uWSGI)
- [ ] Implement proper logging and monitoring

## 🛠️ Troubleshooting

### Certificate Errors:

- **Problem:** Browser shows "Not Secure" warning
- **Solution:** This is expected with self-signed certificates. Click "Advanced" and proceed.

### Port 443 Already in Use:

- **Problem:** Error binding to port 443
- **Solution:** Run as administrator (Windows) or use `sudo` (Linux/Mac), or change port in `main.py`

### Missing Dependencies:

- **Problem:** ImportError when running application
- **Solution:** Run `python -m pip install -r requirements.txt`

### Lost Encryption Key:

- **Problem:** `file_key.key` was deleted or lost
- **Solution:** ⚠️ All encrypted files are unrecoverable. Run `python reset.py` to start fresh.

## 📝 License

This project is for educational purposes (ACG Y2S2 CA2).

## 👨‍💻 Author

DCDF/FT/2A/21 Group 1 , 2026
Anson, Denzel, Cedric, Junjie, Ewean.
Created as part of ACG (Applied Cryptography) coursework at Singapore Polytechnic.
