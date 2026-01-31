# Secure File Vault

A secure web-based file storage application built with Python and Flask. This system implements defense-in-depth security with AES-256-GCM encryption, dual-factor authentication, encrypted private key storage, digital signatures for non-repudiation, and comprehensive audit logging.

## Features

**Authentication and Access Control:**
- Dual-factor authentication with username/password and TOTP (Time-based One-Time Password)
- Password hashing using Bcrypt with salt
- TOTP compatible with Google Authenticator and Microsoft Authenticator
- QR code generation for easy authenticator setup
- Account lockout after failed login attempts
- Session management with JWT tokens and HTTPOnly cookies
- 30-minute session timeout with automatic expiry

**Encryption and Key Management:**
- File encryption at rest using AES-256-GCM authenticated encryption
- Private key encryption using PBKDF2-HMAC-SHA256 (600,000 iterations) and AES-256-GCM
- User private keys encrypted with individual passwords (never stored in plaintext)
- Decrypted keys stored in server-side session memory only (session-scoped)
- TLS/SSL encryption for data in transit
- RSA-2048 keypairs for each user (digital signatures)
- Separate encryption keys for files and user private keys
- Password-based key derivation for secure private key storage
- Defense against database breach attacks

**Non-Repudiation and Audit:**
- Digital signatures on all uploaded files using RSA-PSS with SHA-256
- Immutable audit logs in separate database
- All actions logged with timestamps, IP addresses, and user information
- Admin dashboard for viewing and filtering audit logs
- Complete audit trail for compliance and forensics

**User Isolation and Security:**
- Users can only access their own files
- UUID-based file storage prevents filename collisions
- User private keys encrypted with individual passwords
- Server-side session storage for decrypted private keys (session-scoped only)
- Input sanitization and validation throughout the application

## Project Structure

```
ACG_CA2/
├── app/                    # Application routes and blueprints
│   └── routes/
│       ├── auth.py        # Authentication endpoints (login, register, MFA)
│       └── vault.py       # File operations endpoints (upload, download, delete)
├── certs/                  # SSL/TLS certificates and encryption keys
│   ├── cert.pem           # SSL certificate (generated)
│   ├── key.pem            # SSL private key (generated)
│   └── file_key.key       # Master file encryption key (generated)
├── flask_session/          # Server-side session files (runtime artifact, git-ignored)
├── instance/               # Database files (auto-generated, git-ignored)
│   ├── users.db           # User credentials, keys, and file metadata
│   └── audit.db           # Immutable audit logs
├── scripts/                # Administrative and maintenance scripts
│   ├── create_admin.py    # Create administrator account
│   ├── manage_user_keys.py # Generate or migrate user RSA keypairs
│   ├── verify_security.py # Verify security implementation
│   ├── generate_cert.py   # Generate SSL certificates and encryption keys
│   ├── backup_audit_db.py # Backup audit database
│   ├── view_logs.py       # View audit logs from command line
│   └── reset.py           # Reset system (deletes all data)
├── secure_vault_storage/   # Encrypted file storage (git-ignored)
├── static/                 # Frontend assets
│   ├── css/
│   │   └── style.css      # Application styling
│   └── js/
│       └── main.js        # Client-side JavaScript
├── templates/              # HTML templates
│   └── index.html         # Single-page application
├── utils/                  # Utility modules
│   ├── crypto_utils.py    # File encryption and signature operations
│   └── key_encryption.py  # Private key encryption utilities
├── auth_utils.py           # Authentication helper functions
├── config.py               # Application and database configuration
├── main.py                 # Application entry point
├── models.py               # Database models (User, File, AuditLog)
└── requirements.txt        # Python dependencies
```

## Installation and Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Administrator/root access for HTTPS on port 443

### Step 1: Install Dependencies

Open a terminal in the project directory and run:

```bash
python -m pip install -r requirements.txt
```

### Step 2: Generate Security Certificates and Keys

The system requires SSL certificates and encryption keys. Generate them once:

```bash
python scripts/generate_cert.py
```

This creates:
- `certs/cert.pem` - SSL/TLS certificate
- `certs/key.pem` - SSL/TLS private key  
- `certs/file_key.key` - Master file encryption key

WARNING: Keep these files secure. Loss of `file_key.key` means all encrypted files are unrecoverable.

### Step 3: Create Administrator Account

Create the initial admin user:

```bash
python scripts/create_admin.py
```

This generates:
- Admin username and password
- RSA-2048 keypair (private key encrypted)
- TOTP secret for two-factor authentication
- QR code for authenticator app setup

Save the TOTP secret and scan the QR code with Google Authenticator or Microsoft Authenticator.

### Step 4: Start the Application

```bash
python main.py
```

The server will start on HTTPS port 443. You should see:
```
System: Databases & Keys Ready.
>>> STARTING SECURE VAULT (Port 443) <<<
```

### Step 5: Access the Application

Open your browser and navigate to:
```
https://127.0.0.1:443
```

NOTE: You will see a security warning because the certificate is self-signed. Click "Advanced" and proceed to access the application. For production, use certificates from a trusted Certificate Authority.

## Administrative Tasks

### Generate or Migrate User Keys

Generate RSA keypairs for users (plaintext, legacy mode):
```bash
python scripts/manage_user_keys.py --strategy generate
```

Encrypt existing plaintext private keys:
```bash
python scripts/manage_user_keys.py --strategy encrypt --temp-password TempPass123
```

Regenerate all keys with encrypted storage:
```bash
python scripts/manage_user_keys.py --strategy regenerate --temp-password TempPass123
```

Verify key migration status:
```bash
python scripts/manage_user_keys.py --verify
```

### Verify Security Implementation

Run comprehensive security checks:
```bash
python scripts/verify_security.py --all
```

Check specific components:
```bash
python scripts/verify_security.py --keys          # User RSA keypairs
python scripts/verify_security.py --encryption    # Private key encryption
python scripts/verify_security.py --signatures    # File signatures
```

### Backup Audit Logs

Create timestamped backup of audit database:
```bash
python scripts/backup_audit_db.py
```

### View Audit Logs

View logs from command line:
```bash
python scripts/view_logs.py
```

Or access through the admin dashboard in the web interface.

### Reset System

WARNING: This permanently deletes all data, keys, and files.

```bash
python scripts/reset.py
```

## Usage Guide

### Registration

1. Click "Register New Account" on the login page
2. Choose a username and strong password
3. Scan the displayed QR code with your authenticator app
4. Save the TOTP secret as a backup in a secure location
5. Complete registration

Your account now has:
- Bcrypt-hashed password
- RSA-2048 keypair (private key encrypted with your password)
- TOTP secret for two-factor authentication

### Login

1. Enter your username and password
2. Enter the 6-digit TOTP code from your authenticator app
3. Access granted to your secure file vault

After 5 failed attempts, your account will be locked for 15 minutes.

### Dashboard Operations

**Upload Files:**
- Select a file from your computer
- File is encrypted with AES-256-GCM
- Digital signature created with your RSA private key
- Encrypted file stored with UUID filename
- Upload action logged in audit database

**Download Files:**
- Click on any file you previously uploaded
- File is decrypted using the master encryption key
- Signature verified with your RSA public key
- Original file downloaded to your computer
- Download action logged

**Delete Files:**
- Click the delete button next to any file
- File permanently removed from storage
- Database entry removed
- Delete action logged

**View Audit Logs (Admin Only):**
- Access comprehensive audit trail
- Filter by user, action type, or date
- View timestamps, IP addresses, and action details
- Monitor system security and compliance

## Security Architecture

### Encryption Standards

**File Encryption:**
- Only .txt,.jpeg,.png and .pdf file formats allowed
- Algorithm: AES-256-GCM (Galois/Counter Mode)
- Authenticated encryption with integrity verification
- Unique nonce per file encryption operation
- Master key stored in `certs/file_key.key`
- CRITICAL: Backup this file securely - loss means all encrypted files are unrecoverable
- Never commit to version control (already in .gitignore)

**Private Key Encryption:**
- Key derivation: PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2023 recommendation)
- Encryption: AES-256-GCM with authenticated encryption
- Random 16-byte salt per user (unique per key)
- Private keys encrypted with user passwords before database storage
- Keys never stored in plaintext in database
- Nonce and authentication tag included for integrity
- Decrypted only during login and stored in server-side session
- Automatic session cleanup on logout or timeout
- Resistance to database breach attacks

**Digital Signatures:**
- Algorithm: RSA-PSS with SHA-256
- Key size: 2048-bit RSA keypairs per user
- All uploaded files digitally signed
- Signatures verified on download
- Non-repudiation for file authenticity

**Transport Security:**
- Protocol: HTTPS/TLS
- Self-signed RSA-4096 certificates (development)
- Certificate files: `certs/cert.pem` (public) and `certs/key.pem` (private)
- All data encrypted in transit
- Replace with CA-signed certificates for production

**File Permissions (Important):**

Linux/Mac:
```bash
chmod 700 certs/              # Directory: owner only
chmod 600 certs/*.pem         # Certificate files: owner read/write only
chmod 600 certs/*.key         # Key files: owner read/write only
```

Windows:
- Right-click each file in certs/ folder
- Properties > Security > Advanced
- Disable inheritance > Remove all users except yourself

### Authentication Architecture

**Password Security:**
- Hashing: Bcrypt with automatic salt generation
- Stored in database as hashed values only
- Plaintext passwords never stored

**Two-Factor Authentication:**
- TOTP (Time-based One-Time Password)
- 6-digit codes, 30-second validity window
- Compatible with RFC 6238 standard
- Secrets encrypted in database

**Session Management:**
- Technology: JWT (JSON Web Tokens)
- Storage: HTTPOnly, Secure cookies
- 30-minute expiry with automatic timeout
- Server-side session storage using Flask-Session
- Decrypted private keys stored in session memory only
- Keys automatically cleared on session expiry
- Session data stored in filesystem (not in cookies)
- Enhanced security against token theft

**Account Protection:**
- Failed login tracking per user
- Automatic lockout after 5 failed attempts
- 15-minute lockout duration
- All attempts logged in audit database

### Database Architecture

The system uses two separate SQLite databases for security isolation:

**users.db (User Database):**
- User credentials (username, bcrypt password hash)
- TOTP secrets (encrypted)
- RSA keypairs (public keys plaintext, private keys encrypted with AES-256-GCM)
- Private key encryption salts for PBKDF2 derivation
- File metadata (original names, storage UUIDs, upload times)
- Digital signatures for uploaded files
- Failed login attempts and account status

SECURITY NOTE: Private keys are NEVER stored in plaintext. They are encrypted with the user's password using PBKDF2 + AES-256-GCM. Even if the database is compromised, private keys remain secure.

**audit.db (Audit Log Database):**
- Immutable append-only log
- All user actions: LOGIN, UPLOAD, DOWNLOAD, DELETE, FAILED_LOGIN
- Timestamps with microsecond precision
- IP addresses and user agents
- Complete audit trail for compliance and forensics
- Separate database prevents tampering of logs

### Defense in Depth

The system implements multiple security layers:

1. Network layer: HTTPS/TLS encryption
2. Application layer: JWT session tokens, CSRF protection
3. Authentication layer: Dual-factor (password + TOTP)
4. Authorization layer: User isolation, permission checks
5. Data layer: Encrypted storage, database separation, encrypted private keys
6. Audit layer: Comprehensive logging, immutable records
7. Key management: Password-encrypted private keys, secure key derivation (PBKDF2)
8. Session security: Server-side storage, automatic key cleanup

### Private Key Security Flow

**Registration:**
```
User Password → PBKDF2 (600k iterations) → Encryption Key
RSA Private Key → AES-256-GCM Encrypt → Encrypted Key → Database
Public Key → Database (plaintext, not sensitive)
```

**Login:**
```
User Password + Salt (from DB) → PBKDF2 → Encryption Key
Encrypted Private Key (from DB) → AES-256-GCM Decrypt → Private Key
Private Key → Server-side Session (memory only, 30 min expiry)
```

**File Upload:**
```
Private Key (from session) → RSA Sign File → Digital Signature
File Data → AES-256-GCM Encrypt → Encrypted File → Storage
Signature → Database
```

**Session Expiry:**
```
30 minutes timeout OR user logout → Session cleared
Private Key → Automatically deleted from memory
User must re-login to decrypt key again
```

## Configuration

### Critical Files

These files are automatically generated and must be kept secure:

**certs/file_key.key**
- Master encryption key for all files
- Loss means all encrypted files are unrecoverable
- Must be backed up securely
- Never commit to version control

**certs/cert.pem and certs/key.pem**
- SSL/TLS certificates for HTTPS
- Self-signed for development
- Replace with CA-signed certificates for production

**instance/users.db**
- User credentials and file metadata
- Contains encrypted private keys and TOTP secrets
- Back up regularly

**instance/audit.db**
- Immutable audit logs
- Required for compliance and forensics
- Back up regularly

### Application Settings

Key configuration in `config.py`:

```python
SECRET_KEY = 'super-secret-key-change-in-prod'  # Change in production
SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
SQLALCHEMY_BINDS = {
    'users': 'sqlite:///users.db',
    'audit': 'sqlite:///audit.db'
}
SESSION_TYPE = 'filesystem'  # Server-side session storage
PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes
```

For production deployment:
- Change SECRET_KEY to a strong random value
- Use environment variables for sensitive configuration
- Consider PostgreSQL or MySQL instead of SQLite
- Set proper file permissions on key files
- Disable debug mode

## Dependencies

The application requires these Python packages (see requirements.txt):

**Web Framework:**
- Flask - Core web framework
- Flask-SQLAlchemy - Database ORM
- Flask-Bcrypt - Password hashing
- Flask-Session - Server-side session management
- Werkzeug - Secure filename handling

**Cryptography:**
- cryptography - AES-256-GCM encryption and RSA operations
- PyJWT - JSON Web Token implementation
- pyotp - TOTP implementation for two-factor authentication
- qrcode - QR code generation for TOTP setup
- pillow - Image processing for QR codes
- magic - File header check for approved file formats 

**Database:**
- SQLAlchemy - ORM and database abstraction

Install all dependencies:
```bash
python -m pip install -r requirements.txt
```

**Key Dependencies:**
- Flask: Web framework
- Flask-SQLAlchemy: Database ORM
- Flask-Bcrypt: Password hashing
- Flask-Session: Server-side session management for encrypted key storage
- cryptography: AES-256-GCM encryption and RSA key operations
- PyJWT: JWT token management
- pyotp: TOTP 2FA implementation
- qrcode: QR code generation for 2FA setup

## Production Deployment Checklist

This application is configured for development and learning. For production deployment, implement these security enhancements:

**Certificates and Keys:**
- [ ] Replace self-signed certificates with CA-signed certificates from a trusted authority
- [ ] Store certificates in secure location with restricted file permissions
- [ ] Implement certificate rotation policy
- [ ] Use hardware security modules (HSM) for key storage if available

**Application Configuration:**
- [ ] Change SECRET_KEY to a cryptographically random value
- [ ] Store sensitive configuration in environment variables, not code
- [ ] Set debug=False in main.py
- [ ] Remove or secure the admin account creation script
- [ ] Implement proper logging with log rotation

**Database:**
- [ ] Migrate from SQLite to production database (PostgreSQL or MySQL)
- [ ] Implement database connection pooling
- [ ] Set up automated database backups
- [ ] Encrypt database at rest
- [ ] Implement database access controls

**Web Server:**
- [ ] Use production WSGI server (Gunicorn, uWSGI) instead of Flask development server
- [ ] Configure reverse proxy (Nginx, Apache) for load balancing
- [ ] Implement rate limiting on all endpoints
- [ ] Add CSRF protection tokens
- [ ] Configure proper CORS policies

**Security Enhancements:**
- [ ] Implement password complexity requirements
- [ ] Add password change functionality
- [ ] Implement account recovery process
- [ ] Add email verification for new accounts
- [ ] Set up security monitoring and alerting
- [ ] Implement intrusion detection
- [ ] Add file size limits and upload restrictions
- [ ] Scan uploaded files for malware

**Compliance and Monitoring:**
- [ ] Set up centralized logging system
- [ ] Implement real-time security monitoring
- [ ] Configure automated security updates
- [ ] Perform regular security audits
- [ ] Document security policies and procedures
- [ ] Implement data retention policies
- [ ] Ensure compliance with relevant regulations (GDPR, etc.)

**Infrastructure:**
- [ ] Use firewall to restrict access to necessary ports only
- [ ] Implement network segmentation
- [ ] Set up redundancy and failover systems
- [ ] Configure automated backups with off-site storage
- [ ] Implement disaster recovery plan
- [ ] Use container orchestration for scaling (Docker, Kubernetes)

## Troubleshooting

**Browser shows security warning:**
- Cause: Self-signed SSL certificate not trusted by browser
- Solution: Click "Advanced" and proceed to site. This is expected for development. Use CA-signed certificates for production.

**Port 443 already in use:**
- Cause: Another application using HTTPS port
- Solution: Stop the other application, or run as administrator (Windows) / sudo (Linux/Mac). Alternatively, change port in main.py.

**Module not found errors:**
- Cause: Missing Python dependencies
- Solution: Run `python -m pip install -r requirements.txt`

**File encryption key not found error:**
- Cause: Missing `certs/file_key.key` (encryption key not generated)
- Solution: Run `python scripts/generate_cert.py` to generate required certificates and keys. The application will provide a clear error message with instructions if this key is missing.

**Database errors or table not found:****
- Cause: Database not initialized or corrupted
- Solution: Delete `instance/` folder and restart application. Databases will be recreated. Note: This deletes all user data.

**Cannot decrypt files:**
- Cause: Lost or corrupted `certs/file_key.key`
- Solution: All encrypted files are permanently unrecoverable. Run `python scripts/reset.py` to start fresh. Always backup the encryption key.

**Two-factor authentication not working:**
- Cause: Time synchronization issue between server and authenticator app
- Solution: Ensure server and mobile device have correct time. TOTP requires synchronized clocks.

**Account locked:**
- Cause: Too many failed login attempts
- Solution: Wait 15 minutes for automatic unlock, or reset the user account.

**Private key decryption fails:**
- Cause: Wrong password or corrupted encrypted key
- Solution: Cannot recover without correct password. User must regenerate keypair (loses ability to verify old signatures).

**Session expired errors (401 Unauthorized):**
- Cause: Server-side session expired (30-minute timeout) or server restart cleared session data
- Solution: Log out and log back in. Private keys are decrypted fresh on each login.

**Private key not found in session:**
- Cause: Session cleared due to timeout, logout, or server restart
- Solution: Log in again to decrypt and load private key into session memory.

**Permission denied errors:**
- Cause: Insufficient file system permissions
- Solution: Run with appropriate permissions, or adjust file permissions on `instance/`, `certs/`, `flask_session/`, and `secure_vault_storage/` directories.

## Additional Documentation

For more detailed information, see:
- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Quick command reference for common tasks
- [scripts/README.md](scripts/README.md) - Administrative scripts documentation

## Implementation Summary

This secure file vault system implements enterprise-grade security features:

**Core Security Implementations:**
1. **Encrypted Private Key Storage** - User private keys encrypted with PBKDF2 (600k iterations) + AES-256-GCM, never stored in plaintext
2. **Receipt-based Digital Signatures** - Files signed with structured receipts (user_id + filename + timestamp + SHA256) for stronger non-repudiation
3. **Server-side Session Management** - Decrypted keys stored in filesystem-based sessions, automatically cleared on logout
4. **Defense in Depth** - Multiple security layers from network (TLS) to data (AES-256-GCM encryption)

**Key Features:**
- Dual-factor authentication (password + TOTP)
- File encryption at rest with AES-256-GCM
- Digital signatures for non-repudiation
- Comprehensive audit logging
- Account lockout protection
- Session timeout (30 minutes)
- User isolation and access control

**Production Readiness:**
- Clear error messages for missing dependencies
- Robust startup validation
- Comprehensive troubleshooting documentation
- Administrative scripts for maintenance
- Clean codebase with no redundant files

## License and Attribution

This project is for educational purposes as part of the Applied Cryptography (ACG) coursework at Singapore Polytechnic.

## Authors

DCDF/FT/2A/21 Group 1, 2026
- Anson
- Denzel
- Cedric
- Junjie
- Ewean

Singapore Polytechnic, Diploma in Cybersecurity and Digital Forensics
