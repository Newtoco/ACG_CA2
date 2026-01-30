# Quick Reference Guide

## Starting the Application

```bash
python main.py
```

Access at: `https://localhost:443` or `http://localhost:5000`

## Administrative Tasks

### Create Admin User
```bash
python scripts/create_admin.py
```

### Migrate User Keys (for non-repudiation)
```bash
python scripts/migrate_user_keys.py
```

### Backup Audit Database
```bash
python scripts/backup_audit_db.py
```

### Verify Non-Repudiation Implementation
```bash
python scripts/verify_nonrepudiation.py
```

### Reset System (WARNING: Deletes all data)
```bash
python scripts/reset.py
```

## File Structure

- **`app/`** - Main application code
  - **`routes/`** - Flask blueprints (auth, vault)
  - **`utils/`** - Cryptographic utilities
- **`scripts/`** - Admin & utility scripts
- **`static/`** - CSS and JavaScript
- **`templates/`** - HTML templates
- **`instance/`** - Databases (git-ignored)
- **`secure_vault_storage/`** - Encrypted files (git-ignored)

## Security Features

✅ **Dual Authentication** - Password + TOTP (2FA)  
✅ **End-to-End Encryption** - AES-256-GCM at rest, TLS in transit  
✅ **Non-Repudiation** - RSA signatures per user  
✅ **Audit Logging** - Immutable logs in separate database  
✅ **Session Management** - JWT with HTTPOnly cookies  
✅ **File Integrity** - GCM authenticated encryption  

## Troubleshooting

**SSL Certificate Error:**
```bash
python scripts/generate_cert.py
```

**Missing User Keys:**
```bash
python scripts/migrate_user_keys.py
```

**Database Issues:**
Delete `instance/` folder and restart to recreate databases.
