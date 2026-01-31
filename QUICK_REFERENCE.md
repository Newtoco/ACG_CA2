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

### Manage User Keys
```bash
# Generate plaintext keys (legacy/backward compatibility)
python scripts/manage_user_keys.py --strategy generate

# Encrypt existing plaintext keys
python scripts/manage_user_keys.py --strategy encrypt --temp-password TempPass123

# Regenerate with new encrypted keys
python scripts/manage_user_keys.py --strategy regenerate --temp-password TempPass123

# Verify migration status
python scripts/manage_user_keys.py --verify
```

### Verify Security Implementation
```bash
# Run all security checks
python scripts/verify_security.py --all

# Check specific components
python scripts/verify_security.py --keys          # User keypairs
python scripts/verify_security.py --encryption    # Encrypted keys
python scripts/verify_security.py --signatures    # File signatures
```

### Generate SSL Certificates
```bash
python scripts/generate_cert.py
```

### Backup Audit Database
```bash
python scripts/backup_audit_db.py
```

### View Audit Logs
```bash
python scripts/view_logs.py
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

- Dual Authentication: Password + TOTP (2FA)
- End-to-End Encryption: AES-256-GCM at rest, TLS in transit
- Non-Repudiation: RSA signatures per user
- Audit Logging: Immutable logs in separate database
- Session Management: JWT with HTTPOnly cookies
- File Integrity: GCM authenticated encryption  

## Troubleshooting

**SSL Certificate Error:**
```bash
python scripts/generate_cert.py
```

**Missing or Plaintext User Keys:**
```bash
# Generate keys for users without them
python scripts/manage_user_keys.py --strategy generate

# Encrypt existing plaintext keys
python scripts/manage_user_keys.py --strategy encrypt --temp-password TempPass123
```

**Verify Security Status:**
```bash
python scripts/verify_security.py --all
```

**Database Issues:**
Delete `instance/` folder and restart to recreate databases.
