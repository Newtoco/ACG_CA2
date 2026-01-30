# Administrative Scripts

This folder contains utility and administrative scripts for the Secure File Vault system.

## Scripts Overview

### User Management
- **`create_admin.py`** - Create an administrator account
- **`migrate_user_keys.py`** - Generate RSA keypairs for existing users (non-repudiation)

### Database Operations
- **`backup_audit_db.py`** - Backup audit logs database
- **`reset.py`** - Reset the database (WARNING: Deletes all data)

### Monitoring & Verification
- **`view_logs.py`** - View audit logs (also accessible via web interface)
- **`verify_nonrepudiation.py`** - Check non-repudiation implementation status

## Usage

Run scripts from the project root directory:

```bash
# Example: Create admin user
python scripts/create_admin.py

# Example: Verify non-repudiation
python scripts/verify_nonrepudiation.py

# Example: Backup database
python scripts/backup_audit_db.py
```

## Security Notes

- Only run these scripts with appropriate permissions
- `reset.py` is destructive - use with caution
- Backup database before running migration scripts
