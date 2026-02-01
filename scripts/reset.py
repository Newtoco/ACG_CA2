"""
Anson's Code

Reset Script for Secure Vault Application

Cleans up all generated files and databases to reset the application to initial state.

What gets deleted:
1. certs/ - SSL certificates and master encryption key
2. secure_vault_storage/ - All encrypted uploaded files
3. instance/*.db - User database and audit log database
4. backups/ - Database backup files

Security Implications:
- ALL ENCRYPTED FILES WILL BE LOST (no recovery possible)
- All user accounts will be deleted
- Complete audit trail will be erased
- SSL certificates will need regeneration

Use Cases:
- Development/testing cleanup
- Preparing for fresh deployment
- Removing sensitive data before decommissioning

After running this script:
1. Run: python scripts/generate_cert.py (regenerate certificates)
2. Run: python scripts/create_admin.py (create admin account)
3. Start: python main.py (launch application)

WARNING: This operation is IRREVERSIBLE. Backup any important data first.
"""

import os
import shutil
from pathlib import Path

def delete_file(filepath):
    """Delete a file if it exists. Safe operation (no error if file doesn't exist)"""
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
            print(f"Deleted: {filepath}")
        else:
            print(f"Not found (skipped): {filepath}")
    except Exception as e:
        print(f"Error deleting {filepath}: {e}")

def clear_directory(directory):
    """Clear all files in a directory without deleting the directory itself."""
    try:
        if os.path.exists(directory):
            files_deleted = 0
            for filename in os.listdir(directory):
                file_path = os.path.join(directory, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                        files_deleted += 1
                        print(f"  Deleted: {filename}")
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                        files_deleted += 1
                        print(f"  Deleted directory: {filename}")
                except Exception as e:
                    print(f"  Failed to delete {file_path}: {e}")
            
            if files_deleted > 0:
                print(f"Cleared {files_deleted} item(s) from: {directory}")
            else:
                print(f"Directory empty: {directory}")
        else:
            print(f"Directory not found (skipped): {directory}")
    except Exception as e:
        print(f"Error clearing directory {directory}: {e}")

def clear_database_directory(directory):
    """Clear all database files (.db) in a directory."""
    try:
        if os.path.exists(directory):
            files_deleted = 0
            for filename in os.listdir(directory):
                if filename.endswith('.db'):
                    file_path = os.path.join(directory, filename)
                    try:
                        os.unlink(file_path)
                        files_deleted += 1
                        print(f"  Deleted database: {filename}")
                    except Exception as e:
                        print(f"  Failed to delete {file_path}: {e}")
            
            if files_deleted > 0:
                print(f"Cleared {files_deleted} database(s) from: {directory}")
            else:
                print(f"No databases found in: {directory}")
        else:
            print(f"Directory not found (skipped): {directory}")
    except Exception as e:
        print(f"Error clearing databases in {directory}: {e}")

def main():
    """Main reset function."""
    print("=" * 60)
    print("SECURE VAULT - RESET SCRIPT")
    print("=" * 60)
    print("\nThis will delete all generated files and reset the application.\n")
    
    # Get the project root directory (parent of scripts)
    base_dir = Path(__file__).parent.parent
    
    # Files to delete
    print("1. Deleting certificate and key files...")
    delete_file(base_dir / "certs" / "key.pem")
    delete_file(base_dir / "certs" / "cert.pem")
    delete_file(base_dir / "certs" / "file_key.key")
    
    # Clear vault storage
    print("\n2. Clearing secure vault storage...")
    clear_directory(base_dir / "secure_vault_storage")
    
    # Clear instance databases
    print("\n3. Clearing instance databases...")
    clear_database_directory(base_dir / "instance")
    
    # Clear backups
    print("\n4. Clearing backup files...")
    clear_directory(base_dir / "backups")
    
    print("\n" + "=" * 60)
    print("RESET COMPLETE")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Run: python scripts/generate_cert.py")
    print("2. Run: python scripts/create_admin.py")
    print("3. Start: python main.py")

if __name__ == "__main__":
    main()
