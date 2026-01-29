"""
Reset Script for Secure Vault Application
This script cleans up all generated files and databases to reset the application to its initial state.
"""

import os
import sys
import shutil
from pathlib import Path

# Get project root directory (parent of scripts folder)
script_dir = Path(__file__).parent
project_root = script_dir.parent
os.chdir(project_root)

def delete_file(filepath):
    """Delete a file if it exists."""
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
            print(f"✓ Deleted: {filepath}")
        else:
            print(f"○ Not found (skipped): {filepath}")
    except Exception as e:
        print(f"✗ Error deleting {filepath}: {e}")

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
                        print(f"  ✓ Deleted: {filename}")
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                        files_deleted += 1
                        print(f"  ✓ Deleted directory: {filename}")
                except Exception as e:
                    print(f"  ✗ Failed to delete {file_path}: {e}")
            
            if files_deleted > 0:
                print(f"✓ Cleared {files_deleted} item(s) from: {directory}")
            else:
                print(f"○ Directory empty: {directory}")
        else:
            print(f"○ Directory not found (skipped): {directory}")
    except Exception as e:
        print(f"✗ Error clearing directory {directory}: {e}")

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
                        print(f"  ✓ Deleted database: {filename}")
                    except Exception as e:
                        print(f"  ✗ Failed to delete {file_path}: {e}")
            
            if files_deleted > 0:
                print(f"✓ Cleared {files_deleted} database(s) from: {directory}")
            else:
                print(f"○ No databases found in: {directory}")
        else:
            print(f"○ Directory not found (skipped): {directory}")
    except Exception as e:
        print(f"✗ Error clearing databases in {directory}: {e}")

def main():
    """Main reset function."""
    print("=" * 60)
    print("SECURE VAULT - RESET SCRIPT")
    print("=" * 60)
    print("\nThis will delete all generated files and reset the application.\n")
    
    # Get the script's directory
    base_dir = Path(__file__).parent
    
    # Files to delete
    print("1. Deleting certificate and key files...")
    delete_file(base_dir / "key.pem")
    delete_file(base_dir / "cert.pem")
    delete_file(base_dir / "file_key.key")
    
    # Clear vault storage
    print("\n2. Clearing secure vault storage...")
    clear_directory(base_dir / "secure_vault_storage")
    
    # Clear instance databases
    print("\n3. Clearing instance databases...")
    clear_database_directory(base_dir / "instance")
    
    # Clear __pycache__
    print("\n4. Clearing Python cache...")
    clear_directory(base_dir / "__pycache__")
    
    print("\n" + "=" * 60)
    print("RESET COMPLETE!")
    print("=" * 60)
    print("\nYou can now run the application with a fresh start.")
    print("Remember to run 'python generate_cert.py' before starting the server.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nReset cancelled by user.")
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
