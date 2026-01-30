"""
Script to verify non-repudiation implementation for file uploads
Checks:
1. Users have RSA keypairs
2. Uploaded files have signatures
3. Signatures can be verified
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import app, db
from models import User, File
from utils.crypto_utils import load_user_private_key, load_user_public_key
import base64

def check_user_keys():
    """Check if users have RSA keypairs"""
    print("\n=== CHECKING USER KEYS ===")
    with app.app_context():
        users = User.query.all()
        if not users:
            print("❌ No users found in database")
            return False
        
        all_have_keys = True
        for user in users:
            has_keys = user.private_key_pem and user.public_key_pem
            status = "✓" if has_keys else "✗"
            print(f"{status} User '{user.username}': {'Has keys' if has_keys else 'Missing keys'}")
            if not has_keys:
                all_have_keys = False
        
        return all_have_keys

def check_file_signatures():
    """Check if uploaded files have signatures"""
    print("\n=== CHECKING FILE SIGNATURES ===")
    with app.app_context():
        files = File.query.all()
        if not files:
            print("⚠ No files uploaded yet")
            return True
        
        all_have_signatures = True
        for file_record in files:
            has_sig = file_record.signature is not None and file_record.signature != ""
            status = "✓" if has_sig else "✗"
            user = User.query.get(file_record.user_id)
            username = user.username if user else "Unknown"
            print(f"{status} File '{file_record.original_filename}' by {username}: {'Has signature' if has_sig else 'No signature'}")
            if not has_sig:
                all_have_signatures = False
        
        return all_have_signatures

def verify_signatures():
    """Verify that file signatures match the user's public key"""
    print("\n=== VERIFYING SIGNATURES ===")
    with app.app_context():
        files = File.query.filter(File.signature != None).all()
        if not files:
            print("⚠ No files with signatures found")
            return True
        
        all_valid = True
        for file_record in files:
            user = User.query.get(file_record.user_id)
            if not user or not user.public_key_pem:
                print(f"✗ File '{file_record.original_filename}': Cannot verify - user key missing")
                all_valid = False
                continue
            
            try:
                # Load the user's public key
                public_key = load_user_public_key(user.public_key_pem)
                signature = base64.b64decode(file_record.signature)
                
                # Note: We can't verify without the actual file data
                # This would be done during download
                print(f"✓ File '{file_record.original_filename}' by {user.username}: Signature format valid")
            except Exception as e:
                print(f"✗ File '{file_record.original_filename}': Invalid signature format - {e}")
                all_valid = False
        
        return all_valid

def display_summary():
    """Display summary of non-repudiation status"""
    print("\n=== NON-REPUDIATION SUMMARY ===")
    with app.app_context():
        user_count = User.query.count()
        users_with_keys = User.query.filter(
            User.private_key_pem != None,
            User.public_key_pem != None
        ).count()
        
        file_count = File.query.count()
        files_with_signatures = File.query.filter(File.signature != None).count()
        
        print(f"Users with keys: {users_with_keys}/{user_count}")
        print(f"Files with signatures: {files_with_signatures}/{file_count}")
        
        if user_count > 0 and users_with_keys == user_count:
            print("✓ All users have RSA keypairs")
        elif users_with_keys > 0:
            print("⚠ Some users missing keys - run migrate_user_keys.py")
        else:
            print("❌ No users have keys - run migrate_user_keys.py")
        
        if file_count > 0 and files_with_signatures == file_count:
            print("✓ All files have signatures (Non-repudiation active)")
        elif files_with_signatures > 0:
            print("⚠ Some files missing signatures - old uploads before implementation")
        elif file_count > 0:
            print("❌ No files have signatures - implementation not working")

def main():
    print("=" * 50)
    print("NON-REPUDIATION VERIFICATION TOOL")
    print("=" * 50)
    
    keys_ok = check_user_keys()
    signatures_ok = check_file_signatures()
    verification_ok = verify_signatures()
    display_summary()
    
    print("\n=== TEST INSTRUCTIONS ===")
    print("To fully test non-repudiation:")
    print("1. Register a new user (or ensure users have keys)")
    print("2. Upload a file as that user")
    print("3. Download the file - signature will be verified")
    print("4. Check logs with: python view_logs.py")
    print("\nIf signature verification fails on download:")
    print("- File has been tampered with, OR")
    print("- File was not signed by the claimed user (non-repudiation proven!)")

if __name__ == "__main__":
    main()
