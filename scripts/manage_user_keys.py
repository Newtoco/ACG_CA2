"""
Anson's Code

User Key Migration Script

Comprehensive key management for existing users:
1. Generate keys for users without them (backward compatibility)
2. Migrate plaintext keys to encrypted storage (security upgrade)
3. Verify migration status

Strategies:
- 'generate': Generate plaintext keys for users missing them (legacy support)
- 'encrypt': Migrate plaintext keys to encrypted storage with temporary password
- 'regenerate': Generate new encrypted keypairs (BREAKS old signatures)
- 'verify': Check migration status

Security Note:
Encrypted keys provide database breach protection but require password to use.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import app, db
from models import User
from utils.key_encryption import encrypt_private_key
from utils.crypto_utils import generate_user_keypair
import base64


def generate_plaintext_keys():
    """
    Generate plaintext RSA keypairs for users without them.
    Legacy function for backward compatibility.
    """
    with app.app_context():
        print("=" * 60)
        print("GENERATING PLAINTEXT KEYS (LEGACY)")
        print("=" * 60)
        
        users = User.query.all()
        updated_count = 0
        
        for user in users:
            if not user.private_key_pem or not user.public_key_pem:
                print(f"Generating plaintext keys for user: {user.username}")
                private_pem, public_pem = generate_user_keypair()
                user.private_key_pem = private_pem
                user.public_key_pem = public_pem
                updated_count += 1
        
        if updated_count > 0:
            db.session.commit()
            print(f"\n✓ Generated keys for {updated_count} user(s)")
            print("\nWARNING: Keys stored in plaintext (not secure)")
            print("Consider running with --strategy encrypt for security")
        else:
            print("\n✓ All users already have keys")


def migrate_to_encrypted_keys(strategy='regenerate'):
    """
    Migrates database to use encrypted private keys.
    
    Strategies:
    - 'regenerate': Generate new keypairs (BREAKS old signatures)
    - 'temp_password': Use temporary password (INSECURE, dev only)
    
    Args:
        strategy: Migration strategy ('regenerate' or 'temp_password')
    """
    with app.app_context():
        # First, add columns if they don't exist (do this manually in production)
        # ALTER TABLE user ADD COLUMN encrypted_private_key TEXT;
        # ALTER TABLE user ADD COLUMN private_key_salt TEXT;
        
        print("=" * 60)
        print("MIGRATING TO ENCRYPTED PRIVATE KEYS")
        print("=" * 60)
        print(f"\nStrategy: {strategy}")
        
        users = User.query.all()
        print(f"\nFound {len(users)} users to migrate")
        
        if strategy == 'regenerate':
            print("\nWARNING: This will REGENERATE all keypairs!")
            print("All existing file signatures will become UNVERIFIABLE!")
            response = input("Continue? (yes/no): ")
            if response.lower() != 'yes':
                print("Migration cancelled")
                return
            
            for user in users:
                print(f"\nMigrating user: {user.username}")
                
                # Generate new keypair
                private_pem, public_pem = generate_user_keypair()
                
                # Use username as temporary password (user must change it!)
                temp_password = f"{user.username}_CHANGEME"
                
                # Encrypt private key
                encrypted_key, salt = encrypt_private_key(private_pem, temp_password)
                
                # Store encrypted key and salt
                user.encrypted_private_key = base64.b64encode(encrypted_key).decode('utf-8')
                user.private_key_salt = base64.b64encode(salt).decode('utf-8')
                user.public_key_pem = public_pem
                
                # Clear old plaintext key
                user.private_key_pem = None
                
                print(f"  ✓ New keypair generated and encrypted")
                print(f"  ! Temporary password: {temp_password}")
                print(f"  ! User MUST change password on next login!")
        
        elif strategy == 'encrypt':
            print("\nWARNING: Using temporary password to encrypt existing keys (INSECURE!)")
            print("This is for DEVELOPMENT/TESTING only!")
            print("All users will have same temporary password until they change it!")
            response = input("Continue? (yes/no): ")
            if response.lower() != 'yes':
                print("Migration cancelled")
                return
            
            temp_password = "TEMPORARY_MIGRATION_PASSWORD_CHANGE_ME"
            
            for user in users:
                print(f"\nMigrating user: {user.username}")
                
                if not user.private_key_pem:
                    print("  ! No private key found, generating new one")
                    private_pem, public_pem = generate_user_keypair()
                    user.public_key_pem = public_pem
                else:
                    private_pem = user.private_key_pem
                
                # Encrypt existing private key
                encrypted_key, salt = encrypt_private_key(private_pem, temp_password)
                
                # Store encrypted key and salt
                user.encrypted_private_key = base64.b64encode(encrypted_key).decode('utf-8')
                user.private_key_salt = base64.b64encode(salt).decode('utf-8')
                
                # Clear old plaintext key
                user.private_key_pem = None
                
                print(f"  ✓ Private key encrypted with temporary password")
            
            print(f"\n{'='*60}")
            print(f"Temporary password: {temp_password}")
            print(f"{'='*60}")
            print("\nALL USERS MUST CHANGE PASSWORD to re-encrypt with real password!")
        
        else:
            print(f"Unknown strategy: {strategy}")
            return
        
        # Commit all changes
        db.session.commit()
        print("\n✓ Migration complete!")
        print("\nNext steps:")
        print("1. Users must log in with temporary passwords")
        print("2. Force password change on first login")
        print("3. Remove private_key_pem column from database")


def verify_migration():
    """Verify that all users have encrypted keys."""
    with app.app_context():
        users = User.query.all()
        print(f"\nVerifying {len(users)} users...")
        
        all_good = True
        for user in users:
            has_encrypted = user.encrypted_private_key and user.private_key_salt
            has_old = user.private_key_pem
            status = "✓" if has_encrypted and not has_old else "✗"
            
            print(f"{status} {user.username}:")
            print(f"    Encrypted key: {'Yes' if has_encrypted else 'No'}")
            print(f"    Old plaintext key: {'Yes (should remove!)' if has_old else 'No'}")
            
            if not has_encrypted or has_old:
                all_good = False
        
        if all_good:
            print("\n✓ All users migrated successfully!")
        else:
            print("\n✗ Migration incomplete - some users still need migration")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='User key migration and management')
    parser.add_argument('--strategy', 
                       choices=['generate', 'encrypt', 'regenerate'],
                       default='regenerate',
                       help='Migration strategy: generate (plaintext), encrypt (upgrade to encrypted), regenerate (new encrypted keys)')
    parser.add_argument('--verify', action='store_true',
                       help='Verify migration status')
    
    args = parser.parse_args()
    
    if args.verify:
        verify_migration()
    elif args.strategy == 'generate':
        generate_plaintext_keys()
    else:
        migrate_to_encrypted_keys(args.strategy)
