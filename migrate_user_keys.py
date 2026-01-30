"""
Migration script to generate RSA keypairs for existing users
Run this once after updating the database schema
"""
from config import db, app
from models import User
from utils.crypto_utils import generate_user_keypair

def migrate_existing_users():
    """Generate keypairs for users who don't have them yet"""
    with app.app_context():
        users = User.query.all()
        updated_count = 0
        
        for user in users:
            if not user.private_key_pem or not user.public_key_pem:
                print(f"Generating keys for user: {user.username}")
                private_pem, public_pem = generate_user_keypair()
                user.private_key_pem = private_pem
                user.public_key_pem = public_pem
                updated_count += 1
        
        if updated_count > 0:
            db.session.commit()
            print(f"\n✓ Successfully generated keys for {updated_count} users")
        else:
            print("\n✓ All users already have keys")

if __name__ == "__main__":
    migrate_existing_users()
