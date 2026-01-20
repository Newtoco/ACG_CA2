import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_key_pair(filename_prefix):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Save private key
    with open(f"{filename_prefix}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    public_key = private_key.public_key()
    with open(f"{filename_prefix}_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"Generated: {filename_prefix}")

if __name__ == "__main__":
    # Get the project root directory (one level up from 'utils')
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    keys_dir = os.path.join(project_root, "keys")

    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)
    
    print(f"Saving keys to: {keys_dir}")

    # Generate Server Keys
    generate_key_pair(os.path.join(keys_dir, "server"))
    
    # Generate Client Keys
    generate_key_pair(os.path.join(keys_dir, "client"))
    
    print("✅ PKI Setup Complete.")