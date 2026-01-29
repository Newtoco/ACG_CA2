import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def load_private_key(path):
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def load_public_key(path):
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

# --- HYBRID ENCRYPTION HELPERS ---

def generate_aes_key():
    """Generates a random 32-byte AES key (Fernet compliant)"""
    return Fernet.generate_key()

def encrypt_file_aes(file_data, aes_key):
    """Encrypts file data using AES (Symmetric)"""
    f = Fernet(aes_key)
    return f.encrypt(file_data)

def decrypt_file_aes(encrypted_data, aes_key):
    """Decrypts file data using AES (Symmetric)"""
    f = Fernet(aes_key)
    return f.decrypt(encrypted_data)

def encrypt_aes_key_rsa(aes_key, receiver_public_key):
    """Encrypts the AES key using the Receiver's Public RSA Key (Confidentiality)"""
    return receiver_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_aes_key_rsa(encrypted_aes_key, receiver_private_key):
    """Decrypts the AES key using the Receiver's Private RSA Key"""
    return receiver_private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# --- SIGNATURE HELPERS ---

def sign_data(data, sender_private_key):
    """Signs the data using Sender's Private Key (Non-Repudiation/Integrity)"""
    return sender_private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(data, signature, sender_public_key):
    """Verifies the signature using Sender's Public Key"""
    try:
        sender_public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False