"""
Contributors: Anson, Denzel
Anson, Denzel: AES-256-GCM encryption, RSA-PSS digital signatures, and automated key management
Cryptographic Utilities

Provides cryptographic operations for the secure file vault.

Security Implementation:

1. File Encryption (Hybrid Cryptography):
   - AES-256-GCM for file encryption (authenticated encryption with AEAD)
   - GCM provides both confidentiality and integrity protection
   - Random nonces prevent deterministic encryption
   - Authentication tags detect tampering

2. Digital Signatures (Non-Repudiation):
   - RSA-PSS signature scheme with SHA-256
   - Each user has unique RSA-2048 keypair
   - Private key signs uploaded files
   - Public key verifies signatures on download
   - Provides proof of authorship and integrity

3. Key Management:
   - User keypairs generated at registration
   - Private keys stored in database (encrypted in production)
   - Public keys used for signature verification
   - Server keypairs (RSA-4096) for TLS/SSL

Cryptographic Standards:
- AES-256: NIST FIPS 197 approved
- RSA-2048/4096: NIST FIPS 186-4 approved
- SHA-256: NIST FIPS 180-4 approved
- GCM mode: NIST SP 800-38D
- PSS padding: PKCS#1 v2.1
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def load_private_key(path):
    """Load RSA private key from PEM file"""
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def load_public_key(path):
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

# Hybrid Encryption Helpers

def generate_aes_key():
    """
    Generates a cryptographically secure random 32-byte AES-256 key.
    Uses os.urandom() which sources from system entropy pool.
    """
    return os.urandom(32)

def encrypt_file_aes(file_data, aes_key):
    """
    Encrypts file data using AES-256-GCM (authenticated encryption with associated data).
    
    Security:
    - AES-256: 256-bit key provides ~2^256 security strength
    - GCM mode: Provides both confidentiality and authenticity
    - Random 12-byte nonce: Prevents nonce reuse attacks
    - Authentication tag: Included in ciphertext, verifies integrity
    
    Returns: nonce (12 bytes) + ciphertext + auth_tag (concatenated)
    """
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # GCM standard nonce size
    ciphertext = aesgcm.encrypt(nonce, file_data, None)
    return nonce + ciphertext  # Return nonce + ciphertext (includes auth tag)

def decrypt_file_aes(encrypted_data, aes_key):
    """
    Decrypts file data using AES-256-GCM and verifies authentication tag.
    
    Security:
    - Verifies authentication tag before returning plaintext
    - Raises exception if data has been tampered with
    - Constant-time tag comparison prevents timing attacks
    """
    aesgcm = AESGCM(aes_key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)  # Raises exception if tampered

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

# Signature Helpers

def sign_data(data, sender_private_key):
    """
    Creates a digital signature using RSA-PSS with SHA-256.
    
    Security (Non-Repudiation):
    - Only the private key holder can create valid signatures
    - Provides proof of authorship and data integrity
    - PSS padding: Probabilistic signature scheme (more secure than PKCS#1 v1.5)
    - MAX_LENGTH salt: Maximum security against forgery attempts
    - SHA-256 hash: Collision-resistant hash function
    
    Returns: Digital signature (bytes)
    """
    return sender_private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(data, signature, sender_public_key):
    """
    Verifies a digital signature using RSA-PSS with SHA-256.
    
    Security:
    - Verifies both data integrity and authenticity
    - Anyone with public key can verify, but only private key holder can sign
    - Raises exception if signature is invalid or data has been modified
    - Constant-time comparison prevents timing attacks
    
    Returns: True if valid, False if invalid (catches exceptions)
    """
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

# User Key Generation for Non-Repudiation

def generate_user_keypair():
    """Generates a new RSA keypair for a user (2048-bit)"""
    from cryptography.hazmat.primitives.asymmetric import rsa
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Serialize to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Store unencrypted (or encrypt with user password)
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem

def load_user_private_key(pem_string):
    """Load a user's private key from PEM string"""
    return serialization.load_pem_private_key(
        pem_string.encode('utf-8'),
        password=None
    )

def load_user_public_key(pem_string):
    """Load a user's public key from PEM string"""
    return serialization.load_pem_public_key(pem_string.encode('utf-8'))
