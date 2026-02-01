"""
Anson's code

Private Key Encryption Utilities

Encrypts user private keys with password-derived keys for secure storage.

Security Design:
- Keys encrypted at rest in database
- Password-based key derivation (PBKDF2-HMAC-SHA256)
- Salt per user prevents rainbow table attacks
- High iteration count (600,000) prevents brute force
- AES-256-GCM for authenticated encryption

Attack Resistance:
- Database compromise: Private keys remain encrypted
- Rainbow tables: Unique salt per user defeats precomputation
- Brute force: 600k iterations makes password cracking expensive
- Tampering: GCM authentication tag detects modifications

Workflow:
1. Registration: Derive key from password → Encrypt private key → Store encrypted key + salt
2. Login: Derive key from password → Decrypt private key → Keep in session
3. File Operations: Use decrypted private key from session
"""

import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit encryption key from user password using PBKDF2.
    
    Security Parameters:
    - Algorithm: PBKDF2-HMAC-SHA256
    - Iterations: 600,000 (OWASP 2023 recommendation)
    - Salt: 16 bytes (128 bits) - unique per user
    - Output: 32 bytes (256 bits) for AES-256
    
    Args:
        password: User's plaintext password
        salt: Unique random salt (stored with encrypted key)
    
    Returns:
        32-byte encryption key
    
    Security Note:
        High iteration count makes brute force attacks computationally expensive.
        Even with weak password, attacker needs significant resources.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=salt,
        iterations=600000,  # OWASP 2023 recommendation (was 310,000 in 2022)
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_private_key(private_key_pem: str, password: str) -> tuple[bytes, bytes]:
    """
    Encrypts a private key PEM with password-derived key.
    
    Process:
    1. Generate random 16-byte salt
    2. Derive 256-bit key from password + salt (PBKDF2)
    3. Generate random 12-byte nonce for GCM
    4. Encrypt PEM data with AES-256-GCM
    5. Return (nonce + ciphertext + auth_tag, salt)
    
    Args:
        private_key_pem: PEM-encoded private key (string)
        password: User's password
    
    Returns:
        Tuple of (encrypted_data, salt)
        - encrypted_data: nonce(12) + ciphertext + tag(16)
        - salt: 16-byte salt (must be stored to decrypt later)
    
    Storage Format:
        Both encrypted_data and salt should be base64-encoded for database storage
    
    Security:
        - GCM provides authenticated encryption (confidentiality + integrity)
        - Unique nonce per encryption prevents pattern detection
        - Authentication tag prevents tampering
    """
    # Generate unique salt for this user
    salt = os.urandom(16)
    
    # Derive encryption key from password
    key = derive_key_from_password(password, salt)
    
    # Encrypt private key with AES-256-GCM
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # GCM standard nonce size
    
    # Encrypt PEM data
    pem_bytes = private_key_pem.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, pem_bytes, None)
    
    # Return: (nonce + ciphertext + tag, salt)
    encrypted_data = nonce + ciphertext
    return encrypted_data, salt


def decrypt_private_key(encrypted_data: bytes, salt: bytes, password: str) -> str:
    """
    Decrypts a private key PEM with password.
    
    Process:
    1. Derive same key from password + salt (PBKDF2)
    2. Extract nonce from encrypted data
    3. Decrypt with AES-256-GCM
    4. Verify authentication tag
    5. Return decrypted PEM
    
    Args:
        encrypted_data: nonce(12) + ciphertext + tag(16)
        salt: Same salt used during encryption
        password: User's password
    
    Returns:
        Decrypted PEM-encoded private key (string)
    
    Raises:
        Exception: If password is wrong or data has been tampered with
    
    Security:
        - Wrong password: Key derivation produces wrong key → GCM verification fails
        - Tampered data: GCM authentication tag mismatch → exception raised
        - Constant-time verification prevents timing attacks
    """
    # Derive the same encryption key
    key = derive_key_from_password(password, salt)
    
    # Extract nonce and ciphertext
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    
    # Decrypt and verify authentication tag
    aesgcm = AESGCM(key)
    try:
        pem_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return pem_bytes.decode('utf-8')
    except Exception as e:
        # Wrong password or tampered data
        raise ValueError("Failed to decrypt private key: Wrong password or corrupted data") from e


# Example usage in registration:
"""
from utils.key_encryption import encrypt_private_key
from utils.crypto_utils import generate_user_keypair
import base64

# During registration
password = "user_password_from_form"
private_pem, public_pem = generate_user_keypair()

# Encrypt private key
encrypted_private_key, salt = encrypt_private_key(private_pem, password)

# Store in database (base64 encode for text storage)
user.encrypted_private_key = base64.b64encode(encrypted_private_key).decode('utf-8')
user.private_key_salt = base64.b64encode(salt).decode('utf-8')
user.public_key_pem = public_pem  # Public key stored in plaintext (not sensitive)
"""

# Example usage in login/file operations:
"""
from utils.key_encryption import decrypt_private_key
import base64

# During login (store in session)
encrypted_private_key = base64.b64decode(user.encrypted_private_key)
salt = base64.b64decode(user.private_key_salt)
password = "user_password_from_login_form"

try:
    private_key_pem = decrypt_private_key(encrypted_private_key, salt, password)
    # Store decrypted key in session (server-side session, not in cookies!)
    session['private_key_pem'] = private_key_pem
except ValueError:
    # Wrong password
    return "Invalid password"

# During file upload/signing
from utils.crypto_utils import load_user_private_key
private_key_pem = session.get('private_key_pem')
if not private_key_pem:
    return "Please login again"
    
private_key = load_user_private_key(private_key_pem)
# Use private_key for signing...
"""
