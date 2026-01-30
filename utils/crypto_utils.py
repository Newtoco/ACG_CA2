import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
    """Generates a random 32-byte AES-256 key"""
    return os.urandom(32)

def encrypt_file_aes(file_data, aes_key):
    """Encrypts file data using AES-256-GCM (authenticated encryption)"""
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # GCM standard nonce size
    ciphertext = aesgcm.encrypt(nonce, file_data, None)
    return nonce + ciphertext  # Return nonce + ciphertext (includes auth tag)

def decrypt_file_aes(encrypted_data, aes_key):
    """Decrypts file data using AES-256-GCM (verifies authentication)"""
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

# --- USER KEY GENERATION FOR NON-REPUDIATION ---

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
