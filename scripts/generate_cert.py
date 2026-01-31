"""
Certificate and Key Generation Script

Generates cryptographic materials required for the Secure File Vault:
1. SSL/TLS Certificate (RSA-4096) for HTTPS
2. Master File Encryption Key (AES-256)

Security Considerations:
- RSA-4096 provides ~128-bit equivalent security strength
- Self-signed certificate (acceptable for development/internal use)
- AES-256 key uses cryptographically secure random number generator
- All keys stored in certs/ directory (excluded from git)
- Files should have restricted permissions (chmod 600 on Unix)

Critical Warning:
- KEEP THESE FILES SECURE - losing the AES key means data loss
- NEVER commit these files to version control
- Backup the AES key securely (encrypted backup recommended)
- In production, use certificates from trusted CA (e.g., Let's Encrypt)
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime
import os


def generate_everything():
    print("Generating secure certificates and master keys...")
    
    # Create certs directory if it doesn't exist
    # This directory is git-ignored for security
    os.makedirs("certs", exist_ok=True)

    # Generate Private Key (RSA-4096)
    # 4096-bit RSA provides strong security for TLS/SSL
    # Public exponent 65537 is standard (Fermat number F4)
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Configure the Certificate (Self-Signed)
    # Self-signed cert acceptable for development/internal use
    # For production, obtain certificate from trusted CA (Let's Encrypt, DigiCert, etc.)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"SG"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"SINGAPORE"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"DOVER"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SINGAPORE_POLYTECHNIC"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"GROUP_1_ACG_CA2_SECURE_VAULT_WEBSERVE"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.UTC)
    ).not_valid_after(
        datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())

    # Save Private Key to file
    # WARNING: Key stored without encryption (password=None)
    # For production, encrypt with strong passphrase
    # Use TraditionalOpenSSL format for compatibility
    with open(os.path.join("certs", "key.pem"), "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save Certificate to file
    with open(os.path.join("certs", "cert.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("SSL/TLS Private Key: certs/key.pem")
    print("SSL/TLS Certificate: certs/cert.pem")

    # Generate Master File Encryption Key (AES-256)
    # CRITICAL: This key encrypts ALL files in the vault
    # Losing this key = permanent data loss
    # os.urandom(32) uses system entropy pool (cryptographically secure)
    # 32 bytes = 256 bits for AES-256
    file_key = os.urandom(32)
    with open(os.path.join("certs", "file_key.key"), "wb") as f:
        f.write(file_key)

    print("File Encryption Key: certs/file_key.key")
    print("\n[!] KEEP THESE FILES SECURE AND DO NOT COMMIT TO GIT!")
    print("[!] Set appropriate file permissions: chmod 600 certs/*")

if __name__ == "__main__":
    generate_everything()
