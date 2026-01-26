from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime
import os  # Added for key generation


def generate_everything():
    print("Generating secure certificates and master keys...")

    # --- 1. Generate Private Key (RSA-4096) ---
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # --- 2. Configure the Certificate (Self-Signed) ---
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
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())

    # --- 3. Write 'key.pem' and 'cert.pem' to disk (Transit Security) ---
    with open("key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open("cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # --- 4. NEW: Generate AES-256 Master Key (At-Rest Security) ---
    # This generates exactly 32 raw bytes to fix your ValueError
    with open("file_key.key", "wb") as f:
        f.write(os.urandom(32))

    print("Success! Created 'cert.pem', 'key.pem', and 'file_key.key'.")


if __name__ == "__main__":
    generate_everything()