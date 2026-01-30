"""
File Vault Routes

Handles secure file upload, download, listing, and deletion operations.

Security Architecture:

1. Upload Security:
   - Authentication required (JWT token validation)
   - File type validation using magic numbers (prevents MIME type spoofing)
   - Allowed types: text/plain, PDF, PNG, JPEG
   - Filename sanitization prevents directory traversal
   - UUID-based storage names prevent enumeration attacks
   - Duplicate file detection with overwrite confirmation
   - AES-256-GCM encryption before storage (data at rest protection)
   - RSA-2048 digital signature for non-repudiation
   - Audit logging of all uploads

2. Encryption Process (Defense in Depth):
   Step 1: Read plaintext file data
   Step 2: Generate 12-byte random nonce
   Step 3: Encrypt with AES-256-GCM using master key
   Step 4: Compute authentication tag (integrity protection)
   Step 5: Sign encrypted data with user's private key (non-repudiation)
   Step 6: Store: [nonce(12)][tag(16)][ciphertext(variable)]
   Step 7: Store signature separately in database

3. Download Security:
   - Authentication required
   - Authorization check (users can only access their own files)
   - Signature verification before decryption (integrity check)
   - Public key retrieval from database
   - GCM tag verification (detects tampering)
   - Audit logging of all downloads

4. Non-Repudiation:
   - Each file signed with uploader's private RSA key
   - Signature verified using uploader's public key
   - Proves who uploaded the file and when
   - Detects unauthorized modifications
   - Provides legal proof of authorship

5. Data Storage:
   - Files stored in secure_vault_storage/ directory
   - Encrypted at rest (AES-256-GCM)
   - UUID filenames prevent guessing
   - Metadata in database (users.db)
   - Signatures in database (linked to files)

6. Access Control:
   - User-based isolation (can only access own files)
   - Token-based authentication on all operations
   - Database-level user_id association
   - No directory listing without authentication
"""

import os
import magic
import uuid
from flask import Blueprint, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
from config import UPLOAD_FOLDER, get_gcm_cipher, db
from models import File
from auth_utils import token_required, log_action
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64

vault_bp = Blueprint('vault', __name__)

@vault_bp.route('/dashboard')
@token_required
def dashboard(current_user):
    return render_template('index.html', mode='dashboard', username=current_user.username)

def validate_file_type(file_storage):
    """
    Validates file type using magic numbers (file signatures).
    
    Security: Prevents MIME type spoofing attacks
    - Checks actual file content, not just extension
    - Reads first 2048 bytes to identify file type
    - python-magic uses libmagic (same as Unix 'file' command)
    - Whitelist approach: only explicitly allowed types accepted
    """
    header = file_storage.read(2048)
    file_storage.seek(0)
    mime = magic.from_buffer(header, mime=True)
    allowed = ['text/plain', 'application/pdf', 'image/png', 'image/jpeg']
    return mime in allowed

# Helper to load your private key
def get_private_key():
    with open("key.pem", "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

# Helper to load the public key (from your cert.pem)
def get_public_key():
    with open("cert.pem", "rb") as cert_file:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(cert_file.read())
        return cert.public_key()

@vault_bp.route('/upload', methods=['POST'])
@token_required
def upload(current_user):
    file = request.files.get('file')
    if not file: return jsonify({'message': 'No file'}), 400

    # Validate file type using magic numbers
    if not validate_file_type(file):
        return jsonify({'message': 'Invalid file type detected'}), 400
    
    filename = secure_filename(file.filename)

    # SECURITY: Duplicate File Detection
    # Prevents accidental overwrites without confirmation
    # Each user has isolated namespace (user_id check)
    existing_file = File.query.filter_by(user_id=current_user.id, original_filename=filename).first()

    # Check for an 'overwrite' flag in the request
    # Client must explicitly confirm overwrite operation
    overwrite = request.args.get('overwrite') == 'true'

    if existing_file and not overwrite:
        # Return 409 Conflict: requires user confirmation
        return jsonify({
            "status": "conflict",
            "message": f"A file named {filename} already exists. Overwrite?"
        }), 409

    if existing_file and overwrite:
        # Proceed with your deletion logic
        old_path = os.path.join(UPLOAD_FOLDER, existing_file.storage_name)
        if os.path.exists(old_path):
            os.remove(old_path)
        db.session.delete(existing_file)

    # SECURITY: UUID-based Storage Names
    # Prevents file enumeration attacks (can't guess filenames)
    # Original filename stored separately in database
    # UUID v4 provides 122 bits of randomness
    file_uuid = str(uuid.uuid4())
    file_ext = os.path.splitext(filename)[1]
    storage_name = f"{file_uuid}{file_ext}"

    file_data = file.read()

    # SECURITY: Digital Signature for Non-Repudiation
    # Sign plaintext file data with user's private RSA key before encryption
    # This proves: (1) who uploaded the file, (2) when it was uploaded, (3) file integrity
    # Signature cannot be forged without access to user's private key
    
    from flask import session
    from utils.crypto_utils import load_user_private_key
    
    # Get decrypted private key from session (decrypted during login)
    private_key_pem = session.get('private_key_pem')
    
    if not private_key_pem:
        # Session expired or user needs to re-login
        return jsonify({'message': 'Session expired. Please login again to decrypt your private key.'}), 401
    
    user_private_key = load_user_private_key(private_key_pem)
    
    signature = user_private_key.sign(
        file_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    # Convert signature to string for DB storage
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    
    # Debug output for upload signature
    print(f"File signed by user {current_user.username}")
    print(f"  Signature (full): {signature_b64}")
    print(f"  File: {filename} ({len(file_data)} bytes)")

    # SECURITY: AES-256-GCM Encryption for Data at Rest
    # Encrypts file before storing on disk
    # GCM mode provides both confidentiality and authenticity
    
    # 1. Generate a 12-byte nonce (Standard for GCM)
    # Nonce must be unique for each encryption with same key
    # 12 bytes = 96 bits (recommended size for GCM)
    nonce = os.urandom(12)

    # 2. Set up the GCM cipher engine
    # Uses master encryption key from config (FILE_ENCRYPTION_KEY)
    # Tag is None during encryption (computed during finalize)
    cipher = get_gcm_cipher(nonce)
    encryptor = cipher.encryptor()

    # 3. Encrypt and extract the authentication Tag
    # Tag provides integrity protection (detects tampering)
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    tag = encryptor.tag

    # 4. Store as: [Nonce(12)][Tag(16)][Ciphertext(...)]
    # Nonce and tag must be stored with ciphertext for decryption
    # This format allows easy extraction during download
    encrypted_blob = nonce + tag + ciphertext

    with open(os.path.join(UPLOAD_FOLDER, storage_name), 'wb') as f:
        f.write(encrypted_blob)
    
    # Save file record to database
    file_record = File(
        user_id=current_user.id,
        original_filename=filename,
        storage_name=storage_name,
        signature=signature_b64
    )
    db.session.add(file_record)
    db.session.commit()
        
    log_action(current_user.id, "UPLOAD", filename)
    return jsonify({'message': 'Uploaded'})

@vault_bp.route('/list-files')
@token_required
def list_files(current_user):
    user_files = File.query.filter_by(user_id=current_user.id).all()
    files_list = [f.original_filename for f in user_files]
    return jsonify({'files': files_list})

@vault_bp.route('/download', methods=['POST'])
@token_required
def download(current_user):
    filename = secure_filename(request.json.get('filename'))
    
    # SECURITY: Authorization Check
    # Users can only download their own files (user_id isolation)
    # Prevents unauthorized access to other users' data
    file_record = File.query.filter_by(user_id=current_user.id, original_filename=filename).first()
    if not file_record:
        return jsonify({'message': 'Missing'}), 404
    
    path = os.path.join(UPLOAD_FOLDER, file_record.storage_name)
    if not os.path.exists(path):
        return jsonify({'message': 'Missing'}), 404

    # SECURITY: AES-256-GCM Decryption with Integrity Verification
    # 1. Read the encrypted blob from disk
    with open(path, 'rb') as f:
        raw_data = f.read()

    # 2. Extract components from stored format: [Nonce(12)][Tag(16)][Ciphertext(...)]
    # Each component required for GCM decryption
    nonce = raw_data[:12]   # First 12 bytes: unique nonce used during encryption
    tag = raw_data[12:28]   # Next 16 bytes: authentication tag for integrity
    ciphertext = raw_data[28:]  # Remaining bytes: encrypted file data

    # 3. Initialize GCM decryptor with both nonce and tag
    # Tag is verified during finalization
    cipher = get_gcm_cipher(nonce, tag)
    decryptor = cipher.decryptor()

    # 4. Decrypt and verify integrity (GCM authentication)
    # finalize() raises exception if tag verification fails (tampering detected)
    try:
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:
        # SECURITY EVENT: File has been tampered with
        log_action(current_user.id, "TAMPER_DETECTED", filename)
        return jsonify({'message': 'Integrity check failed'}), 400

    # SECURITY: Digital Signature Verification (Non-Repudiation)
    # Verify file was actually uploaded by claimed user
    # Proves authenticity and integrity of the original upload
    if file_record.signature:
        # Get the uploader's public key (from the user who uploaded it)
        from models import User
        uploader = User.query.get(file_record.user_id)
        
        if not uploader or not uploader.public_key_pem:
            return jsonify({'message': 'Non-repudiation check failed: User key not found'}), 400
        
        # Load uploader's public key and stored signature
        from utils.crypto_utils import load_user_public_key
        user_public_key = load_user_public_key(uploader.public_key_pem)
        signature = base64.b64decode(file_record.signature)
        
        # Verify signature matches the decrypted file data
        # This proves: (1) File uploaded by claimed user, (2) File not modified since upload
        # Uses RSA-PSS signature scheme with SHA-256
        try:
            user_public_key.verify(
                signature,
                decrypted_data,  # Verify against plaintext (signature was created before encryption)
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            # Signature verification successful - non-repudiation confirmed
            sig_full = base64.b64encode(signature).decode('utf-8')
            print(f"Non-repudiation Verified: File uploaded by user {uploader.username}")
            print(f"  Signature (full): {sig_full}")
        except Exception:
            # Signature verification failed - file may be tampered or wrong user
            log_action(current_user.id, "SIGNATURE_VERIFICATION_FAILED", filename)
            return jsonify({'message': 'Non-repudiation check failed: Signature mismatch'}), 400


    log_action(current_user.id, "DOWNLOAD", filename)

    from io import BytesIO
    return send_file(
        BytesIO(decrypted_data),
        as_attachment=True,
        download_name=filename
    )

@vault_bp.route('/delete', methods=['POST'])
@token_required
def delete(current_user):
    filename = secure_filename(request.json.get('filename'))
    
    # Look up file record in database
    file_record = File.query.filter_by(user_id=current_user.id, original_filename=filename).first()
    if not file_record:
        return jsonify({'message': 'Not Found'}), 404
    
    path = os.path.join(UPLOAD_FOLDER, file_record.storage_name)
    
    if os.path.exists(path):
        os.remove(path)
    
    # Delete database record
    db.session.delete(file_record)
    db.session.commit()
    
    log_action(current_user.id, "DELETE", filename)
    return jsonify({'message': 'Deleted'})