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

    # File extension security check
    if not validate_file_type(file):
        return jsonify({'message': 'Invalid file type detected'}), 400
    
    filename = secure_filename(file.filename)

    # --- PREVENT DUPLICATES ---
    existing_file = File.query.filter_by(user_id=current_user.id, original_filename=filename).first()

    # Check for an 'overwrite' flag in the request (e.g., from a query param or JSON body)
    overwrite = request.args.get('overwrite') == 'true'

    if existing_file and not overwrite:
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

    # Generate UUID-based storage name
    file_uuid = str(uuid.uuid4())
    file_ext = os.path.splitext(filename)[1]
    storage_name = f"{file_uuid}{file_ext}"

    file_data = file.read()

    # --- NON-REPUDIATION: SIGNING WITH USER'S PRIVATE KEY ---
    # Use user's private key instead of server key for true non-repudiation
    if not current_user.private_key_pem:
        # Generate keys for user if they don't exist (backward compatibility)
        from utils.crypto_utils import generate_user_keypair
        private_pem, public_pem = generate_user_keypair()
        current_user.private_key_pem = private_pem
        current_user.public_key_pem = public_pem
        db.session.commit()
    
    from utils.crypto_utils import load_user_private_key
    user_private_key = load_user_private_key(current_user.private_key_pem)
    
    signature = user_private_key.sign(
        file_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    # Convert signature to string for DB storage
    signature_b64 = base64.b64encode(signature).decode('utf-8')

    # Encrypt
    # 1. Generate a 12-byte nonce (Standard for GCM)
    nonce = os.urandom(12)

    # 2. Set up the GCM engine (from your updated config)
    # Note: tag is None during encryption
    cipher = get_gcm_cipher(nonce)
    encryptor = cipher.encryptor()

    # 3. Encrypt and extract the Tag
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    tag = encryptor.tag

    # 4. Store as: [Nonce(12)][Tag(16)][Ciphertext(...)]
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
    
    # Look up file record in database
    file_record = File.query.filter_by(user_id=current_user.id, original_filename=filename).first()
    if not file_record:
        return jsonify({'message': 'Missing'}), 404
    
    path = os.path.join(UPLOAD_FOLDER, file_record.storage_name)
    if not os.path.exists(path):
        return jsonify({'message': 'Missing'}), 404

    # Decrypt
    # 1. Read the raw data
    with open(path, 'rb') as f:
        raw_data = f.read()

    # 2. Extract components based on the GCM structure
    # Nonce = 12 bytes, Tag = 16 bytes, Ciphertext = the rest
    nonce = raw_data[:12]
    tag = raw_data[12:28]
    ciphertext = raw_data[28:]

    # 3. Set up the GCM engine (Pass both nonce AND tag)
    cipher = get_gcm_cipher(nonce, tag)
    decryptor = cipher.decryptor()

    # 4. Decrypt and Verify Integrity (GCM Tag)
    try:
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:
        log_action(current_user.id, "TAMPER_DETECTED", filename)
        return jsonify({'message': 'Integrity check failed'}), 400

    # --- NON-REPUDIATION: VERIFY SIGNATURE WITH USER'S PUBLIC KEY ---
    if file_record.signature:
        # Get the uploader's public key (from the user who uploaded it)
        from models import User
        uploader = User.query.get(file_record.user_id)
        
        if not uploader or not uploader.public_key_pem:
            return jsonify({'message': 'Non-repudiation check failed: User key not found'}), 400
        
        from utils.crypto_utils import load_user_public_key
        user_public_key = load_user_public_key(uploader.public_key_pem)
        signature = base64.b64decode(file_record.signature)
        
        try:
            user_public_key.verify(
                signature,
                decrypted_data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print(f"Non-repudiation Verified: File uploaded by user {uploader.username}")
        except Exception:
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