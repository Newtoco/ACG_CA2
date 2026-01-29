import os
import magic
import uuid
from flask import Blueprint, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
from config import UPLOAD_FOLDER, get_gcm_cipher, db
from models import File
from utils import token_required, log_action

vault_bp = Blueprint('vault', __name__)

@vault_bp.route('/dashboard')
@token_required
def dashboard(current_user):
    return render_template('index.html', mode='dashboard', username=current_user.username)

def validate_file_type(file_storage):
    header = file_storage.read(2048)
    file_storage.seek(0) # Reset file pointer after reading
    mime = magic.from_buffer(header, mime=True)
    allowed = ['text/plain', 'application/pdf', 'image/png', 'image/jpeg']
    return mime in allowed

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
    if existing_file:
        # Remove the old physical file from storage
        old_path = os.path.join(UPLOAD_FOLDER, existing_file.storage_name)
        if os.path.exists(old_path):
            os.remove(old_path)

        # Delete the old database record
        db.session.delete(existing_file)
        db.session.commit()

    # Generate UUID-based storage name
    file_uuid = str(uuid.uuid4())
    file_ext = os.path.splitext(filename)[1]
    storage_name = f"{file_uuid}{file_ext}"
    
    # Encrypt using AES-256-GCM (provides encryption + authentication)
    # Generate a 12-byte nonce (GCM standard)
    nonce = os.urandom(12)

    # Get GCM cipher
    cipher = get_gcm_cipher()

    # Read and encrypt file data
    file_data = file.read()
    
    # GCM encrypt returns ciphertext with 16-byte authentication tag appended
    ciphertext = cipher.encrypt(nonce, file_data, None)
    
    # Store: nonce + ciphertext (which includes auth tag)
    encrypted_data = nonce + ciphertext

    with open(os.path.join(UPLOAD_FOLDER, storage_name), 'wb') as f:
        f.write(encrypted_data)
    
    # Save file record to database
    file_record = File(
        user_id=current_user.id,
        original_filename=filename,
        storage_name=storage_name
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
    # Read the raw data from the storage
    with open(path, 'rb') as f:
        raw_data = f.read()

    # Extract the 12-byte nonce (GCM uses 12-byte nonces)
    nonce = raw_data[:12]
    ciphertext = raw_data[12:]  # Includes 16-byte auth tag at the end

    # Get GCM cipher
    cipher = get_gcm_cipher()

    # Decrypt and verify authentication tag
    # This will raise an exception if the file has been tampered with
    try:
        decrypted_data = cipher.decrypt(nonce, ciphertext, None)
    except Exception as e:
        log_action(current_user.id, "DOWNLOAD_FAILED", filename, 
                  details=f"Authentication verification failed - file may be corrupted or tampered")
        return jsonify({'message': 'File integrity check failed - possible tampering detected'}), 403

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