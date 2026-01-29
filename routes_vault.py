import os
import magic
import uuid
from flask import Blueprint, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
from config import UPLOAD_FOLDER, get_ctr_cipher, db
from models import File
from utils import token_required, log_action

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

@vault_bp.route('/upload', methods=['POST'])
@token_required
def upload(current_user):
    file = request.files.get('file')
    if not file: return jsonify({'message': 'No file'}), 400

    # File extension security check
    if not validate_file_type(file):
        return jsonify({'message': 'Invalid file type detected'}), 400
    
    filename = secure_filename(file.filename)

    # --- NEW CHECK: PREVENT DUPLICATES ---
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
    
    # Encrypt
    # 1. Generate a 16-byte nonce (CTR typically uses 16 bytes)
    nonce = os.urandom(16)

    # 2. Set up the CTR engine
    cipher = get_ctr_cipher(nonce)
    encryptor = cipher.encryptor()

    # 3. Encrypt and store (Nonce + Ciphertext)
    file_data = file.read()
    encrypted_data = nonce + encryptor.update(file_data) + encryptor.finalize()

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
    # 1. Read the raw data from the storage
    with open(path, 'rb') as f:
        raw_data = f.read()

    # 1. Extract the 16-byte nonce
    nonce = raw_data[:16]
    ciphertext = raw_data[16:]

    # 2. Set up the CTR engine
    cipher = get_ctr_cipher(nonce)
    decryptor = cipher.decryptor()

    # 3. Decrypt
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

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