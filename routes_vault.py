import os
from flask import Blueprint, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
from config import UPLOAD_FOLDER, get_ctr_cipher, db
from utils import token_required, log_action

vault_bp = Blueprint('vault', __name__)

@vault_bp.route('/dashboard')
@token_required
def dashboard(current_user):
    return render_template('index.html', mode='dashboard', username=current_user.username)

@vault_bp.route('/upload', methods=['POST'])
@token_required
def upload(current_user):
    file = request.files.get('file')
    if not file: return jsonify({'message': 'No file'}), 400
    
    filename = secure_filename(file.filename)
    storage_name = f"{current_user.id}_{filename}"
    
    # Encrypt
    encrypted_data = cipher_suite.encrypt(file.read())
    with open(os.path.join(UPLOAD_FOLDER, storage_name), 'wb') as f:
        f.write(encrypted_data)
        
    log_action(
        user_id=current_user.id,
        action="UPLOAD",
        filename=filename,
        username_entered=current_user.username,
        success=True,
        details="File uploaded successfully"
    )

    return jsonify({'message': 'Uploaded'})

@vault_bp.route('/list-files')
@token_required
def list_files(current_user):
    all_files = os.listdir(UPLOAD_FOLDER)
    user_files = [f.split('_', 1)[1] for f in all_files if f.startswith(f"{current_user.id}_")]
    return jsonify({'files': user_files})

@vault_bp.route('/download', methods=['POST'])
@token_required
def download(current_user):
    filename = secure_filename(request.json.get('filename'))
    storage_name = f"{current_user.id}_{filename}"
    path = os.path.join(UPLOAD_FOLDER, storage_name)
    
    if not os.path.exists(path): return jsonify({'message': 'Missing'}), 404
    
    # Decrypt
    with open(path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    log_action(
        user_id=current_user.id,
        action="DOWNLOAD",
        filename=filename,
        username_entered=current_user.username,
        success=True,
        details="File downloaded successfully"
    )

        
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
    path = os.path.join(UPLOAD_FOLDER, f"{current_user.id}_{filename}")
    
    if os.path.exists(path):
        os.remove(path)
        log_action(
            user_id=current_user.id,
            action="DELETE",
            filename=filename,
            username_entered=current_user.username,
            success=True,
            details="File deleted successfully"
        )
        return jsonify({'message': 'Deleted'})
    return jsonify({'message': 'Not Found'}), 404