import os
import magic  # Requires 'python-magic-bin' (Windows) or 'python-magic' (Linux/Mac)
from io import BytesIO
from flask import Blueprint, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
from config import UPLOAD_FOLDER, cipher_suite
from utils import token_required, log_action

vault_bp = Blueprint('vault', __name__)


# --- SECURITY HELPER: VALIDATE FILE TYPES ---
def validate_file_type(file_storage):
    """
    Reads the file header (Magic Bytes) to verify the actual file type,
    ignoring the file extension provided by the user.
    """
    # 1. Read the first 2KB to identify the file signature
    header = file_storage.read(2048)

    # 2. CRITICAL: Reset the cursor to the start so the file can be saved later
    file_storage.seek(0)

    # 3. Identify MIME type from the header bytes
    mime = magic.from_buffer(header, mime=True)

    # 4. Whitelist allowed types (Adjust this list as needed)
    allowed_mimes = [
        'text/plain',
        'application/pdf',
        'image/png',
        'image/jpeg'
    ]

    return mime in allowed_mimes


@vault_bp.route('/dashboard')
@token_required
def dashboard(current_user):
    return render_template('index.html', mode='dashboard', username=current_user.username)


@vault_bp.route('/upload', methods=['POST'])
@token_required
def upload(current_user):
    file = request.files.get('file')
    if not file: return jsonify({'message': 'No file'}), 400

    # --- SECURITY CHECK: MAGIC NUMBERS ---
    if not validate_file_type(file):
        return jsonify({'message': 'File type mismatch or unauthorized format.'}), 400
    # -------------------------------------

    filename = secure_filename(file.filename)
    storage_name = f"{current_user.id}_{filename}"

    # Encrypt
    encrypted_data = cipher_suite.encrypt(file.read())
    with open(os.path.join(UPLOAD_FOLDER, storage_name), 'wb') as f:
        f.write(encrypted_data)

    log_action(current_user.id, "UPLOAD", filename)
    return jsonify({'message': 'Uploaded'})


@vault_bp.route('/list-files')
@token_required
def list_files(current_user):
    all_files = os.listdir(UPLOAD_FOLDER)
    # Filters files to only show those belonging to the current user
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
        log_action(current_user.id, "DELETE", filename)
        return jsonify({'message': 'Deleted'})
    return jsonify({'message': 'Not Found'}), 404