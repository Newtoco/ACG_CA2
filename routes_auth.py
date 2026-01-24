import datetime
import re
import jwt
import pyotp
import qrcode
import io
import base64
from flask import Blueprint, request, jsonify, make_response, render_template
from config import db, bcrypt
from models import User
from utils import log_action


auth_bp = Blueprint('auth', __name__)

# --- INPUT SANITIZATION ---
def is_safe_input(input_str):
    """
    Prevents Injection Attacks by enforcing alphanumeric characters only.
    Ref: Assignment Brief - 'Robustness'
    """
    if not input_str:
        return False
    # Regex: Allow only a-z, A-Z, 0-9. No special chars (like ' OR 1=1).
    return bool(re.match("^[a-zA-Z0-9]+$", input_str))

# --- PASSWORD STRENGTH POLICY ---
def is_strong_password(password):
    """
    Enforces strong password complexity to prevent Dictionary Attacks.
    Requirements: 8+ chars, Upper, Lower, Digit, Symbol.
    """
    if len(password) < 8: return False
    if not re.search(r"[a-z]", password): return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"[0-9]", password): return False
    if not re.search(r"[!@#$%^&*]", password): return False
    return True

@auth_bp.route('/')
def home():
    return render_template('index.html', mode='login')

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing data'}), 400

    # --- SECURITY CHECK: SANITIZATION ---
    if not is_safe_input(username):
        return jsonify({'message': 'Security Alert: Username must be alphanumeric only.'}), 400
    
    # --- SECURITY CHECK: PASSWORD STRENGTH ---
    if not is_strong_password(password):
        return jsonify({
            'message': 'Weak Password. Must be 8+ chars and include: Upper, Lower, Number, Symbol (!@#$%).'
        }), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    secret = pyotp.random_base32()
    
    try:
        # 'failed_attempts' and 'locked_until' are required in models.py
        user = User(
            username=username, 
            password=hashed_pw, 
            totp_secret=secret,
            failed_attempts=0, 
            locked_until=None
        )
        db.session.add(user)
        db.session.commit()
        
        # Generate QR Code for 2FA
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureVault")
        img = qrcode.make(totp_uri)
        buf = io.BytesIO()
        img.save(buf)
        buf.seek(0)
        img_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        
        return jsonify({'message': 'Registered', 'qr_code': img_b64, 'secret': secret})
    except Exception as e:
        return jsonify({'message': 'User already exists or Database Error'}), 400

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # --- SANITIZATION ---
    if not is_safe_input(username):
        return jsonify({'message': 'Invalid characters in username'}), 400

    user = User.query.filter_by(username=username).first()

    # --- BRUTE FORCE PROTECTION ---
    if user:
        # 1. Check if account is currently locked
        if user.locked_until and user.locked_until > datetime.datetime.utcnow():
            remaining = (user.locked_until - datetime.datetime.utcnow()).seconds // 60
            return jsonify({'message': f'Account Locked. Try again in {remaining} minutes.'}), 403

        # 2. Verify Password
        if bcrypt.check_password_hash(user.password, password):
            # Success: Reset the counter
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()
            return jsonify({'otp_required': True, 'user_id': user.id})
        else:
            # Failure: Increment counter
            user.failed_attempts = (user.failed_attempts or 0) + 1
            
            # Lockout Logic: 5 Failed Attempts = 15 Minute Lockout
            if user.failed_attempts >= 5:
                user.locked_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
                db.session.commit()
                log_action(user.id, "SECURITY_LOCKOUT")
                return jsonify({'message': 'Security Alert: Too many failed attempts. Account locked for 15 minutes.'}), 403
            
            db.session.commit()
            return jsonify({'message': 'Invalid Credentials'}), 401
            
    return jsonify({'message': 'Login Failed'}), 401

@auth_bp.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    user_id = data.get('user_id')
    input_code = data.get('otp')
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
        
    # Verify TOTP
    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(input_code):
        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, 'super-secret-key-change-in-prod', algorithm="HS256")
        
        resp = make_response(jsonify({'message': 'Success'}))
        resp.set_cookie('auth_token', token, httponly=True, secure=True, samesite='Strict') # Guarantees the cookie is never sent over unencrypted HTTP (prevents sniffing)
        log_action(user_id, "LOGIN_SUCCESS")
        return resp
    else:
        return jsonify({'message': 'Invalid 2FA Code'}), 401

@auth_bp.route('/logout', methods=['POST'])
def logout():
    resp = make_response(jsonify({'message': 'Logged out'}))
    resp.set_cookie('auth_token', '', expires=0)
    return resp