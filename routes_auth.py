import datetime
import re
import jwt
import pyotp
import qrcode
import io
import base64
from flask import Blueprint, request, jsonify, make_response, render_template, current_app
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
        
        # Return user_id for OTP confirmation step (instead of redirecting to login immediately)
        return jsonify({
            'message': 'Registered - Confirm OTP',
            'qr_code': img_b64,
            'secret': secret,
            'user_id': user.id,
            'otp_confirmation_required': True
        }), 201
    except Exception as e:
        return jsonify({'message': 'User already exists or Database Error'}), 400

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # --- SANITIZATION ---
    if not is_safe_input(username):
        log_action(
            user_id=None,
            action="LOGIN_FAILED",
            username_entered=username,
            success=False,
            details="INVALID_CHARACTERS_IN_USERNAME"
        )
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
                return jsonify({'message': 'Security Alert: Too many failed attempts. Account locked for 15 minutes.'}), 403
            
            db.session.commit()
            log_action(
                user_id=user.id,
                action="LOGIN_FAILED",
                username_entered=username,
                success=False,
                details="BAD_USERNAME_OR_PASSWORD"
            )
            return jsonify({'message': 'Invalid Credentials'}), 401
            
    print(f"DEBUG: Login attempt for {data.get('username')}")
    
    user = User.query.filter_by(username=data.get('username')).first()
    
    if user and bcrypt.check_password_hash(user.password, data.get('password')):
        print(f"DEBUG: Password OK. Requesting OTP for User ID {user.id}")
        return jsonify({'otp_required': True, 'user_id': user.id})
        
    print("DEBUG: Invalid Username or Password")
    log_action(
        user_id=user.id if user else None,
        action="LOGIN_FAILED",
        username_entered=data.get('username'),
        success=False,
        details="BAD_USERNAME_OR_PASSWORD"
    )
    return jsonify({'message': 'Invalid Credentials'}), 401

@auth_bp.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    user_id = data.get('user_id')
    input_code = data.get('otp')
    
    user = User.query.get(user_id)
    if not user:
        print("DEBUG: User ID not found in DB")
        log_action(
            user_id=user.id,
            action="LOGIN_FAILED",
            username_entered=user.username,
            success=False,
            details="INVALID_OTP"
        )
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
        resp.set_cookie('auth_token', token, httponly=True, secure=True)
        log_action(user_id, "LOGIN_SUCCESS", username_entered=user.username, success=True)
        return resp
    else:
        print("DEBUG: TOTP Verification Failed. Check Server Time vs Phone Time.")
        log_action(
            user_id=user.id,
            action="LOGIN_FAILED",
            username_entered=user.username,
            success=False,
            details="INVALID_2FA CODE"
        )
        return jsonify({'message': 'Invalid 2FA Code'}), 401

#additional feature of confirmation of OTP during registration
@auth_bp.route('/confirm-otp-registration', methods=['POST'])
def confirm_otp_registration():
    """
    New endpoint: Allows users to test their OTP during registration before redirecting to login.
    This happens AFTER they scan the QR code but BEFORE they're taken to the login page.
    """
    data = request.json
    user_id = data.get('user_id')
    input_code = data.get('otp')
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    # Verify TOTP
    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(input_code):
        log_action(user_id, "REGISTRATION_OTP_CONFIRMED", username_entered=user.username, success=True)
        return jsonify({
            'message': 'OTP Confirmed! Registration complete. You can now log in.',
            'success': True
        }), 200
    else:
        return jsonify({
            'message': 'Invalid OTP Code. Please try again.',
            'success': False
        }), 401

@auth_bp.route('/logout', methods=['POST'])
def logout():
    token = request.cookies.get('auth_token')

    username = None
    if token:
        try:
            decoded = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            user_id = decoded.get("user_id")
            if user_id:
                user = User.query.get(user_id)
                if user:
                    username = user.username
        except Exception:
            # token invalid/expired - still proceed to clear cookie
            username = None

    # log logout
    if username:
        log_action(
            user_id=decoded.get("user_id"),
            action="LOGOUT",
            username_entered=username,
            success=True
        )
    resp = make_response(jsonify({'message': 'Logged out'}))
    resp.set_cookie('auth_token', '', expires=0)
    return resp