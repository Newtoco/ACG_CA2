import datetime
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

@auth_bp.route('/')
def home():
    return render_template('index.html', mode='login')

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing data'}), 400
        
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    # Generate Secret
    secret = pyotp.random_base32()
    
    try:
        user = User(username=data['username'], password=hashed_pw, totp_secret=secret)
        db.session.add(user)
        db.session.commit()
        
        # Generate QR
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=data['username'], 
            issuer_name="SecureVault"
        )
        
        img = qrcode.make(totp_uri)
        buf = io.BytesIO()
        img.save(buf)
        buf.seek(0)
        img_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        
        return jsonify({
            'message': 'Registered', 
            'qr_code': img_b64, 
            'secret': secret 
        })
    except Exception as e:
        print(f"DEBUG: Register Error: {e}")
        return jsonify({'message': 'User exists or Error'}), 400

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    print(f"DEBUG: Login attempt for {data.get('username')}")
    
    user = User.query.filter_by(username=data.get('username')).first()
    
    if user and bcrypt.check_password_hash(user.password, data.get('password')):
        print(f"DEBUG: Password OK. Requesting OTP for User ID {user.id}")
        return jsonify({'otp_required': True, 'user_id': user.id})
        
    print("DEBUG: Invalid Username or Password")
    log_action(
        user_id=user.id if user else None,
        action="LOGIN_FAILED",
        username_entered=data.get("username"),
        success=False,
        details="BAD_USERNAME_OR_PASSWORD"
    )
    return jsonify({'message': 'Login Failed'}), 401

@auth_bp.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    user_id = data.get('user_id')
    # FIX: Remove any spaces the user might have typed
    input_code = str(data.get('otp')).replace(" ", "")
    
    print(f"DEBUG: Verifying OTP for User ID: {user_id} | Code: {input_code}")

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
        
    # Verify
    totp = pyotp.TOTP(user.totp_secret)
    
    # DEBUG: Print validation result locally
    is_valid = totp.verify(input_code)
    print(f"DEBUG: Valid Code? {is_valid}")
    
    if is_valid:
        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }, 'super-secret-key-change-in-prod', algorithm="HS256")
        
        resp = make_response(jsonify({'message': 'Success'}))
        resp.set_cookie('auth_token', token, httponly=True, secure=True)
        log_action(user_id, "LOGIN_SUCCESS", username_entered=user.username, success=True)
        return resp
    else:
        print("DEBUG: TOTP Verification Failed. Check Server Time vs Phone Time.")
        return jsonify({'message': 'Invalid 2FA Code'}), 401

@auth_bp.route('/logout', methods=['POST'])
def logout():
    resp = make_response(jsonify({'message': 'Logged out'}))
    resp.set_cookie('auth_token', '', expires=0)
    return resp