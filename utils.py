import jwt
from functools import wraps
from flask import request, jsonify, current_app
from models import User, AuditLog
from config import db

def log_action(user_id, action, filename=None, username_entered=None, success=None, details=None):
    new_log = AuditLog(
        user_id=user_id,
        action=action,
        filename=filename,
        username_entered=username_entered,
        success=success,
        details=details,
        ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
        user_agent=request.headers.get("User-Agent")
    )
    db.session.add(new_log)
    db.session.commit()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('auth_token')
        if not token:
            return jsonify({'message': 'Missing Token'}), 403
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            return jsonify({'message': 'Invalid Token'}), 403
        return f(current_user, *args, **kwargs)
    return decorated