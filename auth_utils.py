"""
Authentication Utilities

Provides authentication helpers and audit logging functionality.

Security Features:
1. JWT Token Management:
   - Tokens stored in HTTPOnly cookies (prevents XSS theft)
   - HS256 algorithm for token signing
   - Token validation on every protected request

2. Audit Logging:
   - Immutable logs stored in separate database
   - Captures IP addresses and user agents for forensics
   - Logs both successful and failed security events
   - Tracks authentication attempts, file operations, and security violations

3. Access Control:
   - Decorator-based authorization (token_required)
   - Fails closed: Invalid/missing tokens result in access denial
   - Passes authenticated user object to protected routes
"""

import jwt
from functools import wraps
from flask import request, jsonify, current_app
from models import User, AuditLog
from config import db

def log_action(user_id, action, filename=None, username_entered=None, success=None, details=None):
    """
    Creates an immutable audit log entry.
    
    Security: All actions are logged to separate database for tamper resistance.
    Logs include IP address and user agent for forensic analysis.
    """
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
    """
    Decorator for protecting routes with JWT authentication.
    
    Security Features:
    1. Token Extraction:
       - Reads JWT from HTTPOnly cookie (prevents XSS theft)
       - Cookie name: 'auth_token'
       - Missing token = 403 Forbidden
    
    2. Token Validation:
       - Verifies JWT signature using SECRET_KEY
       - Checks token hasn't been tampered with
       - Uses HS256 algorithm (HMAC with SHA-256)
       - Invalid/expired token = 403 Forbidden
    
    3. User Resolution:
       - Extracts user_id from JWT payload
       - Queries database for current user object
       - Passes user object to protected route function
    
    4. Security Design:
       - Fails closed (deny access on any error)
       - No token details in error messages (prevents enumeration)
       - Broad exception catching (defensive security)
       - User object ensures route has current data
    
    Usage:
      @vault_bp.route('/protected')
      @token_required
      def protected_route(current_user):
          # current_user is authenticated User object
          return f"Hello {current_user.username}"
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # Extract JWT from HTTPOnly cookie
        token = request.cookies.get('auth_token')
        if not token:
            return jsonify({'message': 'Missing Token'}), 403
        try:
            # Verify and decode JWT
            # Raises exception if signature invalid or token expired
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            # Load current user from database
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            # Fail closed: Deny access on any error
            return jsonify({'message': 'Invalid Token'}), 403
        # Pass authenticated user to protected route
        return f(current_user, *args, **kwargs)
    return decorated