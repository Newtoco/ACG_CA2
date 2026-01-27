from flask import Blueprint, jsonify, request
from utils import token_required
from models import AuditLog

view_logs_bp = Blueprint("view_logs", __name__)

@view_logs_bp.route("/logs/failed-logins", methods=["GET"])
@token_required
def failed_logins(current_user):
    if current_user.username != "admin":
        return jsonify({"message": "Forbidden"}), 403

    limit = min(int(request.args.get("limit", 200)), 500)
    username = request.args.get("username")

    q = AuditLog.query.filter(AuditLog.action == "LOGIN_FAILED").order_by(AuditLog.timestamp.desc())
    if username:
        q = q.filter(AuditLog.username_entered.ilike(f"%{username}%"))

    rows = q.limit(limit).all()

    return jsonify([
        {
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "username_entered": r.username_entered,
            "user_id": r.user_id,
            "ip_address": r.ip_address,
            "details": r.details
        } for r in rows
    ])
