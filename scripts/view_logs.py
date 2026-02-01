# Denzel's Code

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Blueprint, jsonify, request
from auth_utils import token_required
from models import AuditLog, User

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

@view_logs_bp.route("/logs/all", methods=["GET"])
@token_required
def all_logs(current_user):
    if current_user.username != "admin":
        return jsonify({"message": "Forbidden"}), 403

    limit = min(int(request.args.get("limit", 100)), 500)
    username = request.args.get("username")
    action_filter = request.args.get("action")

    query = AuditLog.query

    if username:
        user = User.query.filter(User.username.ilike(f"%{username}%")).first()
        if user:
            query = query.filter(AuditLog.user_id == user.id)
        else:
            # If a username filter is specified but the user doesn't exist, return no results.
            return jsonify([])

    if action_filter:
        # Allow filtering by a single action, e.g., action=UPLOAD
        query = query.filter(AuditLog.action == action_filter)

    rows = query.order_by(AuditLog.timestamp.desc()).limit(limit).all()

    return jsonify([
        {
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "action": r.action,
            "user_id": r.user_id,
            "username_entered": r.username_entered,
            "filename": r.filename,
            "details": r.details,
            "ip_address": r.ip_address
        } for r in rows
    ])
