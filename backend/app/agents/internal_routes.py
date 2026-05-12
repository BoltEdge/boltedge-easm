"""Read-only API endpoints that agent code calls from inside the same
Flask app. Even though there is no network boundary, agents go through
this seam to avoid schema-coupling and to leave an audit trail.

URL prefix: /api/internal
Auth: require_agent_key (validates bearer key with kind='agent')
"""
from flask import Blueprint, jsonify, request

from .auth import require_agent_key
from .internal_queries import (
    recent_audit_log,
    recent_contact_requests,
    recent_findings,
    recent_scans,
    weekly_stats,
)

bp = Blueprint("agents_internal", __name__, url_prefix="/api/internal")


@bp.route("/stats/weekly", methods=["GET"])
@require_agent_key(scope="read:stats")
def stats_weekly():
    days = request.args.get("days", default=7, type=int)
    return jsonify(weekly_stats(window_days=max(1, min(days, 90))))


@bp.route("/findings/recent", methods=["GET"])
@require_agent_key(scope="read:findings")
def findings_recent():
    severity = request.args.get("severity")
    since = request.args.get("since")
    limit = request.args.get("limit", default=50, type=int)
    return jsonify(recent_findings(severity=severity, since=since, limit=limit))


@bp.route("/contact-requests/recent", methods=["GET"])
@require_agent_key(scope="read:contact_requests")
def contact_requests_recent():
    since = request.args.get("since")
    limit = request.args.get("limit", default=50, type=int)
    return jsonify(recent_contact_requests(since=since, limit=limit))


@bp.route("/audit-log/recent", methods=["GET"])
@require_agent_key(scope="read:audit_log")
def audit_log_recent():
    category = request.args.get("category")
    since = request.args.get("since")
    limit = request.args.get("limit", default=50, type=int)
    return jsonify(recent_audit_log(category=category, since=since, limit=limit))


@bp.route("/scans/recent", methods=["GET"])
@require_agent_key(scope="read:scans")
def scans_recent():
    status = request.args.get("status")
    since = request.args.get("since")
    limit = request.args.get("limit", default=50, type=int)
    return jsonify(recent_scans(status=status, since=since, limit=limit))
