"""Read-only API endpoints that agent code calls from inside the same
Flask app. Even though there is no network boundary, agents go through
this seam to avoid schema-coupling and to leave an audit trail.

URL prefix: /api/internal
Auth: require_agent_key (validates bearer key with kind='agent')
"""
from flask import Blueprint, jsonify, request

from .auth import require_agent_key
from .internal_stats import weekly_stats

bp = Blueprint("agents_internal", __name__, url_prefix="/api/internal")


@bp.route("/stats/weekly", methods=["GET"])
@require_agent_key(scope="read:stats")
def stats_weekly():
    days = request.args.get("days", default=7, type=int)
    return jsonify(weekly_stats(window_days=max(1, min(days, 90))))
