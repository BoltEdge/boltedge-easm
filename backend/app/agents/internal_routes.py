"""Read-only API endpoints that agent code calls from inside the same
Flask app. Even though there is no network boundary, agents go through
this seam to avoid schema-coupling and to leave an audit trail.

URL prefix: /api/internal
Auth: require_agent_key (validates bearer key with kind='agent')
"""
from flask import Blueprint

bp = Blueprint("agents_internal", __name__, url_prefix="/api/internal")
