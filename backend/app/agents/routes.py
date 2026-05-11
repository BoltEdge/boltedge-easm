"""Admin UI endpoints for the agent platform.

All routes are gated by the existing `require_superadmin` decorator.
URL prefix: /admin/agents
"""
from flask import Blueprint

bp = Blueprint("agents_admin", __name__, url_prefix="/admin/agents")
