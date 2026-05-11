"""Authentication for agent platform endpoints.

`require_agent_key(scope=...)` validates that the request bears an API
key with `kind='agent'` and the requested scope. On any failure it
returns 401 (missing/invalid key) or 403 (key valid but scope absent).
"""
from __future__ import annotations
import hashlib
from functools import wraps
from typing import Callable

from flask import request, g, jsonify

from app.models import ApiKey


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _extract_bearer(req) -> str | None:
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return auth[len("Bearer "):].strip() or None


def require_agent_key(scope: str) -> Callable:
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            raw = _extract_bearer(request)
            if not raw:
                return jsonify({"error": "missing_bearer"}), 401

            key = ApiKey.query.filter_by(
                key_hash=_sha256(raw), kind="agent",
            ).first()
            if not key:
                return jsonify({"error": "invalid_key"}), 401

            scopes = key.scopes or []
            if scope not in scopes:
                return jsonify({"error": "scope_denied",
                                "required": scope}), 403

            g.agent_api_key = key
            g.agent_id = key.name  # convention: ApiKey.name == agent_id

            # Audit-log the call so every agent API request surfaces in
            # /admin/audit-log alongside all other platform events.
            from app.audit.routes import log_audit  # local import avoids cycles
            log_audit(
                organization_id=key.organization_id,
                user_email=f"agent:{key.name}",
                action=f"{request.method} {request.path}",
                category="agent",
                description=f"Agent API call — scope={scope}",
                metadata={"key_id": key.id, "scope": scope,
                          "remote_addr": request.remote_addr},
            )

            return fn(*args, **kwargs)

        return wrapper

    return decorator
