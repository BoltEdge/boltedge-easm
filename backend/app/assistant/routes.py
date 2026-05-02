# =============================================================================
# File: app/assistant/routes.py
# Description: Nano EASM Security AI Assistant (NESAA) — Phase 1 endpoints.
#
# Phase 1 is template-based, tenant-scoped, read-only. No external AI
# providers are called. See app/assistant/__init__.py for the rationale.
# =============================================================================

from __future__ import annotations

import logging

from flask import Blueprint, request, jsonify

from app.extensions import db
from app.models import Finding, Asset
from app.auth.decorators import (
    require_auth, allow_api_key, current_user_id, current_organization_id,
)
from app.audit.routes import log_audit
from app.utils.display_id import resolve_id

from .explainer import explain_finding


assistant_bp = Blueprint("assistant", __name__, url_prefix="/assistant")
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# POST /assistant/finding-explainer
# ─────────────────────────────────────────────────────────────────────────────
#
# Returns a structured 5-section explanation for a finding the user owns:
#   summary, technicalExplanation, evidence, remediation, clientSummary
#
# Read-only. Uses the same tenant-scoping pattern as findings/routes.py
# (Finding → Asset.organization_id == current_organization_id).
#
# Accepts both numeric ids and display ids (e.g. "FN0042").
# ─────────────────────────────────────────────────────────────────────────────

@assistant_bp.post("/finding-explainer")
@require_auth
@allow_api_key
def finding_explainer():
    body = request.get_json(silent=True) or {}
    raw = body.get("findingId") or body.get("finding_id")
    if raw is None:
        return jsonify(error="findingId is required.", code="INVALID_FINDING_ID"), 400

    int_id = resolve_id(raw, "FN")
    if int_id is None:
        return jsonify(error="Invalid finding id.", code="INVALID_FINDING_ID"), 400

    org_id = current_organization_id()
    user_id = current_user_id()

    # Tenant-scoped fetch: identical pattern to findings/routes.py update_finding.
    # Joining through Asset.organization_id makes cross-org access impossible
    # — a finding owned by another org returns 404 (not 403, so existence
    # isn't leaked).
    finding = (
        db.session.query(Finding)
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(Finding.id == int_id, Asset.organization_id == org_id)
        .options(db.joinedload(Finding.asset).joinedload(Asset.group))
        .first()
    )

    if not finding:
        return jsonify(error="Finding not found.", code="NOT_FOUND"), 404

    try:
        explanation = explain_finding(finding)
    except Exception:
        logger.exception("Finding explainer failed for finding id %s", finding.id)
        return jsonify(
            error="Could not generate an explanation for this finding.",
            code="EXPLAINER_ERROR",
        ), 500

    # Audit log: finding id only, no explanation content. The content is
    # derived deterministically from the finding row itself, so logging it
    # would just duplicate state already in the DB.
    log_audit(
        organization_id=org_id,
        user_id=user_id,
        action="assistant.finding_explained",
        category="assistant",
        target_type="finding",
        target_id=str(finding.id),
        target_label=finding.title,
        description=f"Generated AI explanation for finding {finding.public_id or finding.id}",
        metadata={"template_id": finding.template_id},
    )
    db.session.commit()

    return jsonify(
        findingId=finding.public_id or str(finding.id),
        explanation=explanation,
        # Source label so the frontend can show "Powered by..." attribution
        # if you ever want to. For Phase 1 it's our own knowledge base.
        source="nano-easm-knowledge-base",
    ), 200
