# =============================================================================
# File: app/contact/routes.py
# Description: Public contact-form submissions.
#
#   POST /contact-requests   — public (no auth) form endpoint
#
# Admin endpoints (list / reply / status / delete) live under /admin/* in
# app/admin/routes.py so the existing superadmin guard applies.
# =============================================================================

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
import re

from flask import Blueprint, request, jsonify

from app.extensions import db
from app.models import ContactRequest


contact_bp = Blueprint("contact", __name__, url_prefix="/contact-requests")
logger = logging.getLogger(__name__)


# Rate-limit window: max submissions per IP in the trailing N minutes.
# Match the spirit of the quick-scan abuse limits.
RATE_LIMIT_WINDOW_MINUTES = 60
RATE_LIMIT_MAX_PER_WINDOW = 5

# Hard caps so a hostile sender can't flood the DB with multi-MB payloads.
MAX_NAME_LEN     = 120
MAX_EMAIL_LEN    = 255
MAX_SUBJECT_LEN  = 200
MAX_MESSAGE_LEN  = 5000


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _client_ip() -> str | None:
    # Honour X-Forwarded-For when present (Nginx in front of the app).
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr


@contact_bp.post("")
def submit_contact_request():
    """
    Public form endpoint. Validates input, enforces a per-IP rate limit,
    and persists the row. Returns 201 with a public_id the user can quote
    if they reach out again.
    """
    body = request.get_json(silent=True) or {}

    # --- Honeypot --------------------------------------------------------
    # Form has a hidden input named "website". Bots fill it; humans don't.
    # If it's non-empty, silently accept and drop — appears successful so
    # the bot doesn't retry, but no row is written and no email sent.
    if (body.get("website") or "").strip():
        return jsonify(message="Thanks! We'll get back to you shortly."), 201

    name    = (body.get("name") or "").strip()
    email   = (body.get("email") or "").strip().lower()
    subject = (body.get("subject") or "").strip()
    message = (body.get("message") or "").strip()

    # --- Validation ------------------------------------------------------
    errors: dict[str, str] = {}
    if not name:
        errors["name"] = "Name is required."
    elif len(name) > MAX_NAME_LEN:
        errors["name"] = f"Name must be at most {MAX_NAME_LEN} characters."

    if not email:
        errors["email"] = "Email is required."
    elif len(email) > MAX_EMAIL_LEN or not _EMAIL_RE.match(email):
        errors["email"] = "Please enter a valid email address."

    if subject and len(subject) > MAX_SUBJECT_LEN:
        errors["subject"] = f"Subject must be at most {MAX_SUBJECT_LEN} characters."

    if not message:
        errors["message"] = "Message is required."
    elif len(message) > MAX_MESSAGE_LEN:
        errors["message"] = f"Message must be at most {MAX_MESSAGE_LEN} characters."

    if errors:
        return jsonify(error="Validation failed.", fieldErrors=errors), 400

    # --- Rate limit (per IP) --------------------------------------------
    ip = _client_ip()
    if ip:
        window_start = _now_utc() - timedelta(minutes=RATE_LIMIT_WINDOW_MINUTES)
        recent = ContactRequest.query.filter(
            ContactRequest.ip_address == ip,
            ContactRequest.created_at >= window_start,
        ).count()
        if recent >= RATE_LIMIT_MAX_PER_WINDOW:
            return jsonify(
                error=(
                    "Too many requests from your IP. Please try again in "
                    "an hour or email us directly."
                ),
                code="RATE_LIMITED",
            ), 429

    # --- Persist ---------------------------------------------------------
    user_agent = request.headers.get("User-Agent", "")[:500] or None
    referer = request.headers.get("Referer", "")[:500] or None

    cr = ContactRequest(
        name=name,
        email=email,
        subject=subject or None,
        message=message,
        ip_address=ip,
        user_agent=user_agent,
        referer=referer,
        status="open",
        created_at=_now_utc(),
        updated_at=_now_utc(),
    )
    db.session.add(cr)
    db.session.commit()

    logger.info("Contact request received: %s from %s (%s)", cr.public_id, email, ip)

    return jsonify(
        message="Thanks! We've received your message and will get back to you shortly.",
        requestId=cr.public_id,
    ), 201
