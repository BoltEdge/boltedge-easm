"""
Cloudflare Turnstile verification helper.

Used to gate the public-facing endpoints (/quick-scan, /quick-discovery,
/assistant/public-explain, /contact-requests) against bots and abusive
automation in addition to the existing per-IP rate limit + block list.

Configuration:
    TURNSTILE_SECRET_KEY  — required to enforce verification. When unset
                            (e.g., local dev without a Turnstile account),
                            verify_turnstile() is a no-op.

Token transport:
    Frontend posts the token in the JSON body under "turnstileToken"
    (camelCase, matches the rest of the API). A snake_case "turnstile_token"
    fallback and a "CF-Turnstile-Response" header fallback are accepted
    so other clients (curl, automation) can integrate without ceremony.

Fail-open semantics:
    If Cloudflare's verify endpoint times out, returns 5xx, or reports an
    "internal-error", verify_turnstile() returns success — by design. The
    rate limit + IP block list remain in effect as a backstop, and a
    Cloudflare outage shouldn't break the top-of-funnel. To enforce
    fail-closed for a specific call, pass fail_open=False.
"""
from __future__ import annotations

import logging
import os
from typing import Optional, Tuple

import httpx
from flask import Request


logger = logging.getLogger(__name__)

VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
VERIFY_TIMEOUT_S = 5.0


def verify_turnstile(
    request: Request,
    *,
    fail_open: bool = True,
) -> Tuple[bool, Optional[str]]:
    """Verify a Cloudflare Turnstile token attached to the request.

    Returns (passed, error_message). The error_message (when present) is
    safe to surface in API responses — it never leaks Cloudflare error
    codes or internal state.

    Args:
        request: The Flask request (typically `flask.request`).
        fail_open: When True (default), Cloudflare-side outages do NOT
            reject the request. Set False to fail closed.
    """
    secret = os.getenv("TURNSTILE_SECRET_KEY", "").strip()
    if not secret:
        # Not configured — skip the check entirely. Lets dev environments
        # work without a Turnstile account. Production must set the secret.
        return True, None

    body = request.get_json(silent=True) or {}
    token = (
        (body.get("turnstileToken") or "").strip()
        or (body.get("turnstile_token") or "").strip()
        or request.headers.get("CF-Turnstile-Response", "").strip()
    )
    if not token:
        return False, "Verification challenge required"

    # Cloudflare optionally scores the request using the client IP.
    # request.remote_addr is already the real client IP because ProxyFix
    # is wired up in app/__init__.py.
    remote_ip = request.remote_addr or ""

    try:
        resp = httpx.post(
            VERIFY_URL,
            data={"secret": secret, "response": token, "remoteip": remote_ip},
            timeout=VERIFY_TIMEOUT_S,
        )
    except httpx.HTTPError:
        logger.exception(
            "Turnstile verify request failed; failing %s",
            "open" if fail_open else "closed",
        )
        if fail_open:
            return True, None
        return False, "Verification temporarily unavailable"

    if resp.status_code != 200:
        logger.warning(
            "Turnstile verify returned HTTP %d; failing %s",
            resp.status_code,
            "open" if fail_open else "closed",
        )
        if fail_open:
            return True, None
        return False, "Verification temporarily unavailable"

    try:
        data = resp.json()
    except ValueError:
        logger.warning(
            "Turnstile verify returned non-JSON body; failing %s",
            "open" if fail_open else "closed",
        )
        if fail_open:
            return True, None
        return False, "Verification temporarily unavailable"

    if data.get("success") is True:
        return True, None

    # Cloudflare distinguishes user-side failures (invalid/expired/duplicate
    # token) from Cloudflare-side failures ("internal-error"). Treat the
    # latter as an outage and apply fail_open semantics; treat the former
    # as a real rejection regardless.
    error_codes = data.get("error-codes") or []
    if "internal-error" in error_codes:
        logger.warning(
            "Turnstile reported internal-error; failing %s",
            "open" if fail_open else "closed",
        )
        if fail_open:
            return True, None
        return False, "Verification temporarily unavailable"

    return False, "Verification failed"
