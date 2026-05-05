# app/auth/mfa.py
"""
TOTP MFA endpoints + helpers.

Endpoints (mounted on the existing auth blueprint):
  POST /auth/mfa/enroll              — start enrolment, returns secret + QR + recovery codes
  POST /auth/mfa/enroll/confirm      — verify first code, flip mfa_enabled=true
  POST /auth/mfa/verify              — second-factor at login (TOTP or recovery code)
  POST /auth/mfa/disable             — disable MFA (requires password reverify)
  POST /auth/mfa/recovery-key/regenerate — invalidate old key, return a new one
  GET  /auth/mfa/status              — for the Settings UI: enrolled? enrolled_at? codes_remaining?

Login-flow integration is in routes.py (the /auth/login endpoint
issues an mfa_token instead of a JWT when mfa_required).

Time-skew: pyotp.TOTP.verify defaults to a 30s window with valid_window=0.
We pass valid_window=1 (one step before + one step after) so a clock skew
of up to 30s is tolerated. Replay protection is implicit because the
client only gets one chance per login attempt; we do not maintain a
"used codes" cache.
"""
from __future__ import annotations

import base64
import io
import secrets as _secrets
from datetime import datetime, timezone
from typing import Optional

import pyotp
import qrcode
from flask import Blueprint, current_app, g, jsonify, request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from app.audit.routes import log_audit
from app.auth.decorators import require_auth
from app.auth.mfa_crypto import decrypt_secret, encrypt_secret
from app.extensions import db
from app.models import OrganizationMember, User, UserRecoveryCode


# ── Constants ────────────────────────────────────────────────────────

MFA_TOKEN_MAX_AGE = 60 * 5  # 5 minutes — plenty of time to type a 6-digit code
MFA_TOKEN_SALT = "nanoasm-mfa-challenge"
RECOVERY_KEY_BYTES = 16  # 16 bytes → 32 hex chars → 128 bits of entropy
TOTP_ISSUER = "Nano EASM"


# ── Helpers ──────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _mfa_token_serializer(secret_key: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret_key, salt=MFA_TOKEN_SALT)


def create_mfa_challenge_token(*, secret_key: str, user_id: int) -> str:
    """
    Short-lived token issued after successful password but before MFA
    code. Never granted as a session — purely a one-shot challenge id.
    """
    return _mfa_token_serializer(secret_key).dumps(
        {"user_id": int(user_id), "purpose": "mfa"}
    )


def verify_mfa_challenge_token(*, secret_key: str, token: str) -> Optional[int]:
    """Returns user_id or None if invalid/expired."""
    try:
        data = _mfa_token_serializer(secret_key).loads(
            token, max_age=MFA_TOKEN_MAX_AGE
        )
        if data.get("purpose") != "mfa":
            return None
        uid = data.get("user_id")
        return int(uid) if uid is not None else None
    except (SignatureExpired, BadSignature):
        return None


def _format_recovery_key(raw_hex: str) -> str:
    """
    Format a 32-char hex string as 8 dash-separated 4-char groups for
    readability (e.g., "a3f2-e1c4-b7d8-e9f0-1a2b-3c4d-5e6f-7a8b").
    Verification strips dashes/whitespace before comparing — see
    `_consume_recovery_key`.
    """
    return "-".join(raw_hex[i : i + 4] for i in range(0, len(raw_hex), 4))


def _generate_recovery_key(user: User) -> str:
    """
    Replace any existing UserRecoveryCode row(s) with a single fresh
    recovery key. Returns the plaintext, dash-formatted key (caller
    surfaces it ONCE in the response).
    """
    UserRecoveryCode.query.filter_by(user_id=user.id).delete()
    raw = _secrets.token_hex(RECOVERY_KEY_BYTES)  # 32 hex chars
    db.session.add(
        UserRecoveryCode(
            user_id=user.id,
            code_hash=generate_password_hash(raw),
        )
    )
    return _format_recovery_key(raw)


def _consume_recovery_key(user: User, candidate: str) -> bool:
    """
    Try to consume `candidate` as the single-use recovery key. Returns
    True on success (and stamps used_at). Whitespace and dashes are
    stripped; case is normalised to lower (the key is hex).
    """
    norm = (candidate or "").strip().lower().replace("-", "").replace(" ", "")
    if not norm:
        return False
    rows = UserRecoveryCode.query.filter_by(user_id=user.id, used_at=None).all()
    for row in rows:
        if check_password_hash(row.code_hash, norm):
            row.used_at = _now_utc()
            return True
    return False


def _qr_data_url(provisioning_uri: str) -> str:
    """
    Render the otpauth:// URI as a PNG data URL. We do this server-side
    so the secret never touches a third-party QR-rendering service.
    """
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def _verify_totp(user: User, code: str) -> bool:
    """
    Verify a 6-digit TOTP against the user's encrypted secret. Tolerates
    one 30s step of clock skew on each side.
    """
    norm = (code or "").strip().replace(" ", "").replace("-", "")
    if not (norm.isdigit() and len(norm) == 6):
        return False
    if not user.mfa_secret_ciphertext:
        return False
    plain = decrypt_secret(user.mfa_secret_ciphertext)
    if not plain:
        # Ciphertext present but undecryptable — almost certainly a
        # MFA_SECRET_KEY rotation or corruption. Fail closed; the user
        # must re-enrol.
        return False
    return pyotp.TOTP(plain).verify(norm, valid_window=1)


def _membership_for(user: User) -> Optional[OrganizationMember]:
    return OrganizationMember.query.filter_by(
        user_id=user.id, is_active=True
    ).first()


def _audit_org_id_for(user: User) -> Optional[int]:
    m = _membership_for(user)
    return m.organization_id if m else None


# ── Endpoints ────────────────────────────────────────────────────────

mfa_bp = Blueprint("auth_mfa", __name__, url_prefix="/auth/mfa")


@mfa_bp.post("/enroll")
@require_auth
def enroll():
    """
    Start MFA enrolment. Generates a fresh secret + 10 recovery codes,
    stores them (encrypted / hashed). Does NOT flip mfa_enabled — that
    happens at /enroll/confirm. So a user who closes the page mid-setup
    is back to unenrolled (next call to /enroll just overwrites).
    """
    user: User = g.current_user

    if user.mfa_enabled:
        return jsonify(
            error="MFA is already enabled. Disable it first if you want to re-enrol.",
            code="MFA_ALREADY_ENABLED",
        ), 409

    # Generate + encrypt the secret
    secret = pyotp.random_base32()
    user.mfa_secret_ciphertext = encrypt_secret(secret)
    user.mfa_enrolled_at = None  # not enrolled until confirm

    # Issue a fresh single-use recovery key
    recovery_key = _generate_recovery_key(user)

    db.session.commit()

    # Build the otpauth:// URI that authenticator apps consume
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=user.email,
        issuer_name=TOTP_ISSUER,
    )

    log_audit(
        organization_id=_audit_org_id_for(user),
        user_id=user.id,
        action="auth.mfa_enroll_started",
        category="auth",
        target_type="user",
        target_id=str(user.id),
        target_label=user.email,
        description=f"MFA enrolment started for {user.email}",
    )

    return jsonify(
        secret=secret,                   # shown ONCE so user can manually enter if QR fails
        provisioningUri=provisioning_uri,  # otpauth:// — kept for clients that prefer to render QR themselves
        qrCodeDataUrl=_qr_data_url(provisioning_uri),  # ready-to-render PNG; secret never leaves our server
        recoveryKey=recovery_key,        # shown ONCE — single-use; if lost the user contacts support
    ), 200


@mfa_bp.post("/enroll/confirm")
@require_auth
def enroll_confirm():
    """
    Verify the first code and flip mfa_enabled=true. After this point,
    every login requires MFA.
    """
    user: User = g.current_user

    if user.mfa_enabled:
        return jsonify(error="MFA already enabled", code="MFA_ALREADY_ENABLED"), 409
    if not user.mfa_secret_ciphertext:
        return jsonify(
            error="Start enrolment first.",
            code="MFA_NOT_STARTED",
        ), 400

    body = request.get_json(silent=True) or {}
    code = (body.get("code") or "").strip()

    if not _verify_totp(user, code):
        return jsonify(error="Invalid code. Try again.", code="MFA_INVALID_CODE"), 400

    user.mfa_enabled = True
    user.mfa_enrolled_at = _now_utc()
    db.session.commit()

    log_audit(
        organization_id=_audit_org_id_for(user),
        user_id=user.id,
        action="auth.mfa_enroll_completed",
        category="auth",
        target_type="user",
        target_id=str(user.id),
        target_label=user.email,
        description=f"MFA enabled for {user.email}",
    )

    return jsonify(message="MFA enabled.", mfaEnabled=True), 200


@mfa_bp.post("/verify")
def verify():
    """
    Second-step at login. Body: { mfaToken, code }.
    `code` is either the 6-digit TOTP or one of the user's recovery codes.
    On success, returns the real access token.

    Public route — the mfaToken IS the auth (it was issued by /auth/login
    after successful password). The token is short-lived (5 min).
    """
    body = request.get_json(silent=True) or {}
    mfa_token = (body.get("mfaToken") or "").strip()
    code = (body.get("code") or "").strip()

    if not mfa_token or not code:
        return jsonify(error="mfaToken and code are required"), 400

    user_id = verify_mfa_challenge_token(
        secret_key=current_app.config["SECRET_KEY"],
        token=mfa_token,
    )
    if not user_id:
        return jsonify(
            error="Your sign-in expired. Please enter your password again.",
            code="MFA_TOKEN_EXPIRED",
        ), 401

    user = User.query.get(user_id)
    if not user or not user.mfa_enabled:
        return jsonify(error="Invalid sign-in state.", code="MFA_INVALID_STATE"), 400

    # Try TOTP first, then recovery code
    is_totp = _verify_totp(user, code)
    is_recovery = False if is_totp else _consume_recovery_key(user, code)

    if not (is_totp or is_recovery):
        log_audit(
            organization_id=_audit_org_id_for(user),
            user_id=user.id,
            action="auth.mfa_verify_failed",
            category="auth",
            target_type="user",
            target_id=str(user.id),
            target_label=user.email,
            description=f"MFA verification failed for {user.email}",
        )
        db.session.commit()
        return jsonify(error="Invalid code.", code="MFA_INVALID_CODE"), 401

    db.session.commit()

    log_audit(
        organization_id=_audit_org_id_for(user),
        user_id=user.id,
        action=(
            "auth.mfa_recovery_key_used" if is_recovery else "auth.mfa_verify_success"
        ),
        category="auth",
        target_type="user",
        target_id=str(user.id),
        target_label=user.email,
        description=(
            f"MFA recovery key used by {user.email}"
            if is_recovery
            else f"MFA verified for {user.email}"
        ),
    )

    # Issue the real session — same shape as /auth/login's success path.
    from app.auth.routes import _build_org_payload  # local import avoids circular
    from app.auth.tokens import create_access_token

    token = create_access_token(
        secret_key=current_app.config["SECRET_KEY"], user_id=user.id
    )
    membership = _membership_for(user)
    if membership:
        log_audit(
            organization_id=membership.organization_id,
            user_id=user.id,
            action="auth.login",
            category="auth",
            target_type="user",
            target_id=str(user.id),
            target_label=user.email,
            description=f"User logged in (MFA): {user.email}",
        )

    response: dict = {
        "accessToken": token,
        "user": {
            "id": str(user.id),
            "email": user.email,
            "name": user.name,
            "isSuperadmin": bool(user.is_superadmin),
            "isRootAdmin": bool(user.is_root_admin),
        },
        "viaRecoveryKey": is_recovery,
    }
    if membership:
        response["organization"] = _build_org_payload(membership.organization)
        response["role"] = membership.role

    return jsonify(response), 200


@mfa_bp.post("/disable")
@require_auth
def disable():
    """
    Disable MFA. Requires password reverify (or, for OAuth-only accounts,
    a fresh TOTP) so a stolen JWT alone cannot disable MFA.
    """
    user: User = g.current_user
    body = request.get_json(silent=True) or {}
    password = (body.get("password") or "").strip()
    code = (body.get("code") or "").strip()

    if not user.mfa_enabled:
        return jsonify(error="MFA is not enabled.", code="MFA_NOT_ENABLED"), 400

    # Reauthenticate. Password if the user has one; otherwise require a TOTP.
    if user.password_hash:
        if not password or not check_password_hash(user.password_hash, password):
            return jsonify(error="Password is incorrect.", code="MFA_REAUTH_FAILED"), 401
    else:
        # OAuth-only accounts have no password — a current TOTP is the only
        # local secret they hold.
        if not _verify_totp(user, code):
            return jsonify(error="Invalid code.", code="MFA_REAUTH_FAILED"), 401

    user.mfa_enabled = False
    user.mfa_secret_ciphertext = None
    user.mfa_enrolled_at = None
    UserRecoveryCode.query.filter_by(user_id=user.id).delete()
    db.session.commit()

    log_audit(
        organization_id=_audit_org_id_for(user),
        user_id=user.id,
        action="auth.mfa_disabled",
        category="auth",
        target_type="user",
        target_id=str(user.id),
        target_label=user.email,
        description=f"MFA disabled for {user.email}",
    )

    # Out-of-band notification so a stolen-JWT / phished-password
    # disable can be flagged by the legitimate account holder.
    try:
        from app.auth.emails import send_mfa_reset_notice
        send_mfa_reset_notice(user, by_admin=False)
    except Exception:
        current_app.logger.exception("MFA-disabled notice email failed for user %s", user.id)

    return jsonify(message="MFA disabled.", mfaEnabled=False), 200


@mfa_bp.post("/recovery-key/regenerate")
@require_auth
def regenerate_recovery_key():
    """
    Generate a fresh recovery key. The previous key is invalidated.
    Requires password reverify (same reasoning as /disable).
    """
    user: User = g.current_user
    body = request.get_json(silent=True) or {}
    password = (body.get("password") or "").strip()
    code = (body.get("code") or "").strip()

    if not user.mfa_enabled:
        return jsonify(error="MFA is not enabled.", code="MFA_NOT_ENABLED"), 400

    if user.password_hash:
        if not password or not check_password_hash(user.password_hash, password):
            return jsonify(error="Password is incorrect.", code="MFA_REAUTH_FAILED"), 401
    else:
        if not _verify_totp(user, code):
            return jsonify(error="Invalid code.", code="MFA_REAUTH_FAILED"), 401

    new_key = _generate_recovery_key(user)
    db.session.commit()

    log_audit(
        organization_id=_audit_org_id_for(user),
        user_id=user.id,
        action="auth.mfa_recovery_key_regenerated",
        category="auth",
        target_type="user",
        target_id=str(user.id),
        target_label=user.email,
        description=f"Recovery key regenerated for {user.email}",
    )

    return jsonify(recoveryKey=new_key), 200


@mfa_bp.post("/forced-enroll")
def forced_enroll():
    """
    Enrolment path for users whose role/role-flag requires MFA but who
    haven't enrolled yet. Authenticated by the short-lived mfaToken
    issued by /auth/login (NOT a JWT). Public route.

    Body: { mfaToken }
    Returns the same shape as /auth/mfa/enroll: secret + provisioningUri
    + recoveryKey. The mfaToken stays valid for /forced-enroll/confirm.
    """
    body = request.get_json(silent=True) or {}
    mfa_token = (body.get("mfaToken") or "").strip()
    if not mfa_token:
        return jsonify(error="mfaToken is required"), 400

    user_id = verify_mfa_challenge_token(
        secret_key=current_app.config["SECRET_KEY"],
        token=mfa_token,
    )
    if not user_id:
        return jsonify(
            error="Your sign-in expired. Please enter your password again.",
            code="MFA_TOKEN_EXPIRED",
        ), 401

    user = User.query.get(user_id)
    if not user:
        return jsonify(error="Invalid sign-in state.", code="MFA_INVALID_STATE"), 400
    if user.mfa_enabled:
        # Already enrolled — they should be going through /verify, not this path.
        return jsonify(
            error="MFA is already enabled for this account. Sign in again.",
            code="MFA_ALREADY_ENABLED",
        ), 409

    secret = pyotp.random_base32()
    user.mfa_secret_ciphertext = encrypt_secret(secret)
    user.mfa_enrolled_at = None
    recovery_key = _generate_recovery_key(user)
    db.session.commit()

    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=user.email, issuer_name=TOTP_ISSUER,
    )

    log_audit(
        organization_id=_audit_org_id_for(user),
        user_id=user.id,
        action="auth.mfa_forced_enroll_started",
        category="auth",
        target_type="user",
        target_id=str(user.id),
        target_label=user.email,
        description=f"Forced MFA enrolment started for {user.email}",
    )

    return jsonify(
        secret=secret,
        provisioningUri=provisioning_uri,
        qrCodeDataUrl=_qr_data_url(provisioning_uri),
        recoveryKey=recovery_key,
    ), 200


@mfa_bp.post("/forced-enroll/confirm")
def forced_enroll_confirm():
    """
    Confirm forced enrolment with the first TOTP code, flip mfa_enabled,
    and issue the real session token (same shape as /auth/login success).
    Public route; authenticated by the mfaToken.

    Body: { mfaToken, code }
    """
    body = request.get_json(silent=True) or {}
    mfa_token = (body.get("mfaToken") or "").strip()
    code = (body.get("code") or "").strip()
    if not mfa_token or not code:
        return jsonify(error="mfaToken and code are required"), 400

    user_id = verify_mfa_challenge_token(
        secret_key=current_app.config["SECRET_KEY"],
        token=mfa_token,
    )
    if not user_id:
        return jsonify(
            error="Your sign-in expired. Please enter your password again.",
            code="MFA_TOKEN_EXPIRED",
        ), 401

    user = User.query.get(user_id)
    if not user or not user.mfa_secret_ciphertext or user.mfa_enabled:
        return jsonify(error="Invalid sign-in state.", code="MFA_INVALID_STATE"), 400

    if not _verify_totp(user, code):
        return jsonify(error="Invalid code. Try again.", code="MFA_INVALID_CODE"), 400

    user.mfa_enabled = True
    user.mfa_enrolled_at = _now_utc()
    db.session.commit()

    log_audit(
        organization_id=_audit_org_id_for(user),
        user_id=user.id,
        action="auth.mfa_forced_enroll_completed",
        category="auth",
        target_type="user",
        target_id=str(user.id),
        target_label=user.email,
        description=f"Forced MFA enrolment completed for {user.email}",
    )

    # Issue the real session — symmetric with /auth/mfa/verify success.
    from app.auth.routes import _build_org_payload
    from app.auth.tokens import create_access_token

    token = create_access_token(
        secret_key=current_app.config["SECRET_KEY"], user_id=user.id
    )
    membership = _membership_for(user)
    if membership:
        log_audit(
            organization_id=membership.organization_id,
            user_id=user.id,
            action="auth.login",
            category="auth",
            target_type="user",
            target_id=str(user.id),
            target_label=user.email,
            description=f"User logged in (post forced MFA enrolment): {user.email}",
        )

    response: dict = {
        "accessToken": token,
        "user": {
            "id": str(user.id),
            "email": user.email,
            "name": user.name,
            "isSuperadmin": bool(user.is_superadmin),
            "isRootAdmin": bool(user.is_root_admin),
        },
    }
    if membership:
        response["organization"] = _build_org_payload(membership.organization)
        response["role"] = membership.role
    return jsonify(response), 200


@mfa_bp.get("/status")
@require_auth
def status():
    """
    For the Settings UI. Returns the user's MFA status without leaking
    the secret.
    """
    user: User = g.current_user
    has_recovery_key = (
        user.mfa_enabled
        and UserRecoveryCode.query.filter_by(
            user_id=user.id, used_at=None
        ).count() > 0
    )
    return jsonify(
        mfaEnabled=bool(user.mfa_enabled),
        enrolledAt=(user.mfa_enrolled_at.isoformat() + "Z") if user.mfa_enrolled_at else None,
        recoveryKeyAvailable=bool(has_recovery_key),
        hasPassword=bool(user.password_hash),
    ), 200
