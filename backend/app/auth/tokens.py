# app/auth/tokens.py
from __future__ import annotations

from typing import Optional
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


# Token expiry: 8 hours absolute max
DEFAULT_MAX_AGE = 60 * 60 * 8  # 8 hours

RESET_TOKEN_MAX_AGE = 60 * 60 * 24  # 24 hours

def _serializer(secret_key: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret_key, salt="nanoasm-auth")

def _reset_serializer(secret_key: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret_key, salt="nanoasm-password-reset")


def create_access_token(*, secret_key: str, user_id: int) -> str:
    return _serializer(secret_key).dumps({"user_id": int(user_id)})


def verify_access_token(
    *, secret_key: str, token: str, max_age_seconds: int = DEFAULT_MAX_AGE
) -> Optional[int]:
    """
    Verify a token and return the user_id, or None if invalid/expired.
    """
    try:
        data = _serializer(secret_key).loads(token, max_age=max_age_seconds)
        uid = data.get("user_id")
        return int(uid) if uid is not None else None
    except SignatureExpired:
        return None
    except BadSignature:
        return None


def create_password_reset_token(*, secret_key: str, user_id: int, email: str) -> str:
    """Create a 24-hour signed password-reset token."""
    return _reset_serializer(secret_key).dumps({"user_id": int(user_id), "email": email})


def verify_password_reset_token(
    *, secret_key: str, token: str
) -> Optional[dict]:
    """
    Verify a password-reset token. Returns {"user_id": int, "email": str} or None.
    """
    try:
        data = _reset_serializer(secret_key).loads(token, max_age=RESET_TOKEN_MAX_AGE)
        if "user_id" not in data or "email" not in data:
            return None
        return {"user_id": int(data["user_id"]), "email": data["email"]}
    except (SignatureExpired, BadSignature):
        return None