# app/auth/tokens.py
from __future__ import annotations

from typing import Optional
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


# Token expiry: 8 hours absolute max
DEFAULT_MAX_AGE = 60 * 60 * 8  # 8 hours

def _serializer(secret_key: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret_key, salt="boltedgeeasm-auth")


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
        # Token was valid but has expired
        return None
    except BadSignature:
        # Token is invalid / tampered
        return None