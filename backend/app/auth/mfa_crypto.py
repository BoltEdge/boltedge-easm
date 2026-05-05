# app/auth/mfa_crypto.py
"""
Encryption helpers for the MFA TOTP secret column.

The TOTP shared secret is the crown-jewel of MFA — anyone who has it can
generate valid codes forever. We store it encrypted-at-rest with Fernet
(authenticated symmetric AES-128-CBC + HMAC-SHA256), keyed off
MFA_SECRET_KEY in env.

Operational rules:
  - MFA_SECRET_KEY must be a 32-byte url-safe base64 key. Generate once
    with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
    and put it in .env. Never commit it.
  - Rotating MFA_SECRET_KEY invalidates every enrolled MFA secret in the
    DB — every MFA user has to re-enrol. Avoid rotating unless compromised.
  - Encrypted ciphertext is stored as text in user.mfa_secret_ciphertext.
"""
from __future__ import annotations

import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken


_ENV_VAR = "MFA_SECRET_KEY"


def _fernet() -> Fernet:
    key = os.environ.get(_ENV_VAR, "").strip()
    if not key:
        raise RuntimeError(
            f"{_ENV_VAR} is not set. Generate one with "
            "`python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"` "
            "and add it to .env. MFA cannot be used without it."
        )
    try:
        return Fernet(key.encode("utf-8"))
    except Exception as e:
        raise RuntimeError(
            f"{_ENV_VAR} is not a valid Fernet key. It must be a 32-byte "
            "url-safe base64 string. Original error: " + str(e)
        )


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a TOTP secret. Returns urlsafe ASCII ciphertext."""
    if not plaintext:
        raise ValueError("cannot encrypt empty plaintext")
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext: str) -> Optional[str]:
    """
    Decrypt a stored TOTP secret. Returns None on tampered / unreadable
    ciphertext (caller treats as "MFA misconfigured for this user" rather
    than crashing the request).
    """
    if not ciphertext:
        return None
    try:
        return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeDecodeError):
        return None
