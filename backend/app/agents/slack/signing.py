"""Slack signing-secret verification (HMAC-SHA256, 5-min replay window)."""
from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Mapping


REPLAY_WINDOW_SECONDS = 300  # 5 minutes per Slack docs


def verify_signature(
    headers: Mapping[str, str],
    raw_body: bytes,
    secret: str | None = None,
) -> bool:
    """Return True iff the request bears a valid Slack signature.

    Always returns False when secret is empty/None (no secret means no trust).
    """
    if secret is None:
        secret = os.environ.get("SLACK_SIGNING_SECRET_AGENTS", "")
    if not secret:
        return False

    sig_header = headers.get("X-Slack-Signature")
    ts_header = headers.get("X-Slack-Request-Timestamp")
    if not sig_header or not ts_header:
        return False

    try:
        ts = int(ts_header)
    except ValueError:
        return False

    now = int(time.time())
    if abs(now - ts) > REPLAY_WINDOW_SECONDS:
        return False

    base = f"v0:{ts}:".encode() + raw_body
    expected = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_header)
