"""Slack signature verification — HMAC-SHA256, 5-min replay window."""
from __future__ import annotations

import hashlib
import hmac
import time

import pytest

from app.agents.slack.signing import verify_signature


SECRET = "test-signing-secret"


def _sign(body: bytes, timestamp: str, secret: str = SECRET) -> str:
    base = f"v0:{timestamp}:".encode() + body
    mac = hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return f"v0={mac}"


def test_valid_signature_passes():
    body = b'{"type":"event_callback"}'
    ts = str(int(time.time()))
    sig = _sign(body, ts)
    headers = {"X-Slack-Signature": sig, "X-Slack-Request-Timestamp": ts}
    assert verify_signature(headers, body, secret=SECRET) is True


def test_tampered_body_fails():
    body = b'{"type":"event_callback"}'
    ts = str(int(time.time()))
    sig = _sign(body, ts)
    headers = {"X-Slack-Signature": sig, "X-Slack-Request-Timestamp": ts}
    assert verify_signature(headers, b'{"tampered":true}', secret=SECRET) is False


def test_old_timestamp_fails():
    body = b'{"type":"event_callback"}'
    ts = str(int(time.time()) - 600)
    sig = _sign(body, ts)
    headers = {"X-Slack-Signature": sig, "X-Slack-Request-Timestamp": ts}
    assert verify_signature(headers, body, secret=SECRET) is False


def test_future_timestamp_fails():
    body = b'{"type":"event_callback"}'
    ts = str(int(time.time()) + 600)
    sig = _sign(body, ts)
    headers = {"X-Slack-Signature": sig, "X-Slack-Request-Timestamp": ts}
    assert verify_signature(headers, body, secret=SECRET) is False


def test_missing_signature_header_fails():
    body = b'{"type":"event_callback"}'
    ts = str(int(time.time()))
    headers = {"X-Slack-Request-Timestamp": ts}
    assert verify_signature(headers, body, secret=SECRET) is False


def test_missing_timestamp_header_fails():
    body = b'{"type":"event_callback"}'
    ts = str(int(time.time()))
    headers = {"X-Slack-Signature": _sign(body, ts)}
    assert verify_signature(headers, body, secret=SECRET) is False


def test_empty_secret_fails():
    body = b'{"type":"event_callback"}'
    ts = str(int(time.time()))
    headers = {"X-Slack-Signature": _sign(body, ts), "X-Slack-Request-Timestamp": ts}
    assert verify_signature(headers, body, secret="") is False
