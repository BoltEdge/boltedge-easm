from __future__ import annotations

from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import request, jsonify


def _get_ip() -> str:
    """Real client IP, respecting X-Forwarded-For from the nginx proxy."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _log_scan(ip: str, user_agent: str, target: str, asset_type: str,
              status: str, source: str = "scan",
              duration_ms: int | None = None,
              risk_score: float | None = None,
              finding_counts: dict | None = None,
              error_message: str | None = None) -> None:
    """Write a QuickScanLog row. Wrapped in try/except — never raises."""
    try:
        from app.extensions import db
        from app.models import QuickScanLog

        entry = QuickScanLog(
            ip_address=ip,
            user_agent=(user_agent or "")[:500] or None,
            target=target,
            asset_type=asset_type,
            source=source,
            status=status,
            duration_ms=duration_ms,
            risk_score=risk_score,
            finding_counts=finding_counts,
            error_message=(error_message or "")[:500] or None,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        try:
            from app.extensions import db
            db.session.rollback()
        except Exception:
            pass


def public_abuse_check(*, source: str, limit: int, label: str):
    """Decorator: block-list + rate-limit guard for public endpoints.

    Each public scan/discovery/tool endpoint has its own QuickScanLog source
    bucket so hitting the cap on one doesn't lock out the others. Rejects
    are logged with status `blocked` / `rate_limited`; the decorated
    function only runs for visitors that pass both checks.
    """
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            from app.models import BlockedIP, QuickScanLog

            body = request.get_json(silent=True) or {}
            ip = _get_ip()
            ua = request.headers.get("User-Agent", "")
            target = ((body.get("value") or body.get("domain") or body.get("query")
                       or body.get("ip") or body.get("host") or body.get("hash") or "")[:200]) or "-"
            asset_type = (body.get("type") or "-")[:32]
            now = datetime.now(timezone.utc).replace(tzinfo=None)

            block = BlockedIP.query.filter_by(ip_address=ip).first()
            if block and (block.expires_at is None or block.expires_at > now):
                _log_scan(ip=ip, user_agent=ua, target=target, asset_type=asset_type,
                          source=source, status="blocked")
                return jsonify(
                    error="Your IP address has been blocked from using this service.",
                    code="IP_BLOCKED",
                ), 403

            window_start = now - timedelta(hours=1)
            recent = QuickScanLog.query.filter(
                QuickScanLog.ip_address == ip,
                QuickScanLog.source == source,
                QuickScanLog.created_at >= window_start,
                QuickScanLog.status.notin_(["blocked", "rate_limited"]),
            ).count()
            if recent >= limit:
                _log_scan(ip=ip, user_agent=ua, target=target, asset_type=asset_type,
                          source=source, status="rate_limited")
                return jsonify(
                    error=f"Too many {label}. You can run up to {limit} {label} per hour from this IP. Please try again later. Sign up for free for more {label}.",
                    code="RATE_LIMITED",
                ), 429

            return fn(*args, **kwargs)
        return wrapper
    return deco
