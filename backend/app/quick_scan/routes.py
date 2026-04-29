from __future__ import annotations

import re
import socket
import time
import ipaddress
from typing import Any, Optional, Tuple

from flask import Blueprint, request, jsonify

from app.engine import run_unified_scan

quick_scan_bp = Blueprint("quick_scan", __name__)

ASSET_TYPES = {"domain", "ip"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    v = (value or "").strip().lower()
    if len(v) < 1 or len(v) > 253:
        return False
    if "://" in v or "/" in v:
        return False
    if v.startswith("*."):
        v = v[2:]
    if "." not in v:
        return False
    labels = v.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return False
    if not re.fullmatch(r"[a-z]{2,63}", labels[-1]):
        return False
    return True


def normalize_value(asset_type: str, value: Any) -> str:
    v = (value or "").strip()
    if asset_type == "domain":
        v = v.lower().strip(".")
    return v


def validate(asset_type: str, value: str) -> Tuple[bool, Optional[str]]:
    if asset_type == "ip":
        return (True, None) if is_valid_ip(value) else (False, "invalid IP address format")
    if asset_type == "domain":
        return (True, None) if is_valid_domain(value) else (False, "invalid domain format (domain only, no http/https/path)")
    return False, "type must be domain or ip"


def _get_ip() -> str:
    """Get real client IP, respecting X-Forwarded-For from the nginx proxy."""
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
        from datetime import datetime, timezone

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


@quick_scan_bp.post("/quick-scan")
def quick_scan():
    body = request.get_json(silent=True) or {}
    asset_type = (body.get("type") or "").strip().lower()
    value = normalize_value(asset_type, body.get("value"))
    ip = _get_ip()
    ua = request.headers.get("User-Agent", "")

    if asset_type not in ASSET_TYPES:
        return jsonify(error="type must be domain or ip"), 400

    ok, err = validate(asset_type, value)
    if not ok:
        return jsonify(error=err), 400

    # ── Block list check ─────────────────────────────────────────
    from app.extensions import db
    from app.models import BlockedIP, QuickScanLog
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    block = BlockedIP.query.filter_by(ip_address=ip).first()
    if block and (block.expires_at is None or block.expires_at > now):
        _log_scan(ip=ip, user_agent=ua, target=value, asset_type=asset_type, status="blocked")
        return jsonify(
            error="Your IP address has been blocked from using this service.",
            code="IP_BLOCKED",
        ), 403

    # ── Rate limit: max 5 scans per IP per hour ──────────────────
    RATE_LIMIT = 5
    from datetime import timedelta
    window_start = now - timedelta(hours=1)
    recent_count = QuickScanLog.query.filter(
        QuickScanLog.ip_address == ip,
        QuickScanLog.created_at >= window_start,
        QuickScanLog.status.notin_(["blocked", "rate_limited"]),
    ).count()

    if recent_count >= RATE_LIMIT:
        _log_scan(ip=ip, user_agent=ua, target=value, asset_type=asset_type, status="rate_limited")
        return jsonify(
            error=f"Too many requests. You can run up to {RATE_LIMIT} scans per hour. Please try again later.",
            code="RATE_LIMITED",
        ), 429

    t0 = time.monotonic()
    try:
        result = run_unified_scan(asset_type=asset_type, value=value, max_ips=5)
        duration_ms = int((time.monotonic() - t0) * 1000)

        # Tally findings by severity
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in (result.findings or []):
            sev = (f.get("severity") or "info").lower()
            if sev in counts:
                counts[sev] += 1

        _log_scan(
            ip=ip, user_agent=ua, target=value, asset_type=asset_type,
            status="completed", duration_ms=duration_ms,
            risk_score=result.risk.get("score") if result.risk else None,
            finding_counts=counts,
        )

        return jsonify(
            status="completed",
            assetType=asset_type,
            assetValue=value,
            summary=result.summary,
            risk=result.risk,
            findings=result.findings[:100],
        ), 200

    except Exception as e:
        duration_ms = int((time.monotonic() - t0) * 1000)
        _log_scan(
            ip=ip, user_agent=ua, target=value, asset_type=asset_type,
            status="failed", duration_ms=duration_ms,
            error_message=str(e)[:500],
        )
        return jsonify(status="failed", assetType=asset_type, assetValue=value, error=str(e)), 500


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC QUICK DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_ip(hostname: str) -> list[str]:
    ips: list[str] = []
    try:
        for *_, sockaddr in socket.getaddrinfo(hostname, None):
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def _run_quick_discovery(domain: str) -> dict:
    """
    Lightweight public discovery: CT logs (crt.sh) + apex IP resolution.
    No brute-force — that requires a registered account.
    Returns a dict compatible with DiscoveryDomainResponse on the frontend.
    """
    from app.discovery.modules.ct_logs import CTLogModule

    errors: list[dict] = []
    subdomains: list[str] = []

    # CT logs via crt.sh
    try:
        ct_mod = CTLogModule()
        items = ct_mod.discover(domain, "domain", config={"ct_limit": 2000})
        seen: set[str] = set()
        for item in items:
            val = (item.value or "").strip().lower()
            if val and val != domain and val not in seen:
                seen.add(val)
                subdomains.append(val)
    except Exception as e:
        errors.append({"source": "ct_logs", "error": str(e)[:200]})

    subdomains.sort()

    # Apex IPs
    apex_ips = _resolve_ip(domain)

    # Resolve a sample of subdomains (up to 30) so the card can show IPs
    resolved: dict[str, list[str]] = {}
    for sub in subdomains[:30]:
        ips = _resolve_ip(sub)
        if ips:
            resolved[sub] = ips

    return {
        "status": "completed",
        "domain": domain,
        "counts": {
            "ct": len(subdomains),
            "brute": 0,
            "subdomains": len(subdomains),
            "resolvedNames": len(resolved),
        },
        "subdomains": subdomains[:200],
        "apexIps": apex_ips,
        "resolved": resolved,
        "errors": errors,
    }


@quick_scan_bp.post("/quick-discovery")
def quick_discovery():
    body = request.get_json(silent=True) or {}
    domain_raw = normalize_value("domain", body.get("domain") or body.get("value") or "")
    ip = _get_ip()
    ua = request.headers.get("User-Agent", "")

    ok, err = validate("domain", domain_raw)
    if not ok:
        return jsonify(error=err), 400

    from app.extensions import db
    from app.models import BlockedIP, QuickScanLog
    from datetime import datetime, timezone, timedelta

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    # Block list check
    block = BlockedIP.query.filter_by(ip_address=ip).first()
    if block and (block.expires_at is None or block.expires_at > now):
        _log_scan(ip=ip, user_agent=ua, target=domain_raw, asset_type="domain",
                  source="discovery", status="blocked")
        return jsonify(
            error="Your IP address has been blocked from using this service.",
            code="IP_BLOCKED",
        ), 403

    # Combined rate limit: scan + discovery share the 5/hour budget
    RATE_LIMIT = 5
    window_start = now - timedelta(hours=1)
    recent_count = QuickScanLog.query.filter(
        QuickScanLog.ip_address == ip,
        QuickScanLog.created_at >= window_start,
        QuickScanLog.status.notin_(["blocked", "rate_limited"]),
    ).count()

    if recent_count >= RATE_LIMIT:
        _log_scan(ip=ip, user_agent=ua, target=domain_raw, asset_type="domain",
                  source="discovery", status="rate_limited")
        return jsonify(
            error=f"Too many requests. You can run up to {RATE_LIMIT} scans per hour. Please try again later.",
            code="RATE_LIMITED",
        ), 429

    t0 = time.monotonic()
    try:
        result = _run_quick_discovery(domain_raw)
        duration_ms = int((time.monotonic() - t0) * 1000)
        _log_scan(
            ip=ip, user_agent=ua, target=domain_raw, asset_type="domain",
            source="discovery", status="completed", duration_ms=duration_ms,
            finding_counts={"subdomains": result["counts"]["subdomains"]},
        )
        return jsonify(**result), 200

    except Exception as e:
        duration_ms = int((time.monotonic() - t0) * 1000)
        _log_scan(
            ip=ip, user_agent=ua, target=domain_raw, asset_type="domain",
            source="discovery", status="failed", duration_ms=duration_ms,
            error_message=str(e)[:500],
        )
        return jsonify(status="failed", domain=domain_raw, error=str(e)), 500
