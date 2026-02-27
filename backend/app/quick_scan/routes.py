from __future__ import annotations

import re
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


@quick_scan_bp.post("/quick-scan")
def quick_scan():
    body = request.get_json(silent=True) or {}
    asset_type = (body.get("type") or "").strip().lower()
    value = normalize_value(asset_type, body.get("value"))

    if asset_type not in ASSET_TYPES:
        return jsonify(error="type must be domain or ip"), 400

    ok, err = validate(asset_type, value)
    if not ok:
        return jsonify(error=err), 400

    try:
        result = run_unified_scan(asset_type=asset_type, value=value, max_ips=5)
        return jsonify(
            status="completed",
            assetType=asset_type,
            assetValue=value,
            summary=result.summary,
            risk=result.risk,
            findings=result.findings[:100],
        ), 200
    except Exception as e:
        return jsonify(status="failed", assetType=asset_type, assetValue=value, error=str(e)), 500
