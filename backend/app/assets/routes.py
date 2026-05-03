# =============================================================================
# File: app/assets/routes.py
# Description: Asset and Asset Group routes for managing organizational assets.
#
# Permissions Integration (based on permissions integration guide):
#   - GET endpoints (list/view): all authenticated roles can access
#   - POST /groups/<id>/assets (single add): analyst+ with asset limit check
#   - POST /groups/<id>/assets/bulk: requires bulk_add_assets permission (admin+) with asset limit check
#   - PATCH /assets/<id>: analyst+
#   - DELETE /assets/<id>: analyst+
#   - GET /assets/export, GET /groups/export: requires export_assets permission (admin+)
# =============================================================================

from __future__ import annotations

import re
import ipaddress
import socket
from typing import Any, Dict, Optional, Tuple, List
from urllib.parse import urlparse

import csv
from datetime import datetime
from io import StringIO

from flask import Blueprint, request, jsonify, Response
from sqlalchemy import func, case, desc

from app.extensions import db
from app.models import Asset, AssetGroup, Finding, ScanJob
from app.audit.routes import log_audit
from app.auth.decorators import require_auth, allow_api_key, current_user_id, current_organization_id
from app.auth.permissions import (
    require_role,
    require_permission,
    check_limit,
)

assets_bp = Blueprint("assets", __name__)  # no global prefix; we define full paths below

ASSET_TYPES = {"domain", "ip", "email", "cloud"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ═══════════════════════════════════════════════════════════════
# Cloud URL → Provider / Category Detection
# ═══════════════════════════════════════════════════════════════

# Each entry: (url_pattern_regex, provider_key, cloud_category)
CLOUD_URL_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    # ── Storage ──
    (re.compile(r"\.s3[.\-]amazonaws\.com", re.I),           "aws_s3",           "storage"),
    (re.compile(r"s3://", re.I),                              "aws_s3",           "storage"),
    (re.compile(r"\.blob\.core\.windows\.net", re.I),         "azure_blob",       "storage"),
    (re.compile(r"storage\.googleapis\.com", re.I),           "gcs",              "storage"),
    (re.compile(r"\.storage\.googleapis\.com", re.I),         "gcs",              "storage"),
    (re.compile(r"gs://", re.I),                              "gcs",              "storage"),
    # ── Container Registries ──
    (re.compile(r"\.azurecr\.io", re.I),                      "acr",              "registry"),
    (re.compile(r"gcr\.io/", re.I),                           "gcr",              "registry"),
    (re.compile(r"\.pkg\.dev", re.I),                         "gcr",              "registry"),  # Artifact Registry
    (re.compile(r"public\.ecr\.aws", re.I),                   "ecr_public",       "registry"),
    (re.compile(r"\.dkr\.ecr\.", re.I),                       "ecr",              "registry"),
    (re.compile(r"hub\.docker\.com", re.I),                   "dockerhub",        "registry"),
    (re.compile(r"docker\.io/", re.I),                        "dockerhub",        "registry"),
    # ── Serverless ──
    (re.compile(r"\.azurewebsites\.net", re.I),               "azure_functions",  "serverless"),
    (re.compile(r"\.run\.app", re.I),                         "cloud_run",        "serverless"),
    (re.compile(r"\.cloudfunctions\.net", re.I),              "cloud_functions",  "serverless"),
    (re.compile(r"\.lambda-url\.", re.I),                     "aws_lambda",       "serverless"),
    (re.compile(r"\.execute-api\.", re.I),                    "aws_apigateway",   "serverless"),
    # ── CDN ──
    (re.compile(r"\.cloudfront\.net", re.I),                  "cloudfront",       "cdn"),
    (re.compile(r"\.azureedge\.net", re.I),                   "azure_cdn",        "cdn"),
    (re.compile(r"\.azurefd\.net", re.I),                     "azure_cdn",        "cdn"),
    (re.compile(r"\.fastly\.net", re.I),                      "fastly",           "cdn"),
    (re.compile(r"\.akamaiedge\.net", re.I),                  "akamai",           "cdn"),
    (re.compile(r"\.edgekey\.net", re.I),                     "akamai",           "cdn"),
]


def detect_cloud_provider(url: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Detect cloud provider and category from a URL.
    Returns (provider, cloud_category) or (None, None) if not recognized.
    """
    for pattern, provider, category in CLOUD_URL_PATTERNS:
        if pattern.search(url):
            return provider, category
    return None, None


def is_valid_cloud_url(value: str) -> bool:
    """Validate that a cloud URL is a plausible cloud resource URL."""
    v = value.strip()
    # Allow scheme-prefixed URIs like s3:// and gs://
    if v.startswith("s3://") or v.startswith("gs://"):
        return len(v) > 5
    # Otherwise must look like a URL or hostname
    if "://" not in v:
        v = "https://" + v
    try:
        parsed = urlparse(v)
        # Must have a host with at least one dot
        host = parsed.hostname or ""
        if "." not in host:
            return False
        if len(host) < 4 or len(host) > 253:
            return False
        return True
    except Exception:
        return False


def normalize_cloud_url(value: str) -> str:
    """Normalize a cloud URL for storage."""
    v = value.strip()
    # Keep s3:// and gs:// as-is
    if v.lower().startswith("s3://") or v.lower().startswith("gs://"):
        return v
    # Strip trailing slashes
    v = v.rstrip("/")
    # Ensure https:// prefix for web URLs
    if not v.startswith("http://") and not v.startswith("https://"):
        v = "https://" + v
    return v


def resolve_domain_ips(domain: str) -> List[str]:
    """
    Resolve domain to IP addresses
    Returns list of IPs or empty list if resolution fails
    """
    try:
        # Get all IP addresses for the domain
        addr_info = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips = list(set([addr[4][0] for addr in addr_info]))
        return ips[:5]  # Limit to 5 IPs max
    except (socket.gaierror, socket.timeout):
        return []


def _sid(x) -> str:
    return str(x) if x is not None else ""


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_email(value: str) -> bool:
    return EMAIL_RE.match(value or "") is not None


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


def validate_asset_value(asset_type: str, value: str) -> Tuple[bool, Optional[str]]:
    if asset_type == "ip":
        if not is_valid_ip(value):
            return False, "invalid IP address format"
    elif asset_type == "email":
        if not is_valid_email(value):
            return False, "invalid email format"
    elif asset_type == "domain":
        if not is_valid_domain(value):
            return False, "invalid domain format (domain only, no http/https/path)"
    elif asset_type == "cloud":
        if not is_valid_cloud_url(value):
            return False, "invalid cloud URL — provide a full URL (e.g. https://mybucket.s3.amazonaws.com)"
    else:
        return False, "type must be one of: domain, ip, email, cloud"
    return True, None


def normalize_asset_value(asset_type: str, value: Any) -> str:
    v = (value or "").strip()
    if asset_type in {"domain", "email"}:
        v = v.lower()
    if asset_type == "domain":
        v = v.strip(".")
    if asset_type == "cloud":
        v = normalize_cloud_url(v)
    return v


def asset_to_ui(a: Asset) -> Dict[str, Any]:
    result = {
        "id": _sid(a.id),
        "displayId": a.public_id,
        "groupId": _sid(a.group_id),
        "type": a.asset_type,
        "value": a.value,
        "label": a.label,
        "createdAt": a.created_at.isoformat() if a.created_at else None,
    }
    # Include cloud-specific fields when present
    if a.provider:
        result["provider"] = a.provider
    if a.cloud_category:
        result["cloudCategory"] = a.cloud_category
    return result


# ---------------------------
# Group Assets
# ---------------------------

# GET /groups/<id>/assets — all roles can view
@assets_bp.get("/groups/<group_id>/assets")
@require_auth
@allow_api_key
def list_group_assets(group_id: str):
    uid = current_user_id()
    org_id = current_organization_id()

    # Check group belongs to organization
    g1 = AssetGroup.query.filter_by(id=int(group_id), organization_id=org_id).first()
    if not g1 or not g1.is_active:
        return jsonify(error="group not found"), 404

    # Get assets in this group for this organization
    assets = (
        Asset.query.filter(Asset.group_id == g1.id, Asset.organization_id == org_id)
        .order_by(Asset.id.desc())
        .all()
    )

    out = []
    for a in assets:
        item = {
            "id": str(a.id),
            "displayId": a.public_id,
            "groupId": str(a.group_id),
            "groupDisplayId": g1.public_id,
            "groupName": g1.name,
            "type": a.asset_type,
            "value": a.value,
            "label": a.label,
            "createdAt": a.created_at.isoformat() if a.created_at else None,
            "status": a.scan_status or "never_scanned",
            "lastScanAt": a.last_scan_at.isoformat() if a.last_scan_at else None,
            "latestScanId": None,
        }
        if a.provider:
            item["provider"] = a.provider
        if a.cloud_category:
            item["cloudCategory"] = a.cloud_category
        out.append(item)

    return jsonify(out), 200


# ═══════════════════════════════════════════════════════════════
# CSV export — group assets
# ═══════════════════════════════════════════════════════════════
#
# GET /groups/<id>/assets/export?columns=display_id,type,value,...
#
# Returns text/csv with the columns the caller selected (or the
# Standard preset if no `columns` query is provided). Open-format
# export so the user can pull their own data into spreadsheets,
# CRMs, or compliance reports without API integration.

# Catalogue of every column we know how to render. Each entry is
# (header label, value extractor). The extractor receives the Asset
# row plus a precomputed `ctx` dict with shared lookups (group,
# findings counts, monitored asset IDs) — this keeps per-asset work
# O(1) even on large groups.
_EXPORT_COLUMNS: dict[str, tuple[str, callable]] = {
    "display_id":       ("Display ID",      lambda a, ctx: a.public_id or ""),
    "type":             ("Type",            lambda a, ctx: a.asset_type or ""),
    "value":            ("Value",           lambda a, ctx: a.value or ""),
    "label":            ("Label",           lambda a, ctx: a.label or ""),
    "group":            ("Group",           lambda a, ctx: ctx["group_name"]),
    "added_on":         ("Added on",        lambda a, ctx: a.created_at.strftime("%Y-%m-%d") if a.created_at else ""),
    "last_scan_at":     ("Last scan",       lambda a, ctx: a.last_scan_at.strftime("%Y-%m-%d %H:%M") if a.last_scan_at else ""),
    "scan_status":      ("Scan status",     lambda a, ctx: a.scan_status or "never_scanned"),
    "findings_total":   ("Findings",        lambda a, ctx: ctx["findings"].get(a.id, {}).get("total", 0)),
    "findings_critical":("Critical",        lambda a, ctx: ctx["findings"].get(a.id, {}).get("critical", 0)),
    "findings_high":    ("High",            lambda a, ctx: ctx["findings"].get(a.id, {}).get("high", 0)),
    "findings_medium":  ("Medium",          lambda a, ctx: ctx["findings"].get(a.id, {}).get("medium", 0)),
    "findings_low":     ("Low",             lambda a, ctx: ctx["findings"].get(a.id, {}).get("low", 0)),
    "findings_info":    ("Info",            lambda a, ctx: ctx["findings"].get(a.id, {}).get("info", 0)),
    "provider":         ("Provider",        lambda a, ctx: a.provider or ""),
    "cloud_category":   ("Cloud category",  lambda a, ctx: a.cloud_category or ""),
    "monitored":        ("Monitored",       lambda a, ctx: "yes" if a.id in ctx["monitored_ids"] else "no"),
}

_EXPORT_PRESETS: dict[str, list[str]] = {
    "essentials": ["display_id", "type", "value", "label"],
    "standard":   ["display_id", "type", "value", "label", "group", "last_scan_at", "scan_status", "findings_total"],
    "all":        list(_EXPORT_COLUMNS.keys()),
}


def _resolve_export_columns(raw: Optional[str]) -> list[str]:
    """
    Translate the `columns` query string into a validated list of
    column keys. Accepts a preset name ("essentials"/"standard"/"all")
    or a comma-separated list of explicit columns. Unknown columns
    are silently dropped. Falls back to the Standard preset when
    nothing usable is provided.
    """
    if not raw:
        return _EXPORT_PRESETS["standard"]
    raw = raw.strip().lower()
    if raw in _EXPORT_PRESETS:
        return _EXPORT_PRESETS[raw]
    cols = [c.strip() for c in raw.split(",") if c.strip()]
    cols = [c for c in cols if c in _EXPORT_COLUMNS]
    return cols or _EXPORT_PRESETS["standard"]


def _slugify_for_filename(s: str) -> str:
    """Make a filename-safe slug from a group name."""
    s = re.sub(r"[^a-zA-Z0-9]+", "-", (s or "").strip().lower())
    return s.strip("-") or "group"


# GET /groups/<id>/assets/export — all roles can export their org's data
@assets_bp.get("/groups/<group_id>/assets/export")
@require_auth
@allow_api_key
def export_group_assets(group_id: str):
    org_id = current_organization_id()

    g1 = AssetGroup.query.filter_by(id=int(group_id), organization_id=org_id).first()
    if not g1 or not g1.is_active:
        return jsonify(error="group not found"), 404

    columns = _resolve_export_columns(request.args.get("columns"))

    assets = (
        Asset.query.filter(Asset.group_id == g1.id, Asset.organization_id == org_id)
        .order_by(Asset.id.asc())
        .all()
    )
    asset_ids = [a.id for a in assets]

    # ── Precompute shared lookups so each row render is O(1) ──
    findings_by_asset: dict[int, dict[str, int]] = {}
    if asset_ids and any(c.startswith("findings_") for c in columns):
        rows = (
            db.session.query(
                Finding.asset_id, Finding.severity, func.count(Finding.id)
            )
            .filter(Finding.asset_id.in_(asset_ids))
            .group_by(Finding.asset_id, Finding.severity)
            .all()
        )
        for asset_id, severity, count in rows:
            bucket = findings_by_asset.setdefault(
                asset_id, {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            )
            sev_key = (severity or "info").lower()
            if sev_key in bucket:
                bucket[sev_key] = count
            bucket["total"] += count

    monitored_ids: set[int] = set()
    if asset_ids and "monitored" in columns:
        from app.models import Monitor
        monitor_rows = (
            db.session.query(Monitor.asset_id)
            .filter(Monitor.organization_id == org_id, Monitor.enabled == True, Monitor.asset_id.in_(asset_ids))
            .all()
        )
        monitored_ids = {row[0] for row in monitor_rows if row[0] is not None}

    ctx = {
        "group_name": g1.name,
        "findings": findings_by_asset,
        "monitored_ids": monitored_ids,
    }

    # ── Render CSV ──
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow([_EXPORT_COLUMNS[c][0] for c in columns])
    for asset in assets:
        writer.writerow([_EXPORT_COLUMNS[c][1](asset, ctx) for c in columns])

    # Audit — exports are sensitive enough to log who took what.
    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="assets.exported",
        category="assets",
        target_type="asset_group",
        target_id=str(g1.id),
        target_label=g1.name,
        description=f"Exported {len(assets)} assets from group '{g1.name}' as CSV",
        metadata={"row_count": len(assets), "columns": columns},
    )

    today = datetime.utcnow().strftime("%Y-%m-%d")
    filename = f"assets-{_slugify_for_filename(g1.name)}-{today}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


# POST /groups/<id>/assets — analyst+ (single add) with asset limit check
@assets_bp.post("/groups/<group_id>/assets")
@require_auth
@allow_api_key
@require_role("analyst")
@check_limit("assets")
def add_asset_to_group(group_id: str):
    uid = current_user_id()
    org_id = current_organization_id()

    # Check group belongs to organization
    g1 = AssetGroup.query.filter_by(id=int(group_id), organization_id=org_id).first()
    if not g1 or not g1.is_active:
        return jsonify(error="group not found"), 404

    body = request.get_json(silent=True) or {}
    asset_type = (body.get("type") or body.get("asset_type") or "").strip().lower()
    if asset_type not in ASSET_TYPES:
        return jsonify(error="type must be one of: domain, ip, email, cloud"), 400

    value = normalize_asset_value(asset_type, body.get("value"))
    label = (body.get("label") or "").strip() or None

    ok, err = validate_asset_value(asset_type, value)
    if not ok:
        return jsonify(error=err), 400

    # For cloud assets: detect provider and category from URL
    provider = None
    cloud_category = None
    if asset_type == "cloud":
        provider, cloud_category = detect_cloud_provider(value)
        # Allow explicit overrides from request body
        provider = (body.get("provider") or provider or "other")
        cloud_category = (body.get("cloudCategory") or body.get("cloud_category") or cloud_category or "storage")

    # Check if asset already exists in this organization
    existing = Asset.query.filter_by(
        organization_id=org_id,
        asset_type=asset_type,
        value=value
    ).first()

    if existing:
        # Move it to this group
        old_group_id = existing.group_id
        existing.group_id = g1.id
        existing.label = label or existing.label
        existing.user_id = uid
        # Update cloud fields if provided
        if asset_type == "cloud":
            existing.provider = provider or existing.provider
            existing.cloud_category = cloud_category or existing.cloud_category

        log_audit(
            organization_id=org_id,
            user_id=uid,
            action="asset.moved",
            category="asset",
            target_type="asset",
            target_id=str(existing.id),
            target_label=existing.value,
            description=f"Moved asset '{existing.value}' to group '{g1.name}'",
            metadata={"type": asset_type, "old_group_id": str(old_group_id), "new_group_id": str(g1.id), "group_name": g1.name},
        )
        db.session.commit()

        return jsonify(asset_to_ui(existing)), 200

    # Create new asset
    a1 = Asset(
        user_id=uid,
        organization_id=org_id,
        asset_type=asset_type,
        value=value,
        label=label,
        group_id=g1.id,
        provider=provider,
        cloud_category=cloud_category,
    )
    db.session.add(a1)
    db.session.flush()  # get the ID before logging

    log_audit(
        organization_id=org_id,
        user_id=uid,
        action="asset.created",
        category="asset",
        target_type="asset",
        target_id=str(a1.id),
        target_label=a1.value,
        description=f"Added {asset_type} asset '{value}' to group '{g1.name}'",
        metadata={
            "type": asset_type, "group_id": str(g1.id), "group_name": g1.name,
            **({"provider": provider, "cloudCategory": cloud_category} if asset_type == "cloud" else {}),
        },
    )
    db.session.commit()

    return jsonify(asset_to_ui(a1)), 201


# POST /groups/<id>/assets/bulk — admin+ only (bulk_add_assets permission) with asset limit check
@assets_bp.post("/groups/<group_id>/assets/bulk")
@require_auth
@allow_api_key
@require_permission("bulk_add_assets")
@check_limit("assets")
def bulk_add_assets(group_id: str):
    """Add multiple assets at once. Accepts a list of values, auto-detects types."""
    uid = current_user_id()
    org_id = current_organization_id()

    g1 = AssetGroup.query.filter_by(id=int(group_id), organization_id=org_id).first()
    if not g1 or not g1.is_active:
        return jsonify(error="group not found"), 404

    body = request.get_json(silent=True) or {}
    items = body.get("items", [])  # [{ value, type?, label? }, ...]

    if not items or not isinstance(items, list):
        return jsonify(error="items array is required"), 400

    if len(items) > 200:
        return jsonify(error="Maximum 200 assets per batch"), 400

    results = []
    added = 0
    skipped = 0
    errors = 0

    for item in items:
        value_raw = (item.get("value") or "").strip()
        if not value_raw:
            results.append({"value": value_raw, "status": "error", "reason": "empty value"})
            errors += 1
            continue

        # Auto-detect type if not provided
        asset_type = (item.get("type") or "").strip().lower()
        if not asset_type:
            asset_type = _detect_asset_type(value_raw)

        if asset_type not in ASSET_TYPES:
            results.append({"value": value_raw, "status": "error", "reason": "unknown type"})
            errors += 1
            continue

        value = normalize_asset_value(asset_type, value_raw)
        label = (item.get("label") or "").strip() or None

        # Validate format
        ok, err = validate_asset_value(asset_type, value)
        if not ok:
            results.append({"value": value_raw, "type": asset_type, "status": "error", "reason": err})
            errors += 1
            continue

        # Detect cloud provider/category
        provider = None
        cloud_category = None
        if asset_type == "cloud":
            provider, cloud_category = detect_cloud_provider(value)
            provider = provider or "other"
            cloud_category = cloud_category or "storage"

        # Check for existing asset in org
        existing = Asset.query.filter_by(
            organization_id=org_id,
            asset_type=asset_type,
            value=value,
        ).first()

        if existing:
            # Move to this group if in a different group
            if existing.group_id != g1.id:
                existing.group_id = g1.id
                existing.user_id = uid
                if label:
                    existing.label = label
                if asset_type == "cloud":
                    existing.provider = provider or existing.provider
                    existing.cloud_category = cloud_category or existing.cloud_category
                results.append({"value": value, "type": asset_type, "status": "moved", "id": str(existing.id)})
            else:
                results.append({"value": value, "type": asset_type, "status": "duplicate"})
            skipped += 1
            continue

        # Create new
        a = Asset(
            user_id=uid,
            organization_id=org_id,
            asset_type=asset_type,
            value=value,
            label=label,
            group_id=g1.id,
            provider=provider,
            cloud_category=cloud_category,
        )
        db.session.add(a)
        db.session.flush()  # get ID
        results.append({"value": value, "type": asset_type, "status": "added", "id": str(a.id)})
        added += 1

    log_audit(
        organization_id=org_id,
        user_id=uid,
        action="asset.bulk_added",
        category="asset",
        target_type="asset_group",
        target_id=str(g1.id),
        target_label=g1.name,
        description=f"Bulk added {added} assets to group '{g1.name}' ({skipped} skipped, {errors} errors)",
        metadata={"added": added, "skipped": skipped, "errors": errors, "group_id": str(g1.id), "group_name": g1.name},
    )
    db.session.commit()

    return jsonify(
        added=added,
        skipped=skipped,
        errors=errors,
        total=len(items),
        results=results,
    ), 201


# ---------------------------
# Assets (global)
# ---------------------------

# GET /assets — all roles can view
@assets_bp.get("/assets")
@require_auth
@allow_api_key
def list_assets():
    org_id = current_organization_id()

    # Build query
    query = (
        db.session.query(Asset)
        .join(AssetGroup, Asset.group_id == AssetGroup.id)
        .filter(
            Asset.organization_id == org_id,
            AssetGroup.organization_id == org_id,
            AssetGroup.is_active.is_(True),
        )
    )

    # Optional filters
    type_filter = request.args.get("type")
    if type_filter and type_filter in ASSET_TYPES:
        query = query.filter(Asset.asset_type == type_filter)

    provider_filter = request.args.get("provider")
    if provider_filter:
        query = query.filter(Asset.provider == provider_filter)

    cloud_category_filter = request.args.get("cloudCategory") or request.args.get("cloud_category")
    if cloud_category_filter:
        query = query.filter(Asset.cloud_category == cloud_category_filter)

    assets = query.order_by(Asset.id.desc()).all()

    out = []
    for a in assets:
        item = {
            "id": str(a.id),
            "groupId": str(a.group_id),
            "type": a.asset_type,
            "value": a.value,
            "label": a.label,
            "status": a.scan_status or "never_scanned",
            "lastScanAt": a.last_scan_at.isoformat() if a.last_scan_at else None,
            "latestScanId": None,
        }
        if a.provider:
            item["provider"] = a.provider
        if a.cloud_category:
            item["cloudCategory"] = a.cloud_category
        out.append(item)

    return jsonify(out), 200


# GET /assets/<id> — all roles can view
@assets_bp.get("/assets/<asset_id>")
@require_auth
@allow_api_key
def get_asset(asset_id: str):
    org_id = current_organization_id()

    a1 = Asset.query.filter_by(id=int(asset_id), organization_id=org_id).first()
    if not a1:
        return jsonify(error="asset not found"), 404

    result = asset_to_ui(a1)

    if a1.asset_type == "domain":
        resolved_ips = resolve_domain_ips(a1.value)
        result["resolvedIps"] = resolved_ips

    return jsonify(result), 200


# PATCH /assets/<id> — analyst+
@assets_bp.patch("/assets/<asset_id>")
@require_auth
@allow_api_key
@require_role("analyst")
def update_asset(asset_id: str):
    uid = current_user_id()
    org_id = current_organization_id()

    a1 = Asset.query.filter_by(id=int(asset_id), organization_id=org_id).first()
    if not a1:
        return jsonify(error="asset not found"), 404

    body = request.get_json(silent=True) or {}
    label = body.get("label")
    value = body.get("value")

    changes = {}

    if label is not None:
        old_label = a1.label
        a1.label = (label or "").strip() or None
        if old_label != a1.label:
            changes["label"] = {"old": old_label, "new": a1.label}

    if value is not None:
        asset_type = a1.asset_type
        new_value = normalize_asset_value(asset_type, value)

        ok, err = validate_asset_value(asset_type, new_value)
        if not ok:
            return jsonify(error=err), 400

        clash = Asset.query.filter(
            Asset.organization_id == org_id,
            Asset.id != a1.id,
            Asset.asset_type == asset_type,
            Asset.value == new_value,
        ).first()
        if clash:
            return jsonify(error="another asset already uses that value"), 409

        old_value = a1.value
        a1.value = new_value
        if old_value != new_value:
            changes["value"] = {"old": old_value, "new": new_value}

        # Re-detect cloud provider if value changed on a cloud asset
        if asset_type == "cloud" and old_value != new_value:
            provider, cloud_category = detect_cloud_provider(new_value)
            a1.provider = provider or a1.provider
            a1.cloud_category = cloud_category or a1.cloud_category

    a1.user_id = uid

    if changes:
        log_audit(
            organization_id=org_id,
            user_id=uid,
            action="asset.updated",
            category="asset",
            target_type="asset",
            target_id=str(a1.id),
            target_label=a1.value,
            description=f"Updated asset '{a1.value}'",
            metadata={"changes": changes},
        )

    db.session.commit()
    return jsonify(asset_to_ui(a1)), 200


# DELETE /assets/<id> — analyst+
@assets_bp.delete("/assets/<asset_id>")
@require_auth
@allow_api_key
@require_role("analyst")
def delete_asset(asset_id: str):
    org_id = current_organization_id()

    a1 = Asset.query.filter_by(id=int(asset_id), organization_id=org_id).first()
    if not a1:
        return jsonify(error="asset not found"), 404

    # Capture details before deletion
    asset_value = a1.value
    asset_type = a1.asset_type
    asset_id_str = str(a1.id)
    group_id = str(a1.group_id) if a1.group_id else None

    # Log BEFORE delete — flush attaches to the same transaction
    log_audit(
        organization_id=org_id,
        user_id=current_user_id(),
        action="asset.deleted",
        category="asset",
        target_type="asset",
        target_id=asset_id_str,
        target_label=asset_value,
        description=f"Deleted {asset_type} asset '{asset_value}'",
        metadata={"type": asset_type, "group_id": group_id},
    )

    db.session.delete(a1)
    db.session.commit()
    return jsonify(message="deleted", assetId=_sid(asset_id)), 200


# GET /assets/<id>/overview — "At a glance" summary card.
#
# Pulls together the assorted fragments scattered across /risk,
# /coverage, /timeline etc. into a single payload optimised for the
# overview panel at the top of the asset detail page. Pure
# templated rendering — no LLM, no new analysis. Shape:
#
#   {
#     "asset":     { displayId, type, value, label, group, addedOn, ageDays },
#     "scan":      { lastScanAt, lastScanProfile, scanStatus, totalScans },
#     "findings":  { total, open, bySeverity, topOpen },
#     "monitor":   { enabled, frequency, lastCheckedAt, nextCheckAt },
#     "recommendations": [ "…", "…" ]   # at most 5, ordered by importance
#   }
@assets_bp.get("/assets/<asset_id>/overview")
@require_auth
@allow_api_key
def asset_overview(asset_id: str):
    org_id = current_organization_id()

    asset = Asset.query.filter_by(id=int(asset_id), organization_id=org_id).first()
    if not asset:
        return jsonify(error="asset not found"), 404

    from sqlalchemy import or_, and_
    from app.models import ScanJob, Monitor

    now = datetime.utcnow()

    group = AssetGroup.query.get(asset.group_id) if asset.group_id else None

    age_days = (now - asset.created_at).days if asset.created_at else None

    # ── Findings (open only, by severity) ──
    open_filter = and_(
        or_(Finding.ignored == False, Finding.ignored == None),
        or_(Finding.resolved == False, Finding.resolved == None),
        or_(Finding.in_progress == False, Finding.in_progress == None),
        or_(Finding.accepted_risk == False, Finding.accepted_risk == None),
    )
    sev_rows = (
        db.session.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.asset_id == asset.id)
        .filter(open_filter)
        .group_by(Finding.severity)
        .all()
    )
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for sev, cnt in sev_rows:
        s = (sev or "info").lower()
        if s not in counts:
            s = "info"
        counts[s] += int(cnt)
    open_total = sum(counts.values())

    findings_total = (
        db.session.query(func.count(Finding.id))
        .filter(Finding.asset_id == asset.id)
        .scalar() or 0
    )

    # Top 3 open findings — by severity priority then most-recent.
    SEVERITY_ORDER = case(
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
        value=Finding.severity, else_=4,
    )
    top_findings_q = (
        Finding.query
        .filter(Finding.asset_id == asset.id)
        .filter(open_filter)
        .order_by(SEVERITY_ORDER.asc(), Finding.created_at.desc())
        .limit(3)
        .all()
    )
    top_findings = [
        {
            "id": str(f.id),
            "displayId": f.public_id,
            "title": f.title,
            "severity": f.severity,
            "category": f.category,
        }
        for f in top_findings_q
    ]

    # ── Scan history ──
    # ScanJob has no organization_id of its own — it's scoped through
    # `asset_id`. The asset is already verified org-scoped above, so
    # filtering on asset_id alone is sufficient.
    last_scan = (
        ScanJob.query
        .filter(ScanJob.asset_id == asset.id)
        .order_by(ScanJob.id.desc())
        .first()
    )
    total_scans = (
        db.session.query(func.count(ScanJob.id))
        .filter(ScanJob.asset_id == asset.id)
        .scalar() or 0
    )
    last_scan_profile = None
    if last_scan and getattr(last_scan, "nmap_scan_type", None):
        last_scan_profile = last_scan.nmap_scan_type.title()

    # ── Monitor ──
    monitor = (
        Monitor.query
        .filter(Monitor.asset_id == asset.id, Monitor.organization_id == org_id)
        .order_by(Monitor.id.desc())
        .first()
    )
    monitor_payload = None
    if monitor:
        monitor_payload = {
            "enabled": bool(monitor.enabled),
            "frequency": monitor.frequency,
            "lastCheckedAt": monitor.last_checked_at.isoformat() if monitor.last_checked_at else None,
            "nextCheckAt": monitor.next_check_at.isoformat() if monitor.next_check_at else None,
        }

    # ── Recommendations ──
    # Deterministic rules, ordered by importance. Capped at 5 so the
    # panel doesn't become a wall of text.
    recommendations: list[str] = []

    if total_scans == 0 or asset.scan_status == "never_scanned":
        recommendations.append("Run your first scan to discover what's exposed.")
    else:
        if asset.last_scan_at:
            days_since = (now - asset.last_scan_at).days
            if days_since >= 30:
                recommendations.append(f"Run a fresh scan — the last one was {days_since} days ago.")
            elif (
                last_scan_profile
                and last_scan_profile.lower() in ("quick",)
                and open_total > 0
            ):
                recommendations.append("Run a Deep scan to surface issues a Quick scan misses.")

    if counts["critical"] > 0:
        recommendations.append(
            f"Address the {counts['critical']} open critical finding"
            + ("s" if counts["critical"] != 1 else "")
            + " before they age further."
        )
    elif counts["high"] > 0:
        recommendations.append(
            f"Address the {counts['high']} open high-severity finding"
            + ("s" if counts["high"] != 1 else "")
            + "."
        )

    if not monitor or not monitor.enabled:
        recommendations.append(
            "Enable continuous monitoring to catch new findings as they appear."
        )

    if asset.scan_status == "scan_failed":
        recommendations.append("The last scan failed — retry it from the Scan Jobs page.")

    recommendations = recommendations[:5]

    return jsonify({
        "asset": {
            "id": str(asset.id),
            "displayId": asset.public_id,
            "type": asset.asset_type,
            "value": asset.value,
            "label": asset.label,
            "groupId": str(asset.group_id) if asset.group_id else None,
            "groupName": group.name if group else None,
            "groupDisplayId": group.public_id if group else None,
            "addedOn": asset.created_at.isoformat() if asset.created_at else None,
            "ageDays": age_days,
            "provider": asset.provider,
            "cloudCategory": asset.cloud_category,
        },
        "scan": {
            "lastScanAt": asset.last_scan_at.isoformat() if asset.last_scan_at else None,
            "lastScanProfile": last_scan_profile,
            "scanStatus": asset.scan_status or "never_scanned",
            "totalScans": int(total_scans),
        },
        "findings": {
            "total": int(findings_total),
            "open": open_total,
            "bySeverity": counts,
            "topOpen": top_findings,
        },
        "monitor": monitor_payload,
        "recommendations": recommendations,
    }), 200


# GET /assets/<id>/risk — all roles can view
@assets_bp.get("/assets/<asset_id>/risk")
@require_auth
@allow_api_key
def asset_risk(asset_id: str):
    org_id = current_organization_id()

    asset = Asset.query.filter_by(id=int(asset_id), organization_id=org_id).first()
    if not asset:
        return jsonify(error="asset not found"), 404

    from sqlalchemy import or_, and_

    # Only count truly OPEN findings (not resolved, suppressed, accepted_risk, or in_progress)
    open_filter = and_(
        or_(Finding.ignored == False, Finding.ignored == None),
        or_(Finding.resolved == False, Finding.resolved == None),
        or_(Finding.in_progress == False, Finding.in_progress == None),
        or_(Finding.accepted_risk == False, Finding.accepted_risk == None),
    )

    rows = (
        db.session.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.asset_id == asset.id)
        .filter(open_filter)
        .group_by(Finding.severity)
        .all()
    )

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for sev, cnt in rows:
        s = (sev or "info").lower()
        if s not in counts:
            s = "info"
        counts[s] += int(cnt)

    max_sev = "info"
    for k in ["critical", "high", "medium", "low", "info"]:
        if counts[k] > 0:
            max_sev = k
            break

    return jsonify(
        assetId=str(asset.id),
        type=asset.asset_type,
        value=asset.value,
        openFindings=sum(counts.values()),
        bySeverity=counts,
        maxSeverity=max_sev,
    ), 200


# GET /assets/<id>/coverage — all roles can view
@assets_bp.get("/assets/<asset_id>/coverage")
@require_auth
@allow_api_key
def asset_coverage(asset_id: str):
    org_id = current_organization_id()

    asset = Asset.query.filter_by(id=int(asset_id), organization_id=org_id).first()
    if not asset:
        return jsonify(error="asset not found"), 404

    latest_job = (
        ScanJob.query.filter_by(asset_id=asset.id)
        .order_by(desc(ScanJob.id))
        .first()
    )

    last_scan_at = None
    latest_scan_id = None
    status = "not_scanned"

    if latest_job:
        status = latest_job.status
        latest_scan_id = latest_job.id
        last_scan_at = latest_job.finished_at or latest_job.started_at or latest_job.created_at

    agg = (
        db.session.query(
            func.min(Finding.first_seen_at),
            func.max(Finding.last_seen_at),
            func.count(Finding.id),
        )
        .filter(Finding.asset_id == asset.id)
        .first()
    )

    first_seen_at = agg[0] if agg else None
    last_seen_at = agg[1] if agg else None
    total_findings = int(agg[2] or 0) if agg else 0

    completed_scans = (
        db.session.query(func.count(ScanJob.id))
        .filter(ScanJob.asset_id == asset.id, ScanJob.status == "completed")
        .scalar()
        or 0
    )

    return jsonify(
        assetId=str(asset.id),
        lastScanAt=last_scan_at.isoformat() if last_scan_at else None,
        latestScanId=str(latest_scan_id) if latest_scan_id else None,
        status=status,
        firstSeenAt=first_seen_at.isoformat() if first_seen_at else None,
        lastSeenAt=last_seen_at.isoformat() if last_seen_at else None,
        totalFindings=total_findings,
        completedScans=int(completed_scans),
    ), 200


# GET /assets/<id>/health — all roles can view
@assets_bp.get("/assets/<asset_id>/health")
@require_auth
@allow_api_key
def asset_health(asset_id: str):
    from datetime import datetime

    org_id = current_organization_id()

    asset = Asset.query.filter_by(id=int(asset_id), organization_id=org_id).first()
    if not asset:
        return jsonify(error="asset not found"), 404

    rows = (
        db.session.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.asset_id == asset.id)
        .filter((Finding.ignored.is_(False)) | (Finding.ignored.is_(None)))
        .group_by(Finding.severity)
        .all()
    )

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for sev, cnt in rows:
        s = (sev or "info").lower()
        if s not in counts:
            s = "info"
        counts[s] += int(cnt)

    finding_penalty = (
        (counts["critical"] * 30) +
        (counts["high"] * 15) +
        (counts["medium"] * 8) +
        (counts["low"] * 1.5) +
        (counts["info"] * 0.3)
    )

    base_score = max(0, min(100, 100 - finding_penalty))

    scan_recency_penalty = 0
    days_since_scan = None

    if asset.last_scan_at:
        delta = datetime.utcnow() - asset.last_scan_at
        days_since_scan = delta.days

        if days_since_scan > 90:
            scan_recency_penalty = 20
        elif days_since_scan > 60:
            scan_recency_penalty = 15
        elif days_since_scan > 30:
            scan_recency_penalty = 10
        elif days_since_scan > 14:
            scan_recency_penalty = 5
    else:
        scan_recency_penalty = 25

    final_score = max(0, min(100, base_score - scan_recency_penalty))

    if counts["critical"] > 0:
        risk_level = "critical"
    elif counts["high"] >= 5:
        risk_level = "critical"
    elif counts["high"] > 0 or final_score < 40:
        risk_level = "high"
    elif counts["medium"] >= 10 or final_score < 60:
        risk_level = "medium"
    elif counts["low"] >= 20 or final_score < 80:
        risk_level = "low"
    else:
        risk_level = "healthy"

    max_severity = "info"
    for k in ["critical", "high", "medium", "low", "info"]:
        if counts[k] > 0:
            max_severity = k
            break

    total_findings = sum(counts.values())

    total_scans = (
        db.session.query(func.count(ScanJob.id))
        .filter(ScanJob.asset_id == asset.id)
        .scalar() or 0
    )

    completed_scans = (
        db.session.query(func.count(ScanJob.id))
        .filter(ScanJob.asset_id == asset.id, ScanJob.status == "completed")
        .scalar() or 0
    )

    return jsonify(
        assetId=str(asset.id),
        healthScore=round(final_score, 1),
        riskLevel=risk_level,
        maxSeverity=max_severity,
        totalFindings=total_findings,
        findingsBySeverity=counts,
        lastScanAt=asset.last_scan_at.isoformat() if asset.last_scan_at else None,
        daysSinceLastScan=days_since_scan,
        scanStatus=asset.scan_status or "never_scanned",
        totalScans=int(total_scans),
        completedScans=int(completed_scans),
        scanRecencyPenalty=scan_recency_penalty,
        findingPenalty=round(finding_penalty, 1),
    ), 200


# GET /assets/<id>/timeline — all roles can view
@assets_bp.get("/assets/<asset_id>/timeline")
@require_auth
@allow_api_key
def asset_timeline(asset_id: str):
    org_id = current_organization_id()

    asset = Asset.query.filter_by(id=int(asset_id), organization_id=org_id).first()
    if not asset:
        return jsonify(error="asset not found"), 404

    scans = (
        ScanJob.query
        .filter_by(asset_id=asset.id)
        .order_by(desc(ScanJob.created_at))
        .all()
    )

    scan_events = []
    for scan in scans:
        scan_events.append({
            "type": "scan",
            "scanId": str(scan.id),
            "status": scan.status,
            "createdAt": scan.created_at.isoformat() if scan.created_at else None,
            "startedAt": scan.started_at.isoformat() if scan.started_at else None,
            "finishedAt": scan.finished_at.isoformat() if scan.finished_at else None,
            "error": scan.error_message,
        })

    findings = (
        db.session.query(
            Finding.id,
            Finding.severity,
            Finding.title,
            Finding.first_seen_at,
            Finding.last_seen_at,
            Finding.ignored,
        )
        .filter(Finding.asset_id == asset.id)
        .order_by(desc(Finding.first_seen_at))
        .all()
    )

    finding_events = []
    for f in findings:
        finding_events.append({
            "type": "finding",
            "findingId": str(f.id),
            "severity": f.severity,
            "title": f.title,
            "firstSeenAt": f.first_seen_at.isoformat() if f.first_seen_at else None,
            "lastSeenAt": f.last_seen_at.isoformat() if f.last_seen_at else None,
            "ignored": bool(f.ignored),
        })

    all_events = scan_events + finding_events

    def get_event_time(event):
        if event["type"] == "scan":
            return event.get("createdAt") or ""
        else:
            return event.get("firstSeenAt") or ""

    all_events.sort(key=get_event_time, reverse=True)

    return jsonify(
        assetId=str(asset.id),
        assetValue=asset.value,
        assetType=asset.asset_type,
        events=all_events,
        totalEvents=len(all_events),
        totalScans=len(scan_events),
        totalFindings=len(finding_events),
    ), 200


# ---------------------------
# Helper Functions
# ---------------------------

def _detect_asset_type(value: str) -> str:
    """Auto-detect whether a value is an IP, email, cloud URL, or domain."""
    v = value.strip().lower()

    if "@" in v and "." in v:
        return "email"

    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass

    try:
        ipaddress.ip_network(v, strict=False)
        return "ip"
    except ValueError:
        pass

    # Check if it looks like a cloud URL
    provider, _ = detect_cloud_provider(v)
    if provider:
        return "cloud"

    # URLs with schemes that aren't cloud — still treat as cloud if they have paths
    if "://" in v and "/" in v.split("://", 1)[1]:
        return "cloud"

    return "domain"