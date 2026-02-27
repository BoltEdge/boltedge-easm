# FILE: app/discovery/routes.py
"""
Discovery API Routes — v2 (M10 Discovery Engine)

New endpoints:
  POST /discovery/run                  — launch a discovery job
  GET  /discovery/jobs                 — list discovery jobs
  GET  /discovery/jobs/<id>            — job detail + discovered assets
  POST /discovery/jobs/<id>/cancel     — cancel a running job
  POST /discovery/jobs/<id>/add-assets — add discovered assets to inventory
  DELETE /discovery/jobs/<id>          — delete a discovery job

Legacy (backward compatible):
  POST /discovery/domain               — old endpoint, now wraps new engine
  GET  /discovery/runs                 — alias for /discovery/jobs
  GET  /discovery/runs/<id>            — alias for /discovery/jobs/<id>
  DELETE /discovery/runs/<id>          — alias for delete job
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from threading import Thread
from typing import Any, Dict, Set

from flask import Blueprint, request, jsonify, g, current_app

from app.extensions import db
from app.auth.decorators import require_auth, current_organization_id
from app.auth.permissions import require_role

logger = logging.getLogger(__name__)

discovery_bp = Blueprint("discovery", __name__, url_prefix="/discovery")

DOMAIN_RE = re.compile(r"^(?:\*\.)?([a-z0-9-]+\.)+[a-z]{2,63}$", re.IGNORECASE)
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _now_utc():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _normalize_domain(d: str) -> str:
    d = (d or "").strip().lower()
    if d.startswith("http://") or d.startswith("https://"):
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0]
    d = d.strip().strip(".")
    if d.startswith("*."):
        d = d[2:]
    return d


def _is_valid_domain(d: str) -> bool:
    d = _normalize_domain(d)
    if not d or len(d) > 253:
        return False
    return DOMAIN_RE.match(d) is not None


def _is_valid_ip(v: str) -> bool:
    return bool(IP_RE.match((v or "").strip()))


def _get_existing_asset_values(org_id: int) -> Set[str]:
    from app.models import Asset
    assets = Asset.query.filter(Asset.organization_id == org_id).with_entities(Asset.value).all()
    return {a.value.strip().lower() for a in assets}


def _serialize_job(job, include_assets=False, include_modules=False) -> dict:
    data = {
        "id": job.id,
        "target": job.target,
        "targetType": job.target_type,
        "status": job.status,
        "scanDepth": (job.config or {}).get("scan_depth", "quick"),
        "totalFound": job.total_found,
        "newAssets": job.new_assets,
        "countsByType": job.counts_by_type or {},
        "errorMessage": job.error_message,
        "startedAt": job.started_at.isoformat() + "Z" if job.started_at else None,
        "completedAt": job.completed_at.isoformat() + "Z" if job.completed_at else None,
        "createdAt": job.created_at.isoformat() + "Z" if job.created_at else None,
    }

    # Include cloud config info in response if present
    job_config = job.config or {}
    if job_config.get("company_name"):
        data["companyName"] = job_config["company_name"]
    if job_config.get("brand_keywords"):
        data["brandKeywords"] = job_config["brand_keywords"]

    if include_modules:
        # Expose progress counts only — module names are internal
        module_results = job.module_results or []
        data["engineProgress"] = {
            "total": len(module_results),
            "completed": sum(1 for mr in module_results if mr.status in ("completed", "failed", "skipped")),
            "running": sum(1 for mr in module_results if mr.status == "running"),
            "failed": sum(1 for mr in module_results if mr.status == "failed"),
        }
    if include_assets:
        data["discoveredAssets"] = [
            {
                "id": da.id,
                "assetType": da.asset_type,
                "value": da.value,
                "confidence": da.confidence,
                "resolvedIps": (da.extra_info or {}).get("resolved_ips", []),
                "tags": da.tags or [],
                "isNew": da.is_new,
                "isIgnored": "ignored" in (da.tags or []),
                "addedToInventory": da.added_to_inventory,
                "addedAssetId": da.added_asset_id,
                "discoveredAt": da.discovered_at.isoformat() + "Z" if da.discovered_at else None,
            }
            for da in (job.discovered_assets or [])
        ]
    return data


def _sanitize_cloud_config(body: dict) -> dict:
    """
    Extract and validate cloud enumeration config from request body.

    Accepted fields:
      - company_name:   str, max 200 chars (e.g. "Acme Corp")
      - brand_keywords: list of str, max 20 items, each max 100 chars
      - custom_bases:   list of str, max 50 items, each max 100 chars

    Returns a clean dict with only valid fields (empty dict if none).
    """
    result = {}

    company_name = (body.get("companyName") or body.get("company_name") or "").strip()
    if company_name:
        result["company_name"] = company_name[:200]

    brand_keywords = body.get("brandKeywords") or body.get("brand_keywords") or []
    if isinstance(brand_keywords, list):
        cleaned = [str(k).strip().lower()[:100] for k in brand_keywords if str(k).strip()]
        result["brand_keywords"] = cleaned[:20]  # Max 20 keywords

    custom_bases = body.get("customBases") or body.get("custom_bases") or []
    if isinstance(custom_bases, list):
        cleaned = [str(b).strip().lower()[:100] for b in custom_bases if str(b).strip()]
        result["custom_bases"] = cleaned[:50]  # Max 50 custom base names

    return result


# ═══════════════════════════════════════════════════════════════
# POST /discovery/run — Launch a discovery job
# ═══════════════════════════════════════════════════════════════

@discovery_bp.post("/run")
@require_auth
@require_role("analyst")
def launch_discovery():
    from app.models import DiscoveryJob

    body: Dict[str, Any] = request.get_json(silent=True) or {}
    org = g.current_organization
    org_id = int(org.id)
    user_id = int(g.current_user.id)
    plan = org.effective_plan

    raw_target = (body.get("target") or body.get("domain") or body.get("value") or "").strip()
    target_type = (body.get("targetType") or body.get("target_type") or "domain").strip().lower()

    # Discovery depth: standard / deep (default: standard)
    scan_depth = (body.get("scanDepth") or body.get("scan_depth") or "standard").strip().lower()
    if scan_depth not in ("standard", "deep"):
        scan_depth = "standard"

    # Plan-based depth gating:
    #   free    → standard only
    #   starter+ → standard, deep
    PLAN_DEPTH_LIMIT = {
        "free": ("standard",),
        "starter": ("standard", "deep"),
        "professional": ("standard", "deep"),
        "enterprise_silver": ("standard", "deep"),
        "enterprise_gold": ("standard", "deep"),
    }
    allowed_depths = PLAN_DEPTH_LIMIT.get(plan, ("standard",))
    if scan_depth not in allowed_depths:
        return jsonify(
            error=f"Your plan ({plan}) does not support deep discovery. Upgrade to unlock it.",
            planError={"feature": "scan_depth", "required": scan_depth, "allowed": list(allowed_depths)},
        ), 403

    # Plan-based target type gating:
    #   all plans → domain, ip
    #   starter+  → + asn, org_name
    PLAN_TARGET_LIMIT = {
        "free": ("domain", "ip"),
        "starter": ("domain", "ip", "asn", "org_name", "cidr"),
        "professional": ("domain", "ip", "asn", "org_name", "cidr"),
        "enterprise_silver": ("domain", "ip", "asn", "org_name", "cidr"),
        "enterprise_gold": ("domain", "ip", "asn", "org_name", "cidr"),
    }
    allowed_targets = PLAN_TARGET_LIMIT.get(plan, ("domain", "ip"))
    if target_type not in allowed_targets:
        return jsonify(
            error=f"Your plan ({plan}) does not support {target_type} discovery. Upgrade to unlock it.",
            planError={"feature": "target_type", "required": target_type, "allowed": list(allowed_targets)},
        ), 403

    # Build config that flows to modules
    job_config = body.get("config") or {}
    job_config["scan_depth"] = scan_depth

    # ── Cloud enumeration config ──
    # Accept company_name, brand_keywords, custom_bases from request body
    # and merge into job_config so the orchestrator can inject them into
    # the cloud_enum module.
    cloud_config = _sanitize_cloud_config(body)
    if cloud_config:
        job_config.update(cloud_config)

    # Validate target based on type
    if target_type == "domain":
        target = _normalize_domain(raw_target)
        if not _is_valid_domain(target):
            return jsonify(error="Invalid domain format."), 400
    elif target_type == "ip":
        target = raw_target.strip()
        if not _is_valid_ip(target):
            return jsonify(error="Invalid IP address format."), 400
    elif target_type == "asn":
        target = raw_target.strip().upper()
        if not target.startswith("AS"):
            target = "AS" + target
        # Validate: AS followed by digits
        if not re.match(r"^AS\d{1,10}$", target):
            return jsonify(error="Invalid ASN format. Use e.g. AS13335 or 13335."), 400
    elif target_type == "org_name":
        target = raw_target.strip()
        if len(target) < 2 or len(target) > 200:
            return jsonify(error="Organization name must be 2-200 characters."), 400
    elif target_type == "cidr":
        target = raw_target.strip()
        # Validate CIDR format: x.x.x.x/n
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", target):
            return jsonify(error="Invalid CIDR format. Use e.g. 192.168.1.0/24."), 400
        prefix_len = int(target.split("/")[1])
        if prefix_len < 1 or prefix_len > 32:
            return jsonify(error="CIDR prefix must be between /1 and /32."), 400
        # Depth-based CIDR size limit:
        #   standard → max /28 (16 IPs)
        #   deep     → max /24 (256 IPs)
        min_prefix = 28 if scan_depth == "standard" else 24
        if prefix_len < min_prefix:
            max_label = "/28 (16 hosts)" if scan_depth == "standard" else "/24 (256 hosts)"
            return jsonify(
                error=f"CIDR range too large for {scan_depth} discovery. Maximum: {max_label}.",
            ), 400

    job = DiscoveryJob(
        organization_id=org_id, created_by=user_id,
        target=target, target_type=target_type,
        status="pending", config=job_config,
    )
    db.session.add(job)
    db.session.commit()
    job_id = job.id

    existing = _get_existing_asset_values(org_id)
    app = current_app._get_current_object()

    def _run():
        from app.discovery.orchestrator import DiscoveryOrchestrator
        orchestrator = DiscoveryOrchestrator(app=app)
        try:
            orchestrator.run_discovery(
                job_id=job_id, org_id=org_id, target=target,
                target_type=target_type, plan=plan,
                config=job_config,
                existing_asset_values=existing,
            )
        except Exception as e:
            logger.error("Discovery job #%d crashed: %s", job_id, e, exc_info=True)
            with app.app_context():
                j = db.session.get(DiscoveryJob, job_id)
                if j and j.status == "running":
                    j.status = "failed"
                    j.error_message = str(e)[:1000]
                    j.completed_at = _now_utc()
                    db.session.commit()

    Thread(target=_run, daemon=True).start()
    return jsonify(_serialize_job(job)), 202


# ═══════════════════════════════════════════════════════════════
# GET /discovery/jobs — List discovery jobs
# ═══════════════════════════════════════════════════════════════

@discovery_bp.get("/jobs")
@require_auth
def list_jobs():
    from app.models import DiscoveryJob
    org_id = int(current_organization_id())
    status_filter = request.args.get("status")
    limit = min(int(request.args.get("limit", 50)), 200)
    offset = max(int(request.args.get("offset", 0)), 0)

    query = DiscoveryJob.query.filter_by(organization_id=org_id)
    if status_filter:
        query = query.filter_by(status=status_filter)
    query = query.order_by(DiscoveryJob.created_at.desc())
    total = query.count()
    jobs = query.offset(offset).limit(limit).all()

    return jsonify(items=[_serialize_job(j) for j in jobs], total=total, limit=limit, offset=offset), 200


# ═══════════════════════════════════════════════════════════════
# GET /discovery/jobs/<id> — Job detail
# ═══════════════════════════════════════════════════════════════

@discovery_bp.get("/jobs/<int:job_id>")
@require_auth
def get_job(job_id: int):
    from app.models import DiscoveryJob
    org_id = int(current_organization_id())
    job = DiscoveryJob.query.filter_by(id=job_id, organization_id=org_id).first()
    if not job:
        return jsonify(error="Discovery job not found."), 404
    return jsonify(_serialize_job(job, include_assets=True, include_modules=True)), 200


# ═══════════════════════════════════════════════════════════════
# POST /discovery/jobs/<id>/cancel
# ═══════════════════════════════════════════════════════════════

@discovery_bp.post("/jobs/<int:job_id>/cancel")
@require_auth
@require_role("analyst")
def cancel_job(job_id: int):
    from app.models import DiscoveryJob
    org_id = int(current_organization_id())
    job = DiscoveryJob.query.filter_by(id=job_id, organization_id=org_id).first()
    if not job:
        return jsonify(error="Discovery job not found."), 404
    if job.status not in ("pending", "running"):
        return jsonify(error=f"Cannot cancel job with status '{job.status}'."), 400
    job.status = "cancelled"
    job.completed_at = _now_utc()
    db.session.commit()
    return jsonify(status="cancelled", jobId=job.id), 200


# ═══════════════════════════════════════════════════════════════
# POST /discovery/jobs/<id>/add-assets — Add to inventory
# ═══════════════════════════════════════════════════════════════

@discovery_bp.post("/jobs/<int:job_id>/add-assets")
@require_auth
@require_role("analyst")
def add_assets_to_inventory(job_id: int):
    from app.models import DiscoveryJob, DiscoveredAsset, Asset, AssetGroup

    org_id = int(current_organization_id())
    user_id = int(g.current_user.id)

    job = DiscoveryJob.query.filter_by(id=job_id, organization_id=org_id).first()
    if not job:
        return jsonify(error="Discovery job not found."), 404

    body = request.get_json(silent=True) or {}
    asset_ids = body.get("assetIds") or body.get("asset_ids") or []
    group_id = body.get("groupId") or body.get("group_id")

    if not asset_ids:
        return jsonify(error="No asset IDs provided."), 400
    if not group_id:
        return jsonify(error="No group ID provided."), 400

    group = AssetGroup.query.filter_by(id=int(group_id), organization_id=org_id).first()
    if not group:
        return jsonify(error="Asset group not found."), 404

    discovered = DiscoveredAsset.query.filter(
        DiscoveredAsset.id.in_(asset_ids),
        DiscoveredAsset.job_id == job_id,
        DiscoveredAsset.organization_id == org_id,
    ).all()

    if not discovered:
        return jsonify(error="No matching discovered assets found."), 404

    type_map = {"domain": "domain", "subdomain": "domain", "ip": "ip", "ip_range": "ip", "cloud": "cloud"}
    added, skipped, errors = [], [], []

    for da in discovered:
        if da.added_to_inventory:
            skipped.append({"id": da.id, "value": da.value, "reason": "already_added"})
            continue

        inv_type = type_map.get(da.asset_type, "domain")
        existing = Asset.query.filter_by(organization_id=org_id, asset_type=inv_type, value=da.value).first()

        if existing:
            da.added_to_inventory = True
            da.added_asset_id = existing.id
            skipped.append({"id": da.id, "value": da.value, "reason": "exists_in_inventory"})
            continue

        try:
            # For cloud assets discovered via cloud_enum, detect provider
            provider = None
            cloud_category = None
            if inv_type == "cloud":
                from app.assets.routes import detect_cloud_provider
                provider, cloud_category = detect_cloud_provider(da.value)
                # Also check discovery metadata for provider info
                da_meta = da.extra_info or {}
                provider = provider or da_meta.get("provider") or "other"
                cloud_category = cloud_category or da_meta.get("cloud_category") or "storage"

            asset = Asset(
                user_id=user_id, organization_id=org_id, group_id=int(group_id),
                asset_type=inv_type, value=da.value, label=f"discovered:{job.target}",
                provider=provider,
                cloud_category=cloud_category,
            )
            db.session.add(asset)
            db.session.flush()
            da.added_to_inventory = True
            da.added_asset_id = asset.id
            added.append({"id": da.id, "value": da.value, "assetId": asset.id})
        except Exception as e:
            errors.append({"id": da.id, "value": da.value, "error": str(e)})

    db.session.commit()
    return jsonify(added=added, skipped=skipped, errors=errors, totalAdded=len(added), totalSkipped=len(skipped), totalErrors=len(errors)), 200


# ═══════════════════════════════════════════════════════════════
# DELETE /discovery/jobs/<id>
# ═══════════════════════════════════════════════════════════════

@discovery_bp.delete("/jobs/<int:job_id>")
@require_auth
@require_role("analyst")
def delete_job(job_id: int):
    from app.models import DiscoveryJob
    org_id = int(current_organization_id())
    job = DiscoveryJob.query.filter_by(id=job_id, organization_id=org_id).first()
    if not job:
        return jsonify(error="Discovery job not found."), 404
    if job.status == "running":
        return jsonify(error="Cannot delete a running job. Cancel it first."), 400
    db.session.delete(job)
    db.session.commit()
    return jsonify(status="deleted", jobId=job_id), 200


# ═══════════════════════════════════════════════════════════════
# LEGACY — POST /discovery/domain (sync, backward compatible)
# ═══════════════════════════════════════════════════════════════

@discovery_bp.post("/domain")
@require_auth
@require_role("analyst")
def legacy_discovery_domain():
    from app.models import DiscoveryJob, DiscoveredAsset

    body: Dict[str, Any] = request.get_json(silent=True) or {}
    org = g.current_organization
    org_id = int(org.id)
    user_id = int(g.current_user.id)
    plan = org.effective_plan

    raw = body.get("domain") or body.get("value") or ""
    target = _normalize_domain(str(raw))
    if not _is_valid_domain(target):
        return jsonify(error="Invalid domain format."), 400

    # Build config with cloud enum support
    job_config = body.get("config") or body.get("options") or {}
    cloud_config = _sanitize_cloud_config(body)
    if cloud_config:
        job_config.update(cloud_config)

    job = DiscoveryJob(
        organization_id=org_id, created_by=user_id,
        target=target, target_type="domain", status="pending",
        config=job_config,
    )
    db.session.add(job)
    db.session.commit()
    job_id = job.id

    existing = _get_existing_asset_values(org_id)

    from app.discovery.orchestrator import DiscoveryOrchestrator
    orchestrator = DiscoveryOrchestrator(app=None)

    try:
        orchestrator.run_discovery(
            job_id=job_id, org_id=org_id, target=target, target_type="domain",
            plan=plan, config=job_config,
            existing_asset_values=existing,
        )
    except Exception as e:
        logger.error("Legacy discovery failed: %s", e, exc_info=True)
        return jsonify(error=str(e), status="failed"), 500

    db.session.expire_all()
    job = db.session.get(DiscoveryJob, job_id)
    discovered = DiscoveredAsset.query.filter_by(job_id=job_id).all()

    subdomains = [da.value for da in discovered if da.asset_type in ("domain", "subdomain")]
    resolved = {}
    for da in discovered:
        if da.asset_type in ("domain", "subdomain"):
            ips = (da.extra_info or {}).get("resolved_ips", [])
            if ips:
                resolved[da.value] = ips

    unique_ips = set()
    for ip_list in resolved.values():
        unique_ips.update(ip_list)

    return jsonify(
        status=job.status if job else "completed",
        domain=target, jobId=job_id,
        subdomains=subdomains, resolved=resolved,
        apexIps=resolved.get(target, []),
        counts={"subdomains": len(subdomains), "uniqueIps": len(unique_ips),
                "ct": sum(1 for da in discovered if "ct_logs" in (da.sources or [])),
                "brute": sum(1 for da in discovered if "dns_enum" in (da.sources or []))},
        options={"useCt": True, "useDnsBrute": True, "resolveIps": True, "includeApex": True},
        limits={}, errors=[], stored=True, runId=job_id,
    ), 200


# ═══════════════════════════════════════════════════════════════
# LEGACY — GET /discovery/runs (alias)
# ═══════════════════════════════════════════════════════════════

@discovery_bp.get("/runs")
@require_auth
def legacy_list_runs():
    from app.models import DiscoveryJob
    org_id = int(current_organization_id())
    limit = min(int(request.args.get("limit", 50)), 200)
    offset = max(int(request.args.get("offset", 0)), 0)

    jobs = DiscoveryJob.query.filter_by(organization_id=org_id)\
        .order_by(DiscoveryJob.created_at.desc())\
        .offset(offset).limit(limit).all()

    items = [{
        "id": j.id, "domain": j.target, "status": j.status,
        "createdAt": j.created_at.isoformat() + "Z" if j.created_at else None,
        "sourceFlags": {}, "counts": j.counts_by_type or {"subdomains": j.total_found}, "limits": {},
    } for j in jobs]

    return jsonify(items=items, limit=limit, offset=offset), 200


@discovery_bp.get("/runs/<int:run_id>")
@require_auth
def legacy_get_run(run_id: int):
    from app.models import DiscoveryJob, DiscoveredAsset
    org_id = int(current_organization_id())
    job = DiscoveryJob.query.filter_by(id=run_id, organization_id=org_id).first()
    if not job:
        return jsonify(error="not_found"), 404

    discovered = DiscoveredAsset.query.filter_by(job_id=run_id).all()
    subdomains = [da.value for da in discovered if da.asset_type in ("domain", "subdomain")]
    resolved = {}
    for da in discovered:
        if da.asset_type in ("domain", "subdomain"):
            ips = (da.extra_info or {}).get("resolved_ips", [])
            if ips:
                resolved[da.value] = ips

    return jsonify(
        id=job.id, domain=job.target, status=job.status,
        createdAt=job.created_at.isoformat() + "Z" if job.created_at else None,
        sourceFlags={}, counts=job.counts_by_type or {"subdomains": len(subdomains)}, limits={},
        result={"subdomains": subdomains, "resolved": resolved, "counts": job.counts_by_type or {}},
    ), 200


@discovery_bp.delete("/runs/<int:run_id>")
@require_auth
@require_role("analyst")
def legacy_delete_run(run_id: int):
    from app.models import DiscoveryJob
    org_id = int(current_organization_id())
    job = DiscoveryJob.query.filter_by(id=run_id, organization_id=org_id).first()
    if not job:
        return jsonify(error="not_found"), 404
    db.session.delete(job)
    db.session.commit()
    return jsonify(status="deleted", runId=run_id), 200


# ═══════════════════════════════════════════════════════════════
# PATCH /discovery/assets/<id>/tags — Add or remove tags on a discovered asset
# ═══════════════════════════════════════════════════════════════

@discovery_bp.patch("/assets/<int:asset_id>/tags")
@require_auth
@require_role("analyst")
def update_asset_tags(asset_id: int):
    """
    Add or remove tags on a discovered asset.
    Body: { "add": ["investigate"], "remove": ["false-positive"] }
    or:   { "tags": ["in-scope", "investigate"] }  (replace all)
    """
    from app.models import DiscoveredAsset
    from sqlalchemy.orm.attributes import flag_modified

    org_id = int(current_organization_id())
    asset = DiscoveredAsset.query.filter_by(id=asset_id, organization_id=org_id).first()
    if not asset:
        return jsonify(error="not_found"), 404

    body = request.get_json(silent=True) or {}
    tags = list(asset.tags or [])

    if "tags" in body:
        # Replace mode
        tags = [str(t).strip().lower() for t in body["tags"] if str(t).strip()]
    else:
        # Add/remove mode
        for t in body.get("add", []):
            t = str(t).strip().lower()
            if t and t not in tags:
                tags.append(t)
        for t in body.get("remove", []):
            t = str(t).strip().lower()
            if t in tags:
                tags.remove(t)

    asset.tags = tags
    flag_modified(asset, "tags")
    db.session.commit()

    return jsonify(id=asset.id, tags=asset.tags), 200


# ═══════════════════════════════════════════════════════════════
# PATCH /discovery/assets/bulk-tags — Bulk tag multiple assets
# ═══════════════════════════════════════════════════════════════

@discovery_bp.patch("/assets/bulk-tags")
@require_auth
@require_role("analyst")
def bulk_update_asset_tags():
    """
    Add or remove tags on multiple discovered assets.
    Body: { "assetIds": [1, 2, 3], "add": ["investigate"], "remove": [] }
    """
    from app.models import DiscoveredAsset
    from sqlalchemy.orm.attributes import flag_modified

    org_id = int(current_organization_id())
    body = request.get_json(silent=True) or {}
    asset_ids = body.get("assetIds", [])
    add_tags = [str(t).strip().lower() for t in body.get("add", []) if str(t).strip()]
    remove_tags = [str(t).strip().lower() for t in body.get("remove", []) if str(t).strip()]

    if not asset_ids:
        return jsonify(error="No asset IDs provided."), 400

    assets = DiscoveredAsset.query.filter(
        DiscoveredAsset.id.in_(asset_ids),
        DiscoveredAsset.organization_id == org_id,
    ).all()

    updated = 0
    for asset in assets:
        tags = list(asset.tags or [])
        changed = False
        for t in add_tags:
            if t not in tags:
                tags.append(t)
                changed = True
        for t in remove_tags:
            if t in tags:
                tags.remove(t)
                changed = True
        if changed:
            asset.tags = tags
            flag_modified(asset, "tags")
            updated += 1

    db.session.commit()
    return jsonify(updated=updated), 200