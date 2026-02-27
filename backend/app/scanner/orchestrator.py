# app/scanner/orchestrator.py
"""
Scan Orchestrator — the brain of the M7 detection engine.

Coordinates the full scan pipeline:

    1. Build ScanContext (target info, resolved IPs)
    2. Determine which engines/analyzers to run from the ScanProfile
    3. Load discovery metadata (cloud candidates, etc.)
    4. Run engines (collect raw data)
    5. Run analyzers (interpret data → produce FindingDrafts)
    6. Deduplicate and persist findings to DB
    7. Update ScanJob and Asset with results

Usage from scan_jobs/routes.py:
    from app.scanner import ScanOrchestrator

    orchestrator = ScanOrchestrator()
    result = orchestrator.execute(job, profile)
    # result is a dict stored in ScanJob.result_json
"""

from __future__ import annotations

import hashlib
import json
import logging
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.extensions import db
from app.models import Asset, Finding, ScanJob, ScanProfile
from app.integrations.routes import dispatch_event

from app.scanner.base import (
    BaseAnalyzer,
    BaseEngine,
    EngineResult,
    FindingDraft,
    ScanContext,
    now_utc,
)
from app.scanner.engines import ALL_ENGINES
from app.scanner.analyzers import ALL_ANALYZERS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stable_json(obj: dict) -> str:
    """Deterministic JSON for hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _resolve_domain(domain: str) -> List[str]:
    """Resolve domain to IP addresses. Returns empty list on failure."""
    d = (domain or "").strip().lower()
    if d.startswith("*."):
        d = d[2:]
    if not d:
        return []
    ips: List[str] = []
    try:
        for *_rest, sockaddr in socket.getaddrinfo(d, None):
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    except Exception as e:
        logger.warning(f"DNS resolution failed for {domain}: {e}")
    return ips


def _load_cloud_candidates(asset: Asset) -> Dict[str, Any]:
    """
    Load cloud asset candidates from the asset's discovery metadata.

    When cloud_enum runs during discovery, it produces DiscoveredItems
    with asset_type="cloud" and metadata containing candidate names.
    These are stored on the Asset record (or linked DiscoveryJob).

    Returns a dict keyed by cloud_category:
        {
            "storage":    {"candidate_names": [...], "providers": [...], ...},
            "registry":   {"candidate_names": [...], ...},
            "serverless": {"candidate_names": [...], "probe_paths": [...], ...},
            "cdn_origin": {"candidate_names": [], ...},
        }

    Returns empty dict if no cloud candidates are available.
    """
    candidates = {}

    try:
        # Check asset metadata for cloud discovery results
        meta = asset.metadata_json or {}
        cloud_items = meta.get("cloud_discovery", {})

        if cloud_items:
            # Discovery orchestrator stores cloud_enum results here
            if isinstance(cloud_items, list):
                for item in cloud_items:
                    category = item.get("cloud_category")
                    if category:
                        candidates[category] = item
            elif isinstance(cloud_items, dict):
                candidates = cloud_items
            return candidates

        # Fallback: check for cloud DiscoveredItems linked to this asset
        # via the discovery job results (if stored differently in your DB)
        if hasattr(asset, "discovery_metadata") and asset.discovery_metadata:
            disc_meta = asset.discovery_metadata
            if isinstance(disc_meta, dict):
                return disc_meta.get("cloud_candidates", {})

    except Exception as e:
        logger.warning(f"Failed to load cloud candidates for {asset.value}: {e}")

    return candidates


def _build_direct_cloud_probe(asset: Asset) -> Dict[str, Any]:
    """
    Build a direct probe configuration for a manually added cloud asset.

    Instead of iterating through candidate name lists (which is what happens
    when cloud_enum discovery feeds into the cloud_asset engine), this
    extracts the single target URL and builds a focused probe config.

    Returns a dict with:
        {
            "cloud_category": "storage" | "registry" | "serverless" | "cdn",
            "provider": "aws_s3" | "azure_blob" | ...,
            "url": "https://...",
            "name": "bucket-or-service-name",
        }

    Returns empty dict if unable to parse.
    """
    from app.assets.routes import detect_cloud_provider

    url = asset.value or ""
    provider = asset.provider
    cloud_category = asset.cloud_category

    # Auto-detect if not already set
    if not provider or not cloud_category:
        detected_provider, detected_category = detect_cloud_provider(url)
        provider = provider or detected_provider or "other"
        cloud_category = cloud_category or detected_category or "storage"

    # Extract the resource name from the URL
    name = _extract_cloud_resource_name(url, provider)

    if not name:
        return {}

    return {
        "cloud_category": cloud_category,
        "provider": provider,
        "url": url,
        "name": name,
    }


def _extract_cloud_resource_name(url: str, provider: str) -> Optional[str]:
    """
    Extract the bucket/registry/service name from a cloud URL.

    Examples:
        https://mybucket.s3.amazonaws.com      → "mybucket"
        https://myaccount.blob.core.windows.net → "myaccount"
        https://storage.googleapis.com/mybucket → "mybucket"
        https://myregistry.azurecr.io           → "myregistry"
        https://myapp.azurewebsites.net         → "myapp"
        s3://mybucket                            → "mybucket"
        gs://mybucket                            → "mybucket"
    """
    u = (url or "").strip()

    # Handle s3:// and gs:// schemes
    if u.lower().startswith("s3://"):
        return u[5:].split("/")[0].strip()
    if u.lower().startswith("gs://"):
        return u[5:].split("/")[0].strip()

    # Ensure scheme for urlparse
    if not u.startswith("http://") and not u.startswith("https://"):
        u = "https://" + u

    try:
        parsed = urlparse(u)
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "").strip("/")
    except Exception:
        return None

    # S3: {name}.s3.amazonaws.com or {name}.s3.{region}.amazonaws.com
    if ".s3" in host and "amazonaws.com" in host:
        return host.split(".s3")[0]

    # Azure Blob: {name}.blob.core.windows.net
    if ".blob.core.windows.net" in host:
        return host.split(".blob.core.windows.net")[0]

    # GCS: storage.googleapis.com/{name}
    if "storage.googleapis.com" in host:
        return path.split("/")[0] if path else None

    # ACR: {name}.azurecr.io
    if ".azurecr.io" in host:
        return host.split(".azurecr.io")[0]

    # GCR: gcr.io/{name}
    if host in ("gcr.io", "us.gcr.io", "eu.gcr.io", "asia.gcr.io"):
        return path.split("/")[0] if path else None

    # Artifact Registry: {region}-docker.pkg.dev/{project}
    if ".pkg.dev" in host:
        return path.split("/")[0] if path else None

    # ECR Public: public.ecr.aws/{name}
    if "public.ecr.aws" in host:
        return path.split("/")[0] if path else None

    # Docker Hub: hub.docker.com/u/{name} or hub.docker.com/r/{name}
    if "hub.docker.com" in host or "docker.io" in host:
        parts = path.split("/")
        # Skip leading "u" or "r" or "v2"
        for p in parts:
            if p and p not in ("u", "r", "v2", "repositories"):
                return p
        return None

    # Azure Functions: {name}.azurewebsites.net
    if ".azurewebsites.net" in host:
        return host.split(".azurewebsites.net")[0]

    # Cloud Run: {name}-{hash}.{region}.run.app
    if ".run.app" in host:
        # Name is the first segment before the hash
        first_part = host.split(".")[0]
        # Remove the hash suffix if present (pattern: name-randomhash)
        return first_part

    # CDN: {name}.cloudfront.net, {name}.azureedge.net, etc.
    if ".cloudfront.net" in host:
        return host.split(".cloudfront.net")[0]
    if ".azureedge.net" in host:
        return host.split(".azureedge.net")[0]
    if ".azurefd.net" in host:
        return host.split(".azurefd.net")[0]

    # Fallback: use first subdomain segment
    parts = host.split(".")
    if len(parts) >= 2:
        return parts[0]

    return None


# ---------------------------------------------------------------------------
# Profile → engine/analyzer mapping
# ---------------------------------------------------------------------------

def _get_enabled_engines(profile: Optional[ScanProfile], asset: Optional[Asset] = None) -> List[str]:
    """
    Determine which engines to run based on the scan profile and asset type.

    For cloud assets (asset_type="cloud"):
        - Always run cloud_asset engine
        - Skip domain-specific engines (dns, ssl, http, nmap, nuclei, db_probe)
        - Optionally run shodan if the cloud URL resolves to an IP

    For regular assets:
        - Original logic unchanged
    """
    # ── Cloud asset: focused engine selection ──
    if asset and asset.asset_type == "cloud":
        enabled = ["cloud_asset"]
        # Shodan can still be useful if we can resolve the cloud host to an IP
        if profile and profile.use_shodan:
            enabled.append("shodan")
        return enabled

    # ── Original logic for domain/ip/email assets ──
    if not profile:
        return ["shodan"]

    enabled = []

    if profile.use_shodan:
        enabled.append("shodan")

    if profile.use_sslyze:
        enabled.append("ssl")

    is_quick = profile.is_default and "quick" in (profile.name or "").lower()
    if not is_quick:
        enabled.append("http")
        enabled.append("dns")
    elif profile.use_sslyze and "http" not in enabled:
        enabled.append("http")

    if profile.use_nmap:
        enabled.append("nmap")

    if profile.use_nuclei:
        enabled.append("nuclei")

    if profile.use_nmap:
        enabled.append("db_probe")

    # Cloud Asset engine: enabled on Deep Scan profiles for domain assets
    is_deep = "deep" in (profile.name or "").lower()
    if is_deep:
        enabled.append("cloud_asset")

    return enabled


def _get_engine_config(
    engine_name: str,
    profile: Optional[ScanProfile],
    asset: Optional[Asset] = None,
) -> Dict[str, Any]:
    """
    Build engine-specific configuration from the scan profile.
    Each engine reads different fields from the profile.

    For cloud assets, the cloud_asset engine gets a special "direct_probe"
    config that targets the single URL instead of iterating candidates.
    """
    if not profile and engine_name != "cloud_asset":
        return {}

    if engine_name == "shodan":
        if not profile:
            return {}
        return {
            "include_history": profile.shodan_include_history,
            "include_cves": profile.shodan_include_cves,
            "include_dns": profile.shodan_include_dns,
            "max_ips": 3 if profile.is_default else 5,
        }

    if engine_name == "ssl":
        if not profile:
            return {}
        is_quick = profile.is_default or "quick" in (profile.name or "").lower()
        return {
            "ports": [443] if is_quick else "extended",
            "timeout": 10,
        }

    if engine_name == "http":
        if not profile:
            return {}
        is_quick = profile.is_default or "quick" in (profile.name or "").lower()
        return {
            "ports": [80, 443] if is_quick else "extended",
            "timeout": 10,
        }

    if engine_name == "dns":
        if not profile:
            return {}
        is_deep = "deep" in (profile.name or "").lower()
        return {
            "attempt_zone_transfer": is_deep,
            "timeout": 5,
        }

    if engine_name == "nmap":
        if not profile:
            return {}
        is_deep = "deep" in (profile.name or "").lower()
        return {
            "port_range": profile.nmap_port_range or ("top5000" if is_deep else "top1000"),
            "scan_type": profile.nmap_scan_type or ("deep" if is_deep else "standard"),
            "version_detect": True,
            "os_detect": is_deep,
            "timeout": profile.timeout_seconds or 120,
            "timing": 3 if is_deep else 4,
        }

    if engine_name == "nuclei":
        if not profile:
            return {}
        is_deep = "deep" in (profile.name or "").lower()
        return {
            "severity_filter": ["critical", "high", "medium"] if not is_deep else
                               ["critical", "high", "medium", "low", "info"],
            "rate_limit": 100 if is_deep else 150,
            "timeout": 10,
            "max_duration": 600 if is_deep else 300,
        }

    if engine_name == "db_probe":
        return {
            "timeout": 5,
        }

    if engine_name == "cloud_asset":
        base_config = {
            "timeout": 3,
            "delay": 0.2,
            "max_concurrent": 5,
            "max_storage": 100,
            "max_registries": 50,
            "max_serverless": 30,
            "check_storage": True,
            "check_registries": True,
            "check_serverless": True,
            "check_cdn_origin": True,
        }

        # For manually added cloud assets, inject direct_probe config
        if asset and asset.asset_type == "cloud":
            direct = _build_direct_cloud_probe(asset)
            if direct:
                base_config["direct_probe"] = direct
                logger.info(
                    f"Cloud asset direct probe: {direct['provider']}/"
                    f"{direct['cloud_category']} → {direct['name']}"
                )

        return base_config

    return {}


def _get_enabled_analyzers(profile: Optional[ScanProfile]) -> List[str]:
    """
    Determine which analyzers to run. Most analyzers always run if their
    required engine data is available — the BaseAnalyzer.can_run() check
    handles this automatically. This function allows profile-based filtering
    for optional/expensive analyzers.
    """
    return list(ALL_ANALYZERS.keys())


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class ScanOrchestrator:
    """
    Coordinates the full scan pipeline.

    Typical usage:
        orchestrator = ScanOrchestrator()
        result_dict = orchestrator.execute(scan_job, profile)
        # result_dict is saved to ScanJob.result_json

    The orchestrator is stateless — create a new instance per scan or
    reuse the same instance across scans. All state lives in ScanContext.
    """

    def execute(
        self,
        job: ScanJob,
        profile: Optional[ScanProfile] = None,
    ) -> Dict[str, Any]:
        """
        Run the full scan pipeline for a scan job.

        Steps:
            1. Build ScanContext from the job's asset
            2. Resolve domain → IPs (skip for cloud assets)
            3. Load discovery metadata (cloud candidates, etc.)
            4. Run enabled engines
            5. Run enabled analyzers
            6. Persist findings
            7. Update job and asset
            8. Return result summary

        Args:
            job:     The ScanJob to execute. Must have job.asset loaded.
            profile: The ScanProfile controlling which engines/analyzers run.
                     If None, defaults to Quick Scan behavior (Shodan only).

        Returns:
            Dict with scan summary, stored in job.result_json.

        Raises:
            Nothing — all errors are caught and recorded in the result.
        """
        asset: Asset = job.asset
        total_start = time.monotonic()

        # --- 1. Build context ---
        ctx = ScanContext(
            asset_id=asset.id,
            asset_type=asset.asset_type,
            asset_value=asset.value,
            organization_id=asset.organization_id,
            scan_job_id=job.id,
            started_at=now_utc(),
        )

        # --- 2. Resolve domain → IPs (skip for cloud assets) ---
        if asset.asset_type == "domain":
            ctx.resolved_ips = _resolve_domain(asset.value)
            if not ctx.resolved_ips:
                logger.warning(f"DNS resolution failed for {asset.value}")

        elif asset.asset_type == "cloud":
            # Cloud assets: try to resolve the hostname for Shodan lookups
            try:
                cloud_url = asset.value
                if "://" not in cloud_url:
                    cloud_url = "https://" + cloud_url
                parsed = urlparse(cloud_url)
                host = parsed.hostname
                if host:
                    resolved = _resolve_domain(host)
                    if resolved:
                        ctx.resolved_ips = resolved
                        logger.info(f"Resolved cloud host {host} → {resolved}")
            except Exception as e:
                logger.debug(f"Could not resolve cloud asset host: {e}")

        # --- 3. Load discovery metadata for engines that need it ---
        enabled_engines = _get_enabled_engines(profile, asset)

        if "cloud_asset" in enabled_engines:
            if asset.asset_type == "cloud":
                # For manually added cloud assets, the direct_probe config
                # is injected via _get_engine_config() — no candidates needed.
                # But still store cloud_category in context for analyzers.
                ctx.discovery_metadata["cloud_asset_type"] = asset.cloud_category or "storage"
                ctx.discovery_metadata["cloud_provider"] = asset.provider or "other"
                logger.info(
                    f"Cloud asset scan: {asset.provider}/{asset.cloud_category} "
                    f"→ direct probe for {asset.value}"
                )
            else:
                # For domain assets on deep scan: load cloud_enum candidates
                cloud_candidates = _load_cloud_candidates(asset)
                if cloud_candidates:
                    ctx.discovery_metadata["cloud_candidates"] = cloud_candidates
                    logger.info(
                        f"Loaded cloud candidates for {asset.value}: "
                        f"{list(cloud_candidates.keys())}"
                    )
                else:
                    logger.info(
                        f"No cloud candidates found for {asset.value} — "
                        f"cloud_asset engine will have nothing to probe"
                    )

        # --- 4. Run engines ---
        engines_run = {}

        for engine_name in enabled_engines:
            engine_cls = ALL_ENGINES.get(engine_name)
            if not engine_cls:
                logger.warning(f"Unknown engine: {engine_name}")
                continue

            engine: BaseEngine = engine_cls()
            config = _get_engine_config(engine_name, profile, asset)

            logger.info(f"Running engine '{engine_name}' for {asset.value}")
            result: EngineResult = engine.run(ctx, config)

            # Store in context so analyzers can read it
            ctx.engine_results[engine_name] = result

            engines_run[engine_name] = {
                "success": result.success,
                "duration": result.duration_seconds,
                "errors": result.errors,
            }

            if result.success:
                logger.info(
                    f"Engine '{engine_name}' completed in {result.duration_seconds}s"
                )
            else:
                logger.warning(
                    f"Engine '{engine_name}' failed: {result.errors}"
                )

        # --- 5. Run analyzers ---
        enabled_analyzers = _get_enabled_analyzers(profile)
        analyzers_run = {}

        for analyzer_name in enabled_analyzers:
            analyzer_cls = ALL_ANALYZERS.get(analyzer_name)
            if not analyzer_cls:
                continue

            analyzer: BaseAnalyzer = analyzer_cls()

            logger.info(f"Running analyzer '{analyzer_name}' for {asset.value}")
            drafts: List[FindingDraft] = analyzer.run(ctx)

            # Collect drafts
            ctx.finding_drafts.extend(drafts)

            analyzers_run[analyzer_name] = {
                "findings_produced": len(drafts),
                "skipped": not analyzer.can_run(ctx) if not drafts else False,
            }

            logger.info(
                f"Analyzer '{analyzer_name}' produced {len(drafts)} findings"
            )

        # --- 6. Persist findings ---
        findings_created = self._persist_findings(ctx, job, asset)

        # --- 7. Update job metadata ---
        ctx.finished_at = now_utc()
        total_duration = round(time.monotonic() - total_start, 2)

        job.scan_engines = {
            name: info["success"] for name, info in engines_run.items()
        }

        # --- 8. Build result summary ---
        result_summary = {
            "profileName": profile.name if profile else "Default",
            "profileId": profile.id if profile else None,
            "engines": engines_run,
            "analyzers": analyzers_run,
            "findingsCreated": findings_created,
            "totalDuration": total_duration,
            "resolvedIps": ctx.resolved_ips,
            "assetType": ctx.asset_type,
            "assetValue": ctx.asset_value,
        }

        # Add cloud-specific info to result
        if asset.asset_type == "cloud":
            result_summary["cloudProvider"] = asset.provider
            result_summary["cloudCategory"] = asset.cloud_category

        # --- Dispatch scan completion notification ---
        try:
            group = None
            if asset.group_id:
                from app.models import AssetGroup
                group = AssetGroup.query.get(asset.group_id)

            # Check if any engine failed
            any_failed = any(not info["success"] for info in engines_run.values())
            all_failed = all(not info["success"] for info in engines_run.values()) if engines_run else False

            if all_failed:
                dispatch_event(ctx.organization_id, "scan.failed", {
                    "scan_job_id": str(job.id),
                    "asset": ctx.asset_value,
                    "asset_type": ctx.asset_type,
                    "group": group.name if group else "",
                    "group_id": str(asset.group_id) if asset.group_id else "",
                    "title": f"Scan failed for {ctx.asset_value}",
                    "severity": "high",
                    "error": "; ".join(
                        e for info in engines_run.values() for e in (info.get("errors") or [])
                    )[:300],
                })
            else:
                dispatch_event(ctx.organization_id, "scan.completed", {
                    "scan_job_id": str(job.id),
                    "asset": ctx.asset_value,
                    "asset_type": ctx.asset_type,
                    "group": group.name if group else "",
                    "group_id": str(asset.group_id) if asset.group_id else "",
                    "title": f"Scan completed for {ctx.asset_value}",
                    "severity": "info",
                    "findings_count": findings_created,
                    "duration": total_duration,
                })
        except Exception as e:
            logger.warning(f"Failed to dispatch scan notification: {e}")

        return result_summary

    # -------------------------------------------------------------------
    # Finding persistence
    # -------------------------------------------------------------------

    def _persist_findings(
        self,
        ctx: ScanContext,
        job: ScanJob,
        asset: Asset,
    ) -> int:
        """
        Deduplicate and persist FindingDrafts to the Finding table.

        Deduplication logic:
            - Build a dedupe_key from (org_id, asset_id, template_id, dedupe_fields)
            - If a Finding with the same dedupe_key already exists for this asset:
                → Update its last_seen_at, scan_job_id, and any changed fields
                → Do NOT create a new row (avoids inflating counts)
            - If no previous Finding:
                → Create new with first_seen_at = now

        Returns:
            Number of NEW findings created (not counting updates).
        """
        created = 0
        updated = 0
        now = now_utc()
        new_drafts = []  # Track genuinely new findings for notifications

        for draft in ctx.finding_drafts:
            dedupe_key = self._build_dedupe_key(
                organization_id=ctx.organization_id,
                asset_id=ctx.asset_id,
                template_id=draft.template_id,
                dedupe_fields=draft.dedupe_fields,
            )

            # Check for previous occurrence of this exact finding
            prev = (
                Finding.query
                .filter_by(asset_id=ctx.asset_id, dedupe_key=dedupe_key)
                .order_by(Finding.id.desc())
                .first()
            )

            if prev:
                # ── Existing finding: update in place, skip creation ──
                prev.last_seen_at = now
                prev.scan_job_id = ctx.scan_job_id  # Link to latest scan

                # Update fields that may have changed between scans
                prev.severity = draft.severity or prev.severity
                prev.title = draft.title[:255] if draft.title else prev.title
                prev.description = (draft.description or "")[:2000] if draft.description else prev.description
                prev.details_json = dict(draft.details) if draft.details else prev.details_json

                # Update enrichment columns if present
                if hasattr(Finding, "category") and draft.category:
                    prev.category = (draft.category or "")[:50]
                if hasattr(Finding, "remediation") and draft.remediation:
                    prev.remediation = (draft.remediation or "")[:2000]
                if hasattr(Finding, "cwe") and draft.cwe:
                    prev.cwe = (draft.cwe or "")[:20]
                if hasattr(Finding, "confidence") and draft.confidence:
                    prev.confidence = (draft.confidence or "high")[:20]
                if hasattr(Finding, "tags_json") and draft.tags:
                    prev.tags_json = draft.tags
                if hasattr(Finding, "references_json") and draft.references:
                    prev.references_json = draft.references
                if hasattr(Finding, "engine") and draft.engine:
                    prev.engine = (draft.engine or "")[:50]
                if hasattr(Finding, "analyzer") and draft.analyzer:
                    prev.analyzer = (draft.analyzer or "")[:50]

                db.session.add(prev)
                updated += 1
                continue  # ← Skip to next draft, do NOT create a new row

            # ── New finding: create it ──
            details = dict(draft.details) if draft.details else {}

            finding = Finding(
                asset_id=ctx.asset_id,
                scan_job_id=ctx.scan_job_id,
                source=draft.engine or "engine",
                finding_type=draft.finding_type or draft.template_id,
                dedupe_key=dedupe_key,
                first_seen_at=now,
                last_seen_at=now,
                title=draft.title[:255],
                severity=draft.severity or "info",
                description=(draft.description or "")[:2000],
                details_json=details,
                created_at=now,
            )

            # M7 enrichment columns — set if they exist on the model
            if hasattr(Finding, "category"):
                finding.category = (draft.category or "")[:50]
            if hasattr(Finding, "remediation"):
                finding.remediation = (draft.remediation or "")[:2000] if draft.remediation else None
            if hasattr(Finding, "cwe"):
                finding.cwe = (draft.cwe or "")[:20] if draft.cwe else None
            if hasattr(Finding, "confidence"):
                finding.confidence = (draft.confidence or "high")[:20]
            if hasattr(Finding, "tags_json"):
                finding.tags_json = draft.tags if draft.tags else None
            if hasattr(Finding, "references_json"):
                finding.references_json = draft.references if draft.references else None
            if hasattr(Finding, "engine"):
                finding.engine = (draft.engine or "")[:50] if draft.engine else None
            if hasattr(Finding, "analyzer"):
                finding.analyzer = (draft.analyzer or "")[:50] if draft.analyzer else None
            if hasattr(Finding, "template_id"):
                finding.template_id = (draft.template_id or "")[:100]

            db.session.add(finding)
            created += 1
            new_drafts.append(draft)

        # Flush all at once for performance
        if created > 0 or updated > 0:
            try:
                db.session.flush()
            except Exception as e:
                logger.exception(f"Failed to flush findings")
                db.session.rollback()
                return 0

        logger.info(
            f"persist_findings: {created} created, {updated} updated (deduped) "
            f"for asset {ctx.asset_value}"
        )

        # --- Dispatch notifications only for NEW actionable findings ---
        try:
            group = None
            if asset.group_id:
                from app.models import AssetGroup
                group = AssetGroup.query.get(asset.group_id)

            for draft in new_drafts:
                sev = (draft.severity or "info").lower()
                if sev in ("critical", "high", "medium"):
                    dispatch_event(ctx.organization_id, f"finding.{sev}", {
                        "title": draft.title,
                        "severity": sev,
                        "asset": ctx.asset_value,
                        "asset_type": ctx.asset_type,
                        "group": group.name if group else "",
                        "group_id": str(asset.group_id) if asset.group_id else "",
                        "description": (draft.description or "")[:500],
                        "category": draft.category or "",
                    })
        except Exception as e:
            logger.warning(f"Failed to dispatch finding notifications: {e}")

        return created

    def _build_dedupe_key(
        self,
        *,
        organization_id: int,
        asset_id: int,
        template_id: str,
        dedupe_fields: Dict[str, Any],
    ) -> str:
        """
        Build a deterministic deduplication key.

        The key is a SHA-1 hash of:
            org_id + asset_id + template_id + sorted dedupe_fields

        This means:
            - Same port on same asset → same dedupe_key (won't duplicate)
            - Same port on different asset → different key (separate findings)
            - Different port on same asset → different key (separate findings)
        """
        base = {
            "organization_id": organization_id,
            "asset_id": asset_id,
            "template_id": template_id,
            "fields": dedupe_fields,
        }
        return hashlib.sha1(
            _stable_json(base).encode("utf-8")
        ).hexdigest()