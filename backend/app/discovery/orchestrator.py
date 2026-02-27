# FILE: app/discovery/orchestrator.py
"""
Discovery Orchestrator — the core engine.

Key design: INCREMENTAL RESULT SAVING
- Each module's results are deduplicated and saved to DB immediately when
  the module completes (not batched at the end)
- The job's total_found / new_assets counters are updated after each module
- The frontend polls every 3s and sees assets appearing in real-time
- This means even if one module is slow, the user sees results from fast modules

Cloud asset verification:
- cloud_enum generates candidate names (unconfirmed)
- After cloud_enum completes, candidates are probed using async HTTP checks
- Only confirmed (exists=true) candidates are saved as discovered assets
- Unconfirmed candidates are still stored as metadata for later deep scans
"""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from .base_module import BaseDiscoveryModule, DiscoveredItem
from .dedup import DeduplicationEngine, MergedAsset
from .modules import get_modules_for_target

logger = logging.getLogger(__name__)

# Max subdomains to resolve IPs for in post-processing
MAX_RESOLVE = 500

# Max candidates to probe per category during discovery verification
MAX_VERIFY_STORAGE = 50
MAX_VERIFY_REGISTRIES = 30
MAX_VERIFY_SERVERLESS = 20


def _now_utc():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ═══════════════════════════════════════════════════════════════
# CLOUD CANDIDATE VERIFICATION
# ═══════════════════════════════════════════════════════════════

def _verify_cloud_candidates(cloud_items: List[DiscoveredItem]) -> List[DiscoveredItem]:
    """
    Probe cloud_enum candidates and return only confirmed ones as
    proper DiscoveredItem entries with asset_type="cloud".

    Takes the raw cloud_enum output (candidate lists per category)
    and probes each candidate via HTTP to check if it actually exists.
    Only confirmed resources are returned as DiscoveredItems.
    """
    import httpx

    confirmed_items: List[DiscoveredItem] = []

    # Group candidates by category
    storage_names: List[str] = []
    registry_names: List[str] = []
    serverless_names: List[str] = []
    serverless_paths: List[str] = []
    source_module = "cloud_enum"

    for item in cloud_items:
        meta = item.metadata or {}
        category = meta.get("cloud_category", "")
        names = meta.get("candidate_names", [])
        source_module = item.source_module or "cloud_enum"

        if category == "storage":
            storage_names.extend(names[:MAX_VERIFY_STORAGE])
        elif category == "registry":
            registry_names.extend(names[:MAX_VERIFY_REGISTRIES])
        elif category == "serverless":
            serverless_names.extend(names[:MAX_VERIFY_SERVERLESS])
            serverless_paths = meta.get("probe_paths", [
                "/api/health", "/api/status", "/health", "/healthz", "/ping",
            ])
        # cdn_origin: skipped — detected at scan time from other engine data

    total_candidates = len(storage_names) + len(registry_names) + len(serverless_names)
    if total_candidates == 0:
        return confirmed_items

    logger.info(
        "cloud_verify: probing %d candidates (%d storage, %d registry, %d serverless)",
        total_candidates, len(storage_names), len(registry_names), len(serverless_names),
    )

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        results = loop.run_until_complete(
            _probe_all_candidates(
                storage_names, registry_names, serverless_names, serverless_paths,
            )
        )
        loop.close()

        # Convert confirmed results to DiscoveredItems
        for result in results:
            provider = result.get("provider", "unknown")
            category = result.get("_category", "storage")
            name = (
                result.get("bucket_name")
                or result.get("registry_name")
                or result.get("app_name")
                or ""
            )
            url = (
                result.get("url")
                or result.get("registry_url")
                or result.get("endpoint_url")
                or ""
            )

            # Use the actual URL as the display value
            display_value = url if url else f"{provider}:{name}"

            confirmed_items.append(DiscoveredItem(
                asset_type="cloud",
                value=display_value,
                source_module=source_module,
                confidence=0.9,  # confirmed by probe
                metadata={
                    "cloud_category": category,
                    "provider": provider,
                    "resource_name": name,
                    "url": url,
                    "is_public": result.get("is_public", False),
                    "listing_enabled": result.get("listing_enabled", False),
                    "response_code": result.get("response_code"),
                    "verified": True,
                    "sensitive_files": result.get("sensitive_files", [])[:10],
                    "repositories": result.get("repositories", [])[:10],
                    "image_count": result.get("image_count", 0),
                    "accessible_paths": result.get("accessible_paths", []),
                },
            ))

        logger.info(
            "cloud_verify: %d confirmed out of %d candidates",
            len(confirmed_items), total_candidates,
        )

    except Exception as e:
        logger.exception("cloud_verify: verification failed: %s", e)

    return confirmed_items


async def _probe_all_candidates(
    storage_names: List[str],
    registry_names: List[str],
    serverless_names: List[str],
    serverless_paths: List[str],
) -> List[Dict[str, Any]]:
    """
    Probe all candidate names concurrently across all providers.
    Returns list of result dicts for confirmed (exists=true) resources.
    """
    import httpx

    confirmed: List[Dict[str, Any]] = []
    timeout = httpx.Timeout(5)
    semaphore = asyncio.Semaphore(10)

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
    ) as client:
        tasks = []

        # Storage: probe S3, Azure Blob, GCS for each name
        for name in storage_names:
            tasks.append(_probe_s3_verify(client, semaphore, name))
            tasks.append(_probe_azure_blob_verify(client, semaphore, name))
            tasks.append(_probe_gcs_verify(client, semaphore, name))

        # Registries: probe ACR, GCR, ECR Public, Docker Hub
        for name in registry_names:
            tasks.append(_probe_acr_verify(client, semaphore, name))
            tasks.append(_probe_gcr_verify(client, semaphore, name))
            tasks.append(_probe_ecr_verify(client, semaphore, name))
            tasks.append(_probe_dockerhub_verify(client, semaphore, name))

        # Serverless: probe Azure Functions
        for name in serverless_names:
            tasks.append(_probe_azure_functions_verify(
                client, semaphore, name, serverless_paths,
            ))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, Exception):
                continue
            if r and r.get("exists"):
                confirmed.append(r)

    return confirmed


# ── Storage verification probes ──

async def _probe_s3_verify(client, sem, name) -> Optional[Dict]:
    import httpx
    async with sem:
        try:
            url = f"https://{name}.s3.amazonaws.com"
            resp = await client.head(url)
            if resp.status_code == 200:
                get_resp = await client.get(url)
                listing = "<ListBucketResult" in get_resp.text
                return {
                    "_category": "storage", "provider": "aws_s3",
                    "bucket_name": name, "url": url,
                    "exists": True, "is_public": True,
                    "listing_enabled": listing, "response_code": 200,
                    "sensitive_files": [],
                }
            elif resp.status_code == 403:
                return {
                    "_category": "storage", "provider": "aws_s3",
                    "bucket_name": name, "url": url,
                    "exists": True, "is_public": False,
                    "listing_enabled": False, "response_code": 403,
                }
        except (httpx.RequestError, httpx.HTTPStatusError):
            pass
    return None


async def _probe_azure_blob_verify(client, sem, name) -> Optional[Dict]:
    import httpx
    async with sem:
        try:
            url = f"https://{name}.blob.core.windows.net"
            resp = await client.head(url)
            if resp.status_code in (200, 400):
                list_url = f"{url}?comp=list&restype=container"
                list_resp = await client.get(list_url)
                is_public = list_resp.status_code == 200
                listing = is_public and "<EnumerationResults" in list_resp.text
                return {
                    "_category": "storage", "provider": "azure_blob",
                    "bucket_name": name, "url": url,
                    "exists": True, "is_public": is_public,
                    "listing_enabled": listing, "response_code": resp.status_code,
                }
        except (httpx.RequestError, httpx.HTTPStatusError):
            pass
    return None


async def _probe_gcs_verify(client, sem, name) -> Optional[Dict]:
    import httpx
    async with sem:
        try:
            url = f"https://storage.googleapis.com/{name}"
            resp = await client.get(url)
            if resp.status_code == 200:
                body = resp.text
                listing = "<ListBucketResult" in body or '"kind": "storage#objects"' in body
                return {
                    "_category": "storage", "provider": "gcs",
                    "bucket_name": name, "url": url,
                    "exists": True, "is_public": True,
                    "listing_enabled": listing, "response_code": 200,
                }
            elif resp.status_code == 403:
                return {
                    "_category": "storage", "provider": "gcs",
                    "bucket_name": name, "url": url,
                    "exists": True, "is_public": False,
                    "listing_enabled": False, "response_code": 403,
                }
        except (httpx.RequestError, httpx.HTTPStatusError):
            pass
    return None


# ── Registry verification probes ──

async def _probe_acr_verify(client, sem, name) -> Optional[Dict]:
    import httpx
    async with sem:
        try:
            url = f"https://{name}.azurecr.io/v2/_catalog"
            resp = await client.get(url)
            if resp.status_code == 200:
                repos = []
                try:
                    repos = resp.json().get("repositories", [])[:20]
                except Exception:
                    pass
                return {
                    "_category": "registry", "provider": "acr",
                    "registry_name": name, "registry_url": f"https://{name}.azurecr.io",
                    "exists": True, "is_public": True,
                    "repositories": repos, "image_count": len(repos),
                    "response_code": 200,
                }
            elif resp.status_code == 401:
                return {
                    "_category": "registry", "provider": "acr",
                    "registry_name": name, "registry_url": f"https://{name}.azurecr.io",
                    "exists": True, "is_public": False,
                    "repositories": [], "image_count": 0,
                    "response_code": 401,
                }
        except (httpx.RequestError, httpx.HTTPStatusError):
            pass
    return None


async def _probe_gcr_verify(client, sem, name) -> Optional[Dict]:
    import httpx
    async with sem:
        try:
            url = f"https://gcr.io/v2/{name}/tags/list"
            resp = await client.get(url)
            if resp.status_code == 200:
                tags = []
                try:
                    tags = resp.json().get("tags", [])
                except Exception:
                    pass
                return {
                    "_category": "registry", "provider": "gcr",
                    "registry_name": name, "registry_url": f"https://gcr.io/{name}",
                    "exists": True, "is_public": True,
                    "repositories": [name], "image_count": len(tags),
                    "response_code": 200,
                }
            elif resp.status_code == 401:
                return {
                    "_category": "registry", "provider": "gcr",
                    "registry_name": name, "registry_url": f"https://gcr.io/{name}",
                    "exists": True, "is_public": False,
                    "repositories": [], "image_count": 0,
                    "response_code": 401,
                }
        except (httpx.RequestError, httpx.HTTPStatusError):
            pass
    return None


async def _probe_ecr_verify(client, sem, name) -> Optional[Dict]:
    import httpx
    async with sem:
        try:
            url = f"https://public.ecr.aws/v2/{name}/tags/list"
            resp = await client.get(url)
            if resp.status_code == 200:
                tags = []
                try:
                    tags = resp.json().get("tags", [])
                except Exception:
                    pass
                return {
                    "_category": "registry", "provider": "ecr_public",
                    "registry_name": name, "registry_url": f"https://public.ecr.aws/{name}",
                    "exists": True, "is_public": True,
                    "repositories": [name], "image_count": len(tags),
                    "response_code": 200,
                }
        except (httpx.RequestError, httpx.HTTPStatusError):
            pass
    return None


async def _probe_dockerhub_verify(client, sem, name) -> Optional[Dict]:
    import httpx
    async with sem:
        try:
            url = f"https://hub.docker.com/v2/repositories/{name}/"
            resp = await client.get(url)
            if resp.status_code == 200:
                repos = []
                count = 0
                try:
                    data = resp.json()
                    repos = [r.get("name", "") for r in data.get("results", [])[:20]]
                    count = data.get("count", len(repos))
                except Exception:
                    pass
                # Only confirm if there are actual repositories
                if count > 0:
                    return {
                    "_category": "registry", "provider": "dockerhub",
                    "registry_name": name,
                    "registry_url": f"https://hub.docker.com/u/{name}",
                    "exists": True, "is_public": True,
                    "repositories": repos, "image_count": count,
                    "response_code": 200,
                }
        except (httpx.RequestError, httpx.HTTPStatusError):
            pass
    return None


# ── Serverless verification probes ──

async def _probe_azure_functions_verify(client, sem, name, paths) -> Optional[Dict]:
    import httpx
    async with sem:
        try:
            base_url = f"https://{name}.azurewebsites.net"
            resp = await client.get(base_url)
            if resp.status_code == 404:
                return None

            accessible_paths = []
            for path in (paths or [])[:5]:
                try:
                    pr = await client.get(f"{base_url}{path}")
                    if pr.status_code == 200:
                        accessible_paths.append(path)
                except (httpx.RequestError, httpx.HTTPStatusError):
                    continue

            return {
                "_category": "serverless", "provider": "azure_functions",
                "app_name": name, "endpoint_url": base_url,
                "exists": True,
                "is_public": bool(accessible_paths),
                "accessible_paths": accessible_paths,
                "response_code": resp.status_code,
            }
        except (httpx.RequestError, httpx.HTTPStatusError):
            pass
    return None


# ═══════════════════════════════════════════════════════════════
# ORCHESTRATOR CLASS
# ═══════════════════════════════════════════════════════════════

class DiscoveryOrchestrator:
    """
    Runs a discovery job: selects modules, executes them in parallel,
    saves results incrementally as each module completes.
    """

    def __init__(self, app=None):
        self.app = app

    def run_discovery(
        self,
        job_id: int,
        org_id: int,
        target: str,
        target_type: str,
        plan: str,
        config: dict = None,
        existing_asset_values: Set[str] = None,
    ) -> dict:
        config = config or {}
        existing = existing_asset_values or set()

        # ── Cloud assets don't need discovery — they're already exact URLs ──
        if target_type == "cloud":
            logger.info(
                "Discovery job #%d: target_type=cloud — skipping discovery "
                "(cloud assets are already exact URLs)", job_id,
            )
            self._update_job_completed(
                job_id=job_id,
                status="completed",
                total_found=0,
                new_assets=0,
                counts_by_type={},
                error=None,
            )
            return {"total_found": 0, "new_assets": 0, "counts_by_type": {}}

        modules = get_modules_for_target(plan, target_type)

        if not modules:
            logger.warning("No eligible modules for plan=%s target_type=%s", plan, target_type)
            self._update_job_status(job_id, "failed", error="No discovery modules available for your plan.")
            return {"total_found": 0, "new_assets": 0, "counts_by_type": {}}

        # ── Inject cloud_enum config from request body ──
        if config.get("company_name") or config.get("brand_keywords") or config.get("custom_bases"):
            cloud_config = {
                "company_name": config.get("company_name", ""),
                "brand_keywords": config.get("brand_keywords", []),
                "custom_bases": config.get("custom_bases", []),
            }
            config["cloud_enum"] = {**config.get("cloud_enum", {}), **cloud_config}
            logger.info(
                "Discovery job #%d: cloud_enum config injected — "
                "company_name=%s, brand_keywords=%s, custom_bases=%d",
                job_id,
                cloud_config["company_name"],
                cloud_config["brand_keywords"],
                len(cloud_config["custom_bases"]),
            )

        module_names = [m.name for m in modules]
        logger.info(
            "Discovery job #%d: target=%s type=%s plan=%s modules=%s",
            job_id, target, target_type, plan, module_names,
        )

        self._update_job_started(job_id, module_names)
        self._create_module_results(job_id, module_names)

        # Track what we've already saved (to avoid dupes across modules)
        saved_values: Set[str] = set(existing)
        total_found = 0
        total_new = 0
        counts_by_type: dict = {}
        module_errors = []

        # Track raw cloud_enum results before they go through dedup.
        cloud_discovery_items: List[DiscoveredItem] = []

        # Scale timeout based on discovery depth
        scan_depth = config.get("scan_depth", "standard")
        timeout_map = {"standard": 300, "deep": 1800}
        module_timeout = timeout_map.get(scan_depth, 300)

        with ThreadPoolExecutor(max_workers=min(len(modules), 4)) as executor:
            future_to_module = {}
            for module in modules:
                future = executor.submit(self._run_module, module, target, target_type, config, job_id)
                future_to_module[future] = module

            for future in as_completed(future_to_module):
                module = future_to_module[future]
                try:
                    items = future.result(timeout=module_timeout)

                    # ── Special handling for cloud_enum ──
                    # Don't pass raw cloud candidates through the normal
                    # dedup → store pipeline. Instead, verify them first
                    # and only save confirmed resources.
                    if module.name == "cloud_enum" and items:
                        cloud_discovery_items.extend(items)

                        # Verify candidates by actually probing them
                        logger.info(
                            "cloud_verify: starting verification of "
                            "cloud_enum candidates for job #%d", job_id,
                        )

                        verified_items = _verify_cloud_candidates(items)

                        if verified_items:
                            # Run verified items through normal dedup → store
                            dedup = DeduplicationEngine(saved_values)
                            dedup.add_results(verified_items)
                            dedup.correlate()

                            merged = dedup.get_results()
                            stats = dedup.get_stats()

                            if merged:
                                self._store_discovered_assets(job_id, org_id, merged)
                                for asset in merged:
                                    saved_values.add(asset.value.strip().lower())

                            total_found += stats["total"]
                            total_new += stats["new"]
                            for t, c in stats.get("by_type", {}).items():
                                counts_by_type[t] = counts_by_type.get(t, 0) + c

                            self._update_job_progress(
                                job_id, total_found, total_new, counts_by_type,
                            )
                            self._update_module_result(
                                job_id, module.name, "completed", stats["total"],
                            )
                            logger.info(
                                "cloud_enum completed: %d verified, %d new",
                                stats["total"], stats["new"],
                            )
                        else:
                            self._update_module_result(
                                job_id, module.name, "completed", 0,
                            )
                            logger.info(
                                "cloud_enum completed: 0 candidates verified",
                            )

                        continue  # Skip normal dedup/store for cloud_enum

                    # ── Normal module handling (non-cloud) ──
                    dedup = DeduplicationEngine(saved_values)
                    dedup.add_results(items)
                    dedup.correlate()

                    merged = dedup.get_results()
                    stats = dedup.get_stats()

                    # Save immediately
                    if merged:
                        self._store_discovered_assets(job_id, org_id, merged)
                        for asset in merged:
                            saved_values.add(asset.value.strip().lower())

                    # Update running totals
                    total_found += stats["total"]
                    total_new += stats["new"]
                    for t, c in stats.get("by_type", {}).items():
                        counts_by_type[t] = counts_by_type.get(t, 0) + c

                    # Update job counters so frontend sees progress
                    self._update_job_progress(job_id, total_found, total_new, counts_by_type)
                    self._update_module_result(job_id, module.name, "completed", stats["total"])

                    logger.info(
                        "Module %s completed: %d items (%d new)",
                        module.name, stats["total"], stats["new"],
                    )

                except Exception as e:
                    logger.error("Module %s failed: %s", module.name, e, exc_info=True)
                    module_errors.append({"module": module.name, "error": str(e)})
                    self._update_module_result(
                        job_id, module.name, "failed", 0, error=str(e),
                    )

        # Store cloud discovery metadata on Asset records so the scanner
        # orchestrator can load candidates for the cloud_asset engine.
        if cloud_discovery_items:
            self._store_cloud_discovery_metadata(org_id, target, cloud_discovery_items)

        # Resolve IPs for any domain/subdomain assets that don't have them yet
        self._resolve_missing_ips(job_id)

        # Auto-tag assets based on metadata and scope
        self._auto_tag_assets(job_id, target, target_type)

        # Final status
        if module_errors and len(module_errors) == len(modules):
            status = "failed"
        elif module_errors:
            status = "partial"
        else:
            status = "completed"

        self._update_job_completed(
            job_id=job_id,
            status=status,
            total_found=total_found,
            new_assets=total_new,
            counts_by_type=counts_by_type,
            error="; ".join(e["error"] for e in module_errors) if module_errors else None,
        )

        logger.info(
            "Discovery job #%d %s: %d total, %d new, types=%s",
            job_id, status, total_found, total_new, counts_by_type,
        )

        return {
            "total_found": total_found,
            "new_assets": total_new,
            "counts_by_type": counts_by_type,
            "errors": module_errors,
        }

    def _run_module(
        self,
        module: BaseDiscoveryModule,
        target: str,
        target_type: str,
        config: dict,
        job_id: int,
    ) -> List[DiscoveredItem]:
        """Run a single module (called in a thread)."""
        self._update_module_result(job_id, module.name, "running", 0)
        start = time.monotonic()
        try:
            items = module.discover(target, target_type, config)
            return items or []
        finally:
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.debug("Module %s took %dms", module.name, duration_ms)

    # ── Database helpers ──

    def _with_context(self, fn, *args, **kwargs):
        """Run fn within an app context if we have an app, otherwise run directly."""
        try:
            if self.app:
                with self.app.app_context():
                    return fn(*args, **kwargs)
            else:
                return fn(*args, **kwargs)
        except Exception as e:
            logger.error("DB operation failed: %s", e, exc_info=True)

    def _update_job_started(self, job_id: int, module_names: List[str]):
        def _do():
            from app.extensions import db
            from app.models import DiscoveryJob
            job = db.session.get(DiscoveryJob, job_id)
            if job:
                job.status = "running"
                job.started_at = _now_utc()
                job.modules_run = module_names
                db.session.commit()
        self._with_context(_do)

    def _update_job_status(self, job_id: int, status: str, error: str = None):
        def _do():
            from app.extensions import db
            from app.models import DiscoveryJob
            job = db.session.get(DiscoveryJob, job_id)
            if job:
                job.status = status
                if error:
                    job.error_message = error[:1000]
                db.session.commit()
        self._with_context(_do)

    def _update_job_progress(self, job_id: int, total_found: int, new_assets: int, counts_by_type: dict):
        """Update job counters mid-run so the frontend sees incremental progress."""
        def _do():
            from app.extensions import db
            from app.models import DiscoveryJob
            job = db.session.get(DiscoveryJob, job_id)
            if job:
                job.total_found = total_found
                job.new_assets = new_assets
                job.counts_by_type = counts_by_type
                db.session.commit()
        self._with_context(_do)

    def _update_job_completed(self, job_id, status, total_found, new_assets, counts_by_type, error=None):
        def _do():
            from app.extensions import db
            from app.models import DiscoveryJob
            job = db.session.get(DiscoveryJob, job_id)
            if job:
                job.status = status
                job.total_found = total_found
                job.new_assets = new_assets
                job.counts_by_type = counts_by_type
                job.completed_at = _now_utc()
                if error:
                    job.error_message = error[:1000]
                db.session.commit()
        self._with_context(_do)

    def _create_module_results(self, job_id: int, module_names: List[str]):
        def _do():
            from app.extensions import db
            from app.models import DiscoveryModuleResult
            for name in module_names:
                db.session.add(DiscoveryModuleResult(
                    job_id=job_id, module_name=name, status="pending",
                ))
            db.session.commit()
        self._with_context(_do)

    def _update_module_result(
        self, job_id: int, module_name: str, status: str,
        assets_found: int, error: str = None,
    ):
        def _do():
            from app.extensions import db
            from app.models import DiscoveryModuleResult
            mr = DiscoveryModuleResult.query.filter_by(
                job_id=job_id, module_name=module_name,
            ).first()
            if mr:
                mr.status = status
                mr.assets_found = assets_found
                if status == "running":
                    mr.started_at = _now_utc()
                if status in ("completed", "failed"):
                    mr.completed_at = _now_utc()
                    if mr.started_at:
                        mr.duration_ms = int(
                            (_now_utc() - mr.started_at).total_seconds() * 1000
                        )
                if error:
                    mr.error = error
                db.session.commit()
        self._with_context(_do)

    def _store_cloud_discovery_metadata(
        self,
        org_id: int,
        target: str,
        cloud_items: List[DiscoveredItem],
    ):
        """
        Store cloud_enum discovery metadata on the Asset record so the
        scanner orchestrator can load it for the cloud_asset engine.
        """
        def _do():
            from app.extensions import db
            from app.models import Asset
            from sqlalchemy.orm.attributes import flag_modified

            asset = Asset.query.filter_by(
                organization_id=org_id,
                value=target.strip().lower(),
            ).first()

            if not asset:
                logger.warning(
                    "Cannot store cloud discovery metadata: no Asset found for "
                    "org_id=%d target=%s", org_id, target,
                )
                return

            cloud_discovery = []
            for item in cloud_items:
                meta = item.metadata or {}
                category = meta.get("cloud_category")
                if not category:
                    continue

                cloud_discovery.append({
                    "cloud_category": category,
                    "candidate_names": meta.get("candidate_names", []),
                    "candidate_count": meta.get("candidate_count", 0),
                    "providers": meta.get("providers", []),
                    "probe_paths": meta.get("probe_paths", []),
                    "base_words": meta.get("base_words", []),
                    "note": meta.get("note", ""),
                })

            if not cloud_discovery:
                return

            metadata = asset.metadata_json or {}
            metadata["cloud_discovery"] = cloud_discovery
            asset.metadata_json = metadata
            flag_modified(asset, "metadata_json")

            db.session.commit()

            total_candidates = sum(
                d.get("candidate_count", 0) for d in cloud_discovery
            )
            categories = [d["cloud_category"] for d in cloud_discovery]
            logger.info(
                "Stored cloud discovery metadata on Asset '%s': "
                "%d categories (%s), %d total candidates",
                target, len(categories), ", ".join(categories), total_candidates,
            )

        self._with_context(_do)

    def _auto_tag_assets(self, job_id: int, target: str, target_type: str):
        """Auto-tag discovered assets based on metadata and scope."""
        def _do():
            from app.extensions import db
            from app.models import DiscoveredAsset
            from sqlalchemy.orm.attributes import flag_modified

            apex = target.strip().lower().rstrip(".")

            assets = DiscoveredAsset.query.filter_by(job_id=job_id).all()
            tagged_count = 0

            for asset in assets:
                tags = list(asset.tags or [])
                info = asset.extra_info or {}
                val = (asset.value or "").strip().lower()

                if target_type == "domain" and asset.asset_type in ("domain", "subdomain"):
                    if val == apex or val.endswith("." + apex):
                        if "in-scope" not in tags:
                            tags.append("in-scope")
                    else:
                        if "out-of-scope" not in tags:
                            tags.append("out-of-scope")

                role = info.get("role", "")
                if role == "nameserver" and "nameserver" not in tags:
                    tags.append("nameserver")

                if any(x in val for x in (
                    "mail", "smtp", "imap", "pop3", "mx", "exchange", "owa",
                )):
                    if "mail" not in tags:
                        tags.append("mail")

                cdn_indicators = (
                    "cdn", "akamai", "akam", "cloudfront", "fastly",
                    "cloudflare", "edgecast", "incapsula", "stackpath",
                )
                if any(x in val for x in cdn_indicators):
                    if "cdn" not in tags:
                        tags.append("cdn")

                if (info.get("historical")
                        or info.get("discovered_via") == "wayback_machine"):
                    if "historical" not in tags:
                        tags.append("historical")

                env_indicators = (
                    "dev", "test", "staging", "stage", "qa", "uat",
                    "beta", "alpha", "sandbox", "preprod", "demo",
                )
                parts = val.replace(".", " ").replace("-", " ").split()
                if any(p in env_indicators for p in parts):
                    if "dev-staging" not in tags:
                        tags.append("dev-staging")

                if any(p in (
                    "api", "api2", "api3", "graphql", "rest", "ws", "wss",
                ) for p in parts):
                    if "api" not in tags:
                        tags.append("api")

                if asset.asset_type == "cloud":
                    if "cloud" not in tags:
                        tags.append("cloud")

                if tags != list(asset.tags or []):
                    asset.tags = tags
                    flag_modified(asset, "tags")
                    tagged_count += 1

            if tagged_count:
                db.session.commit()
                logger.info(
                    "Auto-tagged %d assets in job #%d", tagged_count, job_id,
                )

        self._with_context(_do)

    def _resolve_missing_ips(self, job_id: int):
        """Post-processing: resolve IPs for domain/subdomain assets."""
        import socket

        def _do():
            from app.extensions import db
            from app.models import DiscoveredAsset

            assets = DiscoveredAsset.query.filter_by(job_id=job_id).filter(
                DiscoveredAsset.asset_type.in_(["domain", "subdomain"])
            ).limit(MAX_RESOLVE).all()

            resolved_count = 0
            for asset in assets:
                info = asset.extra_info or {}
                if info.get("resolved_ips"):
                    continue

                try:
                    results = socket.getaddrinfo(asset.value, None)
                    ips = list(dict.fromkeys(sa[0] for *_, sa in results))
                    if ips:
                        info["resolved_ips"] = ips
                        asset.extra_info = info
                        from sqlalchemy.orm.attributes import flag_modified
                        flag_modified(asset, "extra_info")
                        resolved_count += 1
                except (socket.gaierror, socket.herror, OSError):
                    pass

            if resolved_count:
                db.session.commit()
                logger.info(
                    "Resolved IPs for %d assets in job #%d",
                    resolved_count, job_id,
                )

        self._with_context(_do)

    def _store_discovered_assets(
        self, job_id: int, org_id: int, merged: List[MergedAsset],
    ):
        def _do():
            import json
            from app.extensions import db
            from app.models import DiscoveredAsset, IgnoredDiscoveredAsset

            ignored_rows = IgnoredDiscoveredAsset.query.filter_by(
                organization_id=org_id,
            ).with_entities(
                IgnoredDiscoveredAsset.asset_type,
                IgnoredDiscoveredAsset.value,
            ).all()
            ignored_set = {
                (r.asset_type, r.value.strip().lower()) for r in ignored_rows
            }

            saved = 0
            merged_count = 0

            for asset in merged:
                val_lower = asset.value.strip().lower()
                is_ignored = (asset.asset_type, val_lower) in ignored_set

                existing = DiscoveredAsset.query.filter_by(
                    job_id=job_id,
                    asset_type=asset.asset_type,
                    value=asset.value,
                ).first()

                if existing:
                    try:
                        old_sources = (
                            json.loads(existing.sources)
                            if isinstance(existing.sources, str)
                            else (existing.sources or [])
                        )
                    except (json.JSONDecodeError, TypeError):
                        old_sources = []
                    try:
                        new_sources = (
                            json.loads(asset.sources)
                            if isinstance(asset.sources, str)
                            else (asset.sources or [])
                        )
                    except (json.JSONDecodeError, TypeError):
                        new_sources = []

                    combined = list(dict.fromkeys(old_sources + new_sources))
                    existing.sources = (
                        json.dumps(combined)
                        if isinstance(existing.sources, str)
                        else combined
                    )

                    if asset.confidence and asset.confidence > (existing.confidence or 0):
                        existing.confidence = asset.confidence

                    try:
                        old_meta = (
                            json.loads(existing.extra_info)
                            if isinstance(existing.extra_info, str)
                            else (existing.extra_info or {})
                        )
                    except (json.JSONDecodeError, TypeError):
                        old_meta = {}
                    try:
                        new_meta = (
                            json.loads(asset.metadata)
                            if isinstance(asset.metadata, str)
                            else (asset.metadata or {})
                        )
                    except (json.JSONDecodeError, TypeError):
                        new_meta = {}

                    for k, v in new_meta.items():
                        if k not in old_meta:
                            old_meta[k] = v
                        elif k == "resolved_ips" and isinstance(v, list):
                            old_ips = old_meta.get("resolved_ips", [])
                            old_meta["resolved_ips"] = list(
                                dict.fromkeys(old_ips + v)
                            )

                    existing.extra_info = (
                        json.dumps(old_meta)
                        if isinstance(existing.extra_info, str)
                        else old_meta
                    )

                    from sqlalchemy.orm.attributes import flag_modified
                    flag_modified(existing, "sources")
                    flag_modified(existing, "extra_info")

                    merged_count += 1
                else:
                    da = DiscoveredAsset(
                        job_id=job_id,
                        organization_id=org_id,
                        asset_type=asset.asset_type,
                        value=asset.value,
                        original_value=asset.original_value,
                        sources=asset.sources,
                        confidence=asset.confidence,
                        extra_info=asset.metadata,
                        is_new=asset.is_new and not is_ignored,
                    )
                    if is_ignored:
                        da.tags = ["ignored"]
                    db.session.add(da)
                    saved += 1

            try:
                db.session.commit()
                if merged_count:
                    logger.info(
                        "Stored %d new + merged %d existing assets for job #%d",
                        saved, merged_count, job_id,
                    )
            except Exception as e:
                db.session.rollback()
                logger.error("Failed to commit discovered assets: %s", e)
                raise

        self._with_context(_do)