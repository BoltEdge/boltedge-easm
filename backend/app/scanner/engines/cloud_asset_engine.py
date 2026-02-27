# app/scanner/engines/cloud_asset_engine.py
"""
Cloud Asset Engine — probes for publicly accessible cloud resources.

Two operating modes:

  A. CANDIDATE MODE (discovery-driven):
     Receives candidate names from cloud_enum discovery module and checks
     whether those resources exist and are publicly accessible.

  B. DIRECT PROBE MODE (manually-added cloud assets):
     Receives a single cloud URL via config["direct_probe"] and probes
     that specific resource directly. Skips candidate iteration entirely.

Four categories:
  1. Storage Buckets    — S3, Azure Blob, GCS
  2. Container Registries — ECR Public, ACR, GCR, Docker Hub
  3. Serverless Endpoints — Azure Functions, Cloud Run
  4. CDN Origin Exposure  — CloudFront, Cloudflare, Azure CDN, Fastly, Akamai

Extends BaseEngine. Returns EngineResult with raw probe data.
Never classifies severity — that's the analyser's job.

Requires: httpx (async HTTP client)
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree

import httpx

from app.scanner.base import BaseEngine, EngineResult, ScanContext

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# KNOWN CDN IP RANGES (CIDR prefixes for detection)
# These are well-known CDN provider address blocks.
# Updated periodically — not exhaustive but covers major providers.
# ═══════════════════════════════════════════════════════════════

CDN_PROVIDERS: Dict[str, List[str]] = {
    "cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ],
    "cloudfront": [
        "13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14",
        "13.249.0.0/16", "18.64.0.0/14", "18.160.0.0/15",
        "52.84.0.0/15", "54.182.0.0/16", "54.192.0.0/16",
        "54.230.0.0/16", "54.239.128.0/18", "54.239.192.0/19",
        "99.84.0.0/16", "99.86.0.0/16", "143.204.0.0/16",
        "204.246.164.0/22", "204.246.168.0/22", "205.251.192.0/19",
    ],
    "fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
        "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
        "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17",
        "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
        "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
        "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21",
        "199.232.0.0/16",
    ],
    "akamai": [
        "23.0.0.0/12", "23.32.0.0/11", "23.64.0.0/14",
        "23.192.0.0/11", "72.246.0.0/15", "96.6.0.0/15",
        "96.16.0.0/15", "104.64.0.0/10", "184.24.0.0/13",
        "184.50.0.0/15", "184.84.0.0/14",
    ],
}

# Pre-compile networks for fast lookup
_CDN_NETWORKS: Dict[str, List[ipaddress.IPv4Network]] = {}
for _provider, _cidrs in CDN_PROVIDERS.items():
    _CDN_NETWORKS[_provider] = [ipaddress.ip_network(c) for c in _cidrs]


# Sensitive file extensions to check in public storage buckets
SENSITIVE_EXTENSIONS = {
    ".env", ".sql", ".csv", ".pem", ".key", ".bak", ".backup",
    ".dump", ".sqlite", ".db", ".mdb", ".tar", ".tar.gz", ".tgz",
    ".zip", ".7z", ".rar", ".pfx", ".p12", ".jks", ".conf",
    ".config", ".yml", ".yaml", ".json", ".xml", ".log",
    ".credentials", ".htpasswd", ".pgpass", ".npmrc", ".dockercfg",
}

# Default configuration
DEFAULT_CONFIG = {
    "timeout": 3,           # Per-request timeout (seconds)
    "delay": 0.2,           # Delay between requests (rate limiting)
    "max_concurrent": 5,    # Max concurrent HTTP requests
    "max_storage": 100,     # Max storage candidates to probe
    "max_registries": 50,   # Max registry candidates to probe
    "max_serverless": 30,   # Max serverless candidates to probe
    "check_storage": True,
    "check_registries": True,
    "check_serverless": True,
    "check_cdn_origin": True,
}

# Maps provider keys to the probe method + category
PROVIDER_TO_PROBE = {
    # Storage
    "aws_s3":           ("storage",    "_probe_s3"),
    "azure_blob":       ("storage",    "_probe_azure_blob"),
    "gcs":              ("storage",    "_probe_gcs"),
    # Registries
    "acr":              ("registry",   "_probe_acr"),
    "gcr":              ("registry",   "_probe_gcr"),
    "ecr_public":       ("registry",   "_probe_ecr_public"),
    "ecr":              ("registry",   "_probe_ecr_public"),
    "dockerhub":        ("registry",   "_probe_dockerhub"),
    # Serverless
    "azure_functions":  ("serverless", "_probe_azure_functions"),
    "cloud_run":        ("serverless", "_probe_cloud_run"),
    "cloud_functions":  ("serverless", None),  # Not yet implemented
    "aws_lambda":       ("serverless", None),
    "aws_apigateway":   ("serverless", None),
}


# ═══════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def _identify_cdn_provider(ip_str: str) -> Optional[str]:
    """Check if an IP belongs to a known CDN provider."""
    try:
        addr = ipaddress.ip_address(ip_str)
        for provider, networks in _CDN_NETWORKS.items():
            for network in networks:
                if addr in network:
                    return provider
    except ValueError:
        pass
    return None


def _extract_sensitive_files(body: str) -> List[str]:
    """Extract sensitive filenames from an XML bucket listing."""
    found = []
    try:
        root = ElementTree.fromstring(body)
        # S3 XML uses namespace
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"
        for key_elem in root.iter(f"{ns}Key"):
            name = (key_elem.text or "").lower()
            for ext in SENSITIVE_EXTENSIONS:
                if name.endswith(ext):
                    found.append(key_elem.text)
                    break
    except ElementTree.ParseError:
        # Not XML — try line-by-line (GCS sometimes returns JSON-like)
        for ext in SENSITIVE_EXTENSIONS:
            if ext in body.lower():
                found.append(f"*{ext}")
    return found[:50]  # Cap to avoid huge lists


# ═══════════════════════════════════════════════════════════════
# ENGINE CLASS
# ═══════════════════════════════════════════════════════════════

class CloudAssetEngine(BaseEngine):
    """
    Probes for publicly accessible cloud assets.

    Two modes:
      A. Candidate mode: reads candidate names from cloud_enum discovery
         results in ScanContext and probes across 4 categories.
      B. Direct probe mode: probes a single cloud URL specified in
         config["direct_probe"] (for manually added cloud assets).

    Returns raw probe results in EngineResult.data for the analyser.
    """

    name = "cloud_asset"
    description = "Cloud asset exposure detection (storage, registries, serverless, CDN)"
    @property
    def supported_asset_types(self):
        return ["domain", "cloud"]

    def execute(self, context: ScanContext, config: dict = None) -> EngineResult:
        """
        Run cloud asset probing.

        If config contains "direct_probe", runs single-target direct mode.
        Otherwise, reads candidates from context.discovery_metadata.
        """
        cfg = {**DEFAULT_CONFIG, **(config or {})}

        # Route to direct probe if configured
        direct = cfg.get("direct_probe")
        if direct:
            return self._execute_direct(context, cfg, direct)

        # Otherwise: candidate-based probing (original logic)
        return self._execute_candidates(context, cfg)

    # ─────────────────────────────────────────────────────
    # MODE B: Direct Probe (single cloud URL)
    # ─────────────────────────────────────────────────────

    def _execute_direct(
        self,
        context: ScanContext,
        cfg: dict,
        direct: Dict[str, Any],
    ) -> EngineResult:
        """
        Probe a single cloud resource directly.

        direct = {
            "cloud_category": "storage",
            "provider": "aws_s3",
            "url": "https://mybucket.s3.amazonaws.com",
            "name": "mybucket",
        }
        """
        start = time.time()
        errors: List[str] = []
        data: Dict[str, Any] = {
            "storage": {"results": [], "candidates_checked": 0},
            "registries": {"results": [], "candidates_checked": 0},
            "serverless": {"results": [], "candidates_checked": 0},
            "cdn_origin": {"results": [], "domains_checked": 0},
            "direct_probe": True,
        }

        provider = direct.get("provider", "other")
        cloud_category = direct.get("cloud_category", "storage")
        name = direct.get("name", "")
        url = direct.get("url", "")

        if not name:
            errors.append("Direct probe: no resource name extracted from URL")
            return EngineResult(
                engine_name=self.name,
                success=False,
                data=data,
                metadata={"direct_probe": True, "provider": provider},
                errors=errors,
                duration_seconds=time.time() - start,
            )

        logger.info(
            f"cloud_asset: direct probe — {provider}/{cloud_category} "
            f"name='{name}' url='{url}'"
        )

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            probe_info = PROVIDER_TO_PROBE.get(provider)

            if probe_info:
                category_key, method_name = probe_info

                if method_name and hasattr(self, method_name):
                    # Map category to data key
                    data_key_map = {
                        "storage": "storage",
                        "registry": "registries",
                        "serverless": "serverless",
                    }
                    data_key = data_key_map.get(category_key, "storage")

                    result = loop.run_until_complete(
                        self._run_single_probe(method_name, name, cfg)
                    )
                    if result:
                        data[data_key]["results"].append(result)
                        data[data_key]["candidates_checked"] = 1
                else:
                    # Provider recognized but no probe method — try generic
                    logger.info(f"No specific probe for provider {provider}, trying generic")
                    result = loop.run_until_complete(
                        self._probe_generic_url(url, provider, cloud_category, cfg)
                    )
                    if result:
                        data_key = {"storage": "storage", "registry": "registries", "serverless": "serverless"}.get(cloud_category, "storage")
                        data[data_key]["results"].append(result)
                        data[data_key]["candidates_checked"] = 1
            else:
                # Unknown provider — probe the URL generically
                result = loop.run_until_complete(
                    self._probe_generic_url(url, provider, cloud_category, cfg)
                )
                if result:
                    data_key = {"storage": "storage", "registry": "registries", "serverless": "serverless"}.get(cloud_category, "storage")
                    data[data_key]["results"].append(result)
                    data[data_key]["candidates_checked"] = 1

            # Also check CDN origin if we have resolved IPs
            if cfg.get("check_cdn_origin") and context.resolved_ips:
                try:
                    cdn_results = self._check_cdn_origin(context)
                    data["cdn_origin"]["results"] = cdn_results
                    data["cdn_origin"]["domains_checked"] = len(cdn_results)
                except Exception as e:
                    errors.append(f"CDN origin check error: {e}")

            loop.close()

        except Exception as e:
            errors.append(f"Direct probe error: {e}")
            logger.exception("cloud_asset: direct probe failed")

        duration = time.time() - start
        total_found = sum(
            len([r for r in data[cat]["results"]
                 if r.get("exists") or r.get("is_accessible") or r.get("origin_accessible")])
            for cat in data if isinstance(data[cat], dict) and "results" in data[cat]
        )

        return EngineResult(
            engine_name=self.name,
            success=len(errors) == 0,
            data=data,
            metadata={
                "direct_probe": True,
                "provider": provider,
                "cloud_category": cloud_category,
                "resource_name": name,
                "total_assets_found": total_found,
            },
            errors=errors,
            duration_seconds=duration,
        )

    async def _run_single_probe(
        self,
        method_name: str,
        name: str,
        cfg: dict,
    ) -> Optional[Dict[str, Any]]:
        """Run a single probe method by name with a fresh HTTP client."""
        timeout = httpx.Timeout(cfg.get("timeout", 3))
        semaphore = asyncio.Semaphore(1)

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            method = getattr(self, method_name)

            if method_name in ("_probe_azure_functions", "_probe_cloud_run"):
                # Serverless probes take extra paths argument
                paths = ["/api/health", "/api/status", "/health", "/healthz", "/ping"]
                return await method(client, semaphore, name, paths, cfg)
            else:
                return await method(client, semaphore, name, cfg)

    async def _probe_generic_url(
        self,
        url: str,
        provider: str,
        cloud_category: str,
        cfg: dict,
    ) -> Optional[Dict[str, Any]]:
        """
        Generic probe for cloud URLs where we don't have a specific probe method.
        Just checks if the URL is accessible and what it returns.
        """
        timeout = httpx.Timeout(cfg.get("timeout", 3))

        result = {
            "provider": provider,
            "url": url,
            "exists": False,
            "is_public": False,
            "is_accessible": False,
            "response_code": None,
            "response_type": None,
            "leaked_info": [],
        }

        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.get(url)
                result["response_code"] = resp.status_code

                if resp.status_code == 200:
                    result["exists"] = True
                    result["is_public"] = True
                    result["is_accessible"] = True

                    ct = resp.headers.get("content-type", "")
                    if "json" in ct:
                        result["response_type"] = "json"
                    elif "xml" in ct:
                        result["response_type"] = "xml"
                    elif "html" in ct:
                        result["response_type"] = "html"

                    # Check for sensitive info leaks
                    body = resp.text[:2000]
                    self._detect_leaks(body, result)

                    # For storage: check if listing is enabled
                    if cloud_category == "storage":
                        body = resp.text
                        if "<ListBucketResult" in body or "<EnumerationResults" in body:
                            result["listing_enabled"] = True
                            result["sensitive_files"] = _extract_sensitive_files(body)

                elif resp.status_code == 403:
                    result["exists"] = True
                    result["is_public"] = False

                elif resp.status_code == 401:
                    result["exists"] = True
                    result["is_public"] = False

                elif resp.status_code == 404:
                    return None

        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.debug(f"Generic probe error for {url}: {e}")
            return None

        return result

    # ─────────────────────────────────────────────────────
    # MODE A: Candidate-based Probing (original logic)
    # ─────────────────────────────────────────────────────

    def _execute_candidates(
        self,
        context: ScanContext,
        cfg: dict,
    ) -> EngineResult:
        """
        Original candidate-based probing logic.
        Reads candidates from context.discovery_metadata["cloud_candidates"].
        """
        start = time.time()
        errors: List[str] = []
        data: Dict[str, Any] = {
            "storage": {"results": [], "candidates_checked": 0},
            "registries": {"results": [], "candidates_checked": 0},
            "serverless": {"results": [], "candidates_checked": 0},
            "cdn_origin": {"results": [], "domains_checked": 0},
        }

        # Extract cloud candidates from discovery metadata
        candidates = getattr(context, "discovery_metadata", {}).get("cloud_candidates", {})

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # ── Storage Buckets ──
            if cfg["check_storage"]:
                storage_names = candidates.get("storage", {}).get("candidate_names", [])
                storage_names = storage_names[:cfg["max_storage"]]
                if storage_names:
                    try:
                        results = loop.run_until_complete(
                            self._check_storage(storage_names, cfg)
                        )
                        data["storage"]["results"] = results
                        data["storage"]["candidates_checked"] = len(storage_names)
                    except Exception as e:
                        errors.append(f"Storage check error: {e}")
                        logger.exception("cloud_asset: storage check failed")

            # ── Container Registries ──
            if cfg["check_registries"]:
                registry_names = candidates.get("registry", {}).get("candidate_names", [])
                registry_names = registry_names[:cfg["max_registries"]]
                if registry_names:
                    try:
                        results = loop.run_until_complete(
                            self._check_registries(registry_names, cfg)
                        )
                        data["registries"]["results"] = results
                        data["registries"]["candidates_checked"] = len(registry_names)
                    except Exception as e:
                        errors.append(f"Registry check error: {e}")
                        logger.exception("cloud_asset: registry check failed")

            # ── Serverless Endpoints ──
            if cfg["check_serverless"]:
                serverless_names = candidates.get("serverless", {}).get("candidate_names", [])
                serverless_names = serverless_names[:cfg["max_serverless"]]
                probe_paths = candidates.get("serverless", {}).get("probe_paths", [
                    "/api/health", "/api/status", "/health", "/healthz", "/ping",
                ])
                if serverless_names:
                    try:
                        results = loop.run_until_complete(
                            self._check_serverless(serverless_names, probe_paths, cfg)
                        )
                        data["serverless"]["results"] = results
                        data["serverless"]["candidates_checked"] = len(serverless_names)
                    except Exception as e:
                        errors.append(f"Serverless check error: {e}")
                        logger.exception("cloud_asset: serverless check failed")

            # ── CDN Origin Exposure ──
            if cfg["check_cdn_origin"]:
                try:
                    results = self._check_cdn_origin(context)
                    data["cdn_origin"]["results"] = results
                    data["cdn_origin"]["domains_checked"] = len(results)
                except Exception as e:
                    errors.append(f"CDN origin check error: {e}")
                    logger.exception("cloud_asset: CDN origin check failed")

            loop.close()

        except Exception as e:
            errors.append(f"Engine error: {e}")
            logger.exception("cloud_asset: engine failed")

        duration = time.time() - start
        total_found = sum(
            len([r for r in data[cat]["results"] if r.get("exists") or r.get("is_accessible") or r.get("origin_accessible")])
            for cat in data
        )

        return EngineResult(
            engine_name=self.name,
            success=len(errors) == 0,
            data=data,
            metadata={
                "total_candidates_checked": sum(
                    data[cat].get("candidates_checked", data[cat].get("domains_checked", 0))
                    for cat in data
                ),
                "total_assets_found": total_found,
                "categories_checked": [
                    cat for cat in ["storage", "registries", "serverless", "cdn_origin"]
                    if cfg.get(f"check_{cat}", cfg.get(f"check_{cat.replace('cdn_origin', 'cdn_origin')}", True))
                ],
            },
            errors=errors,
            duration_seconds=duration,
        )

    # ─────────────────────────────────────────────────────
    # Category 1: Storage Buckets
    # ─────────────────────────────────────────────────────

    async def _check_storage(
        self, names: List[str], cfg: dict
    ) -> List[Dict[str, Any]]:
        """Probe candidate names against S3, Azure Blob, and GCS."""
        results = []
        semaphore = asyncio.Semaphore(cfg["max_concurrent"])
        timeout = httpx.Timeout(cfg["timeout"])

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=False,
        ) as client:
            tasks = []
            for name in names:
                tasks.append(self._probe_s3(client, semaphore, name, cfg))
                tasks.append(self._probe_azure_blob(client, semaphore, name, cfg))
                tasks.append(self._probe_gcs(client, semaphore, name, cfg))

            probe_results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in probe_results:
                if isinstance(r, Exception):
                    logger.debug(f"Storage probe exception: {r}")
                    continue
                if r and r.get("exists"):
                    results.append(r)

        return results

    async def _probe_s3(
        self, client: httpx.AsyncClient, sem: asyncio.Semaphore,
        name: str, cfg: dict,
    ) -> Optional[Dict[str, Any]]:
        """Probe AWS S3 bucket."""
        async with sem:
            await asyncio.sleep(cfg["delay"])
            url = f"https://{name}.s3.amazonaws.com"
            result = {
                "provider": "aws_s3",
                "bucket_name": name,
                "url": url,
                "exists": False,
                "is_public": False,
                "listing_enabled": False,
                "sensitive_files": [],
                "response_code": None,
            }
            try:
                resp = await client.head(url)
                result["response_code"] = resp.status_code

                if resp.status_code == 200:
                    result["exists"] = True
                    result["is_public"] = True

                    # Check for directory listing
                    get_resp = await client.get(url)
                    body = get_resp.text
                    if "<ListBucketResult" in body:
                        result["listing_enabled"] = True
                        result["sensitive_files"] = _extract_sensitive_files(body)

                elif resp.status_code == 403:
                    result["exists"] = True
                    result["is_public"] = False

                elif resp.status_code == 404:
                    return None  # Doesn't exist — discard

            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                logger.debug(f"S3 probe error for {name}: {e}")
                return None

            return result

    async def _probe_azure_blob(
        self, client: httpx.AsyncClient, sem: asyncio.Semaphore,
        name: str, cfg: dict,
    ) -> Optional[Dict[str, Any]]:
        """Probe Azure Blob Storage account."""
        async with sem:
            await asyncio.sleep(cfg["delay"])
            url = f"https://{name}.blob.core.windows.net"
            result = {
                "provider": "azure_blob",
                "bucket_name": name,
                "url": url,
                "exists": False,
                "is_public": False,
                "listing_enabled": False,
                "sensitive_files": [],
                "response_code": None,
            }
            try:
                resp = await client.head(url)
                result["response_code"] = resp.status_code

                if resp.status_code in (200, 400):
                    # 400 usually means account exists but invalid request
                    result["exists"] = True

                    # Try container listing
                    list_url = f"{url}?comp=list&restype=container"
                    list_resp = await client.get(list_url)
                    if list_resp.status_code == 200:
                        result["is_public"] = True
                        if "<EnumerationResults" in list_resp.text:
                            result["listing_enabled"] = True
                            result["sensitive_files"] = _extract_sensitive_files(list_resp.text)

                elif resp.status_code == 404:
                    return None

            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                logger.debug(f"Azure Blob probe error for {name}: {e}")
                return None

            return result

    async def _probe_gcs(
        self, client: httpx.AsyncClient, sem: asyncio.Semaphore,
        name: str, cfg: dict,
    ) -> Optional[Dict[str, Any]]:
        """Probe Google Cloud Storage bucket."""
        async with sem:
            await asyncio.sleep(cfg["delay"])
            url = f"https://storage.googleapis.com/{name}"
            result = {
                "provider": "gcs",
                "bucket_name": name,
                "url": url,
                "exists": False,
                "is_public": False,
                "listing_enabled": False,
                "sensitive_files": [],
                "response_code": None,
            }
            try:
                resp = await client.get(url)
                result["response_code"] = resp.status_code

                if resp.status_code == 200:
                    result["exists"] = True
                    result["is_public"] = True
                    body = resp.text
                    if "<ListBucketResult" in body or '"kind": "storage#objects"' in body:
                        result["listing_enabled"] = True
                        result["sensitive_files"] = _extract_sensitive_files(body)

                elif resp.status_code == 403:
                    result["exists"] = True
                    result["is_public"] = False

                elif resp.status_code == 404:
                    return None

            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                logger.debug(f"GCS probe error for {name}: {e}")
                return None

            return result

    # ─────────────────────────────────────────────────────
    # Category 2: Container Registries
    # ─────────────────────────────────────────────────────

    async def _check_registries(
        self, names: List[str], cfg: dict
    ) -> List[Dict[str, Any]]:
        """Probe candidate names against ACR, GCR, ECR Public, Docker Hub."""
        results = []
        semaphore = asyncio.Semaphore(cfg["max_concurrent"])
        timeout = httpx.Timeout(cfg["timeout"])

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            tasks = []
            for name in names:
                tasks.append(self._probe_acr(client, semaphore, name, cfg))
                tasks.append(self._probe_gcr(client, semaphore, name, cfg))
                tasks.append(self._probe_ecr_public(client, semaphore, name, cfg))
                tasks.append(self._probe_dockerhub(client, semaphore, name, cfg))

            probe_results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in probe_results:
                if isinstance(r, Exception):
                    logger.debug(f"Registry probe exception: {r}")
                    continue
                if r and r.get("exists"):
                    results.append(r)

        return results

    async def _probe_acr(
        self, client: httpx.AsyncClient, sem: asyncio.Semaphore,
        name: str, cfg: dict,
    ) -> Optional[Dict[str, Any]]:
        """Probe Azure Container Registry."""
        async with sem:
            await asyncio.sleep(cfg["delay"])
            url = f"https://{name}.azurecr.io/v2/_catalog"
            result = {
                "provider": "acr",
                "registry_name": name,
                "registry_url": f"https://{name}.azurecr.io",
                "exists": False,
                "is_public": False,
                "repositories": [],
                "image_count": 0,
                "response_code": None,
            }
            try:
                resp = await client.get(url)
                result["response_code"] = resp.status_code

                if resp.status_code == 200:
                    result["exists"] = True
                    result["is_public"] = True
                    try:
                        data = resp.json()
                        repos = data.get("repositories", [])
                        result["repositories"] = repos[:100]
                        result["image_count"] = len(repos)
                    except Exception:
                        pass

                elif resp.status_code == 401:
                    # Auth required — registry exists but is private
                    result["exists"] = True

                elif resp.status_code == 404:
                    return None

            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                logger.debug(f"ACR probe error for {name}: {e}")
                return None

            return result

    async def _probe_gcr(
        self, client: httpx.AsyncClient, sem: asyncio.Semaphore,
        name: str, cfg: dict,
    ) -> Optional[Dict[str, Any]]:
        """Probe Google Container Registry / Artifact Registry."""
        async with sem:
            await asyncio.sleep(cfg["delay"])
            url = f"https://gcr.io/v2/{name}/tags/list"
            result = {
                "provider": "gcr",
                "registry_name": name,
                "registry_url": f"https://gcr.io/{name}",
                "exists": False,
                "is_public": False,
                "repositories": [],
                "image_count": 0,
                "response_code": None,
            }
            try:
                resp = await client.get(url)
                result["response_code"] = resp.status_code

                if resp.status_code == 200:
                    result["exists"] = True
                    result["is_public"] = True
                    try:
                        data = resp.json()
                        tags = data.get("tags", [])
                        result["repositories"] = [data.get("name", name)]
                        result["image_count"] = len(tags)
                    except Exception:
                        pass

                elif resp.status_code == 401:
                    result["exists"] = True

                elif resp.status_code in (404, 403):
                    return None

            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                logger.debug(f"GCR probe error for {name}: {e}")
                return None

            return result

    async def _probe_ecr_public(
        self, client: httpx.AsyncClient, sem: asyncio.Semaphore,
        name: str, cfg: dict,
    ) -> Optional[Dict[str, Any]]:
        """Probe AWS ECR Public Gallery."""
        async with sem:
            await asyncio.sleep(cfg["delay"])
            url = f"https://public.ecr.aws/v2/{name}/tags/list"
            result = {
                "provider": "ecr_public",
                "registry_name": name,
                "registry_url": f"https://public.ecr.aws/{name}",
                "exists": False,
                "is_public": False,
                "repositories": [],
                "image_count": 0,
                "response_code": None,
            }
            try:
                resp = await client.get(url)
                result["response_code"] = resp.status_code

                if resp.status_code == 200:
                    result["exists"] = True
                    result["is_public"] = True
                    try:
                        data = resp.json()
                        tags = data.get("tags", [])
                        result["repositories"] = [data.get("name", name)]
                        result["image_count"] = len(tags)
                    except Exception:
                        pass

                elif resp.status_code in (401, 404):
                    return None

            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                logger.debug(f"ECR Public probe error for {name}: {e}")
                return None

            return result

    async def _probe_dockerhub(
        self, client: httpx.AsyncClient, sem: asyncio.Semaphore,
        name: str, cfg: dict,
    ) -> Optional[Dict[str, Any]]:
        """Probe Docker Hub for organisation repositories."""
        async with sem:
            await asyncio.sleep(cfg["delay"])
            url = f"https://hub.docker.com/v2/repositories/{name}/"
            result = {
                "provider": "dockerhub",
                "registry_name": name,
                "registry_url": f"https://hub.docker.com/u/{name}",
                "exists": False,
                "is_public": False,
                "repositories": [],
                "image_count": 0,
                "response_code": None,
            }
            try:
                resp = await client.get(url)
                result["response_code"] = resp.status_code

                if resp.status_code == 200:
                    result["exists"] = True
                    result["is_public"] = True
                    try:
                        data = resp.json()
                        repos = data.get("results", [])
                        result["repositories"] = [
                            r.get("name", "") for r in repos[:100]
                        ]
                        result["image_count"] = data.get("count", len(repos))
                    except Exception:
                        pass

                elif resp.status_code == 404:
                    return None

            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                logger.debug(f"Docker Hub probe error for {name}: {e}")
                return None

            return result

    # ─────────────────────────────────────────────────────
    # Category 3: Serverless Endpoints
    # ─────────────────────────────────────────────────────

    async def _check_serverless(
        self, names: List[str], probe_paths: List[str], cfg: dict
    ) -> List[Dict[str, Any]]:
        """Probe candidate names against Azure Functions and Cloud Run."""
        results = []
        semaphore = asyncio.Semaphore(cfg["max_concurrent"])
        timeout = httpx.Timeout(cfg["timeout"])

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,
        ) as client:
            tasks = []
            for name in names:
                tasks.append(self._probe_azure_functions(
                    client, semaphore, name, probe_paths, cfg
                ))
                tasks.append(self._probe_cloud_run(
                    client, semaphore, name, probe_paths, cfg
                ))

            probe_results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in probe_results:
                if isinstance(r, Exception):
                    logger.debug(f"Serverless probe exception: {r}")
                    continue
                if r and r.get("is_accessible"):
                    results.append(r)

        return results

    async def _probe_azure_functions(
        self, client: httpx.AsyncClient, sem: asyncio.Semaphore,
        name: str, paths: List[str], cfg: dict,
    ) -> Optional[Dict[str, Any]]:
        """Probe Azure Functions app."""
        async with sem:
            await asyncio.sleep(cfg["delay"])
            base_url = f"https://{name}.azurewebsites.net"
            result = {
                "provider": "azure_functions",
                "app_name": name,
                "endpoint_url": base_url,
                "is_accessible": False,
                "auth_required": True,
                "accessible_paths": [],
                "leaked_info": [],
                "response_code": None,
                "response_type": None,
            }
            try:
                # Check base URL first
                resp = await client.get(base_url)
                result["response_code"] = resp.status_code

                if resp.status_code == 404:
                    return None  # App doesn't exist

                # Probe common API paths
                for path in paths:
                    try:
                        path_resp = await client.get(f"{base_url}{path}")
                        if path_resp.status_code == 200:
                            result["is_accessible"] = True
                            result["auth_required"] = False
                            result["accessible_paths"].append(path)

                            # Check for leaked info
                            body = path_resp.text[:2000]
                            ct = path_resp.headers.get("content-type", "")
                            if "json" in ct:
                                result["response_type"] = "json"
                            elif "html" in ct:
                                result["response_type"] = "html"

                            self._detect_leaks(body, result)

                    except (httpx.RequestError, httpx.HTTPStatusError):
                        continue

            except (httpx.RequestError, httpx.HTTPStatusError) as e:
                logger.debug(f"Azure Functions probe error for {name}: {e}")
                return None

            return result

    async def _probe_cloud_run(
        self, client: httpx.AsyncClient, sem: asyncio.Semaphore,
        name: str, paths: List[str], cfg: dict,
    ) -> Optional[Dict[str, Any]]:
        """Probe Google Cloud Run service (common regions)."""
        regions = [
            "us-central1", "us-east1", "us-west1",
            "europe-west1", "europe-west2",
            "asia-east1", "asia-southeast1",
        ]
        async with sem:
            await asyncio.sleep(cfg["delay"])

            for region in regions:
                # Cloud Run URL pattern: {name}-{hash}-{region}.a.run.app
                # We can't guess the hash, but sometimes services use custom domains
                # Try the newer format: {name}-{random}.{region}.run.app
                # Best we can do is try the base service name with region
                # Actually, Cloud Run services often also have custom domains
                # pointing to them. The most reliable pattern is azurewebsites.net-style.
                # For Cloud Run, try the JSON API for the project.
                # In practice, Cloud Run services discovered via DNS are more reliable.
                pass

            # Cloud Run detection is more reliable via DNS/HTTP engine results
            # (discovering *.run.app CNAME targets). Return None for now —
            # CDN origin detection handles this better.
            return None

    def _detect_leaks(self, body: str, result: Dict[str, Any]) -> None:
        """Detect information leaks in response body."""
        leak_patterns = {
            "stack_trace": [
                "Traceback (most recent call last)",
                "at System.", "at Microsoft.",
                "Exception in thread", "NullPointerException",
                "SQLSTATE[", "pg_connect()",
            ],
            "version_info": [
                '"version":', '"build":', '"commit":',
                "X-Powered-By:", "Server:",
            ],
            "config_leak": [
                "DATABASE_URL", "DB_HOST", "SECRET_KEY",
                "API_KEY", "AWS_ACCESS", "AZURE_",
                "GOOGLE_APPLICATION_CREDENTIALS",
            ],
            "debug_mode": [
                "DEBUG = True", "FLASK_DEBUG",
                "Werkzeug Debugger", "Django Debug Toolbar",
                "Whoops!", "Laravel",
            ],
        }

        for category, patterns in leak_patterns.items():
            for pattern in patterns:
                if pattern.lower() in body.lower():
                    result["leaked_info"].append({
                        "category": category,
                        "indicator": pattern,
                    })
                    break  # One per category is enough

    # ─────────────────────────────────────────────────────
    # Category 4: CDN Origin Exposure
    # ─────────────────────────────────────────────────────

    def _check_cdn_origin(self, context: ScanContext) -> List[Dict[str, Any]]:
        """
        Detect CDN origin exposure by cross-referencing engine results.

        Reads from:
          - dns engine:    A records, CNAME chains
          - http engine:   Response headers (X-Served-By, Via, X-Backend-Server)
          - shodan engine: Historical IPs and services
          - ssl engine:    Certificate SANs
        """
        results = []
        engine_results = context.engine_results or {}

        dns_data = engine_results.get("dns", {})
        http_data = engine_results.get("http", {})
        shodan_data = engine_results.get("shodan", {})
        ssl_data = engine_results.get("ssl", {})

        # If we don't have engine results, we have nothing — use EngineResult.data
        if hasattr(dns_data, "data"):
            dns_data = dns_data.data or {}
        if hasattr(http_data, "data"):
            http_data = http_data.data or {}
        if hasattr(shodan_data, "data"):
            shodan_data = shodan_data.data or {}
        if hasattr(ssl_data, "data"):
            ssl_data = ssl_data.data or {}

        domain = context.asset_value
        resolved_ips = context.resolved_ips or []

        # Step 1: Check if the domain is CDN-fronted
        cdn_provider = None
        cdn_ips = []
        non_cdn_ips = []

        for ip in resolved_ips:
            provider = _identify_cdn_provider(ip)
            if provider:
                cdn_provider = provider
                cdn_ips.append(ip)
            else:
                non_cdn_ips.append(ip)

        # Also check CNAME targets for CDN indicators
        cname_targets = dns_data.get("cname_targets", [])
        cdn_cname_indicators = {
            "cloudfront.net": "cloudfront",
            "cloudflare": "cloudflare",
            "fastly": "fastly",
            "akamaiedge.net": "akamai",
            "edgekey.net": "akamai",
            "azureedge.net": "azure_cdn",
            "azurefd.net": "azure_cdn",
        }
        for cname in cname_targets:
            cname_lower = cname.lower()
            for indicator, provider in cdn_cname_indicators.items():
                if indicator in cname_lower:
                    cdn_provider = provider
                    break

        if not cdn_provider:
            return results  # Not CDN-fronted — nothing to check

        # Step 2: Look for origin IP clues
        origin_candidates: List[Dict[str, Any]] = []

        # Clue 2a: Non-CDN IPs in DNS (direct A records alongside CDN CNAMEs)
        for ip in non_cdn_ips:
            origin_candidates.append({
                "ip": ip,
                "detection_method": "dns_non_cdn_ip",
                "confidence": "medium",
            })

        # Clue 2b: HTTP headers leaking origin
        leak_headers = ["x-served-by", "x-backend-server", "via", "x-real-ip", "x-origin-server"]
        headers = http_data.get("response_headers", {})
        for hdr_name in leak_headers:
            value = headers.get(hdr_name, "")
            if value:
                # Try to extract IP from header value
                ip_match = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", value)
                for ip in ip_match:
                    if not _identify_cdn_provider(ip):
                        origin_candidates.append({
                            "ip": ip,
                            "detection_method": "header_leak",
                            "header_name": hdr_name,
                            "header_value": value[:200],
                            "confidence": "high",
                        })

        # Clue 2c: Shodan historical IPs
        shodan_services = shodan_data.get("services", [])
        for svc in shodan_services:
            ip = svc.get("ip", "")
            if ip and not _identify_cdn_provider(ip):
                origin_candidates.append({
                    "ip": ip,
                    "detection_method": "shodan_historical",
                    "port": svc.get("port"),
                    "confidence": "low",
                })

        # Clue 2d: SSL certificate SANs revealing origin hostname
        cert_sans = ssl_data.get("sans", [])
        for san in cert_sans:
            san_lower = san.lower()
            if "origin" in san_lower or "backend" in san_lower or "direct" in san_lower:
                origin_candidates.append({
                    "hostname": san,
                    "detection_method": "cert_san",
                    "confidence": "medium",
                })

        # Step 3: Build results (dedup by IP)
        seen_ips = set()
        for candidate in origin_candidates:
            ip = candidate.get("ip", "")
            if ip in seen_ips:
                continue
            if ip:
                seen_ips.add(ip)

            results.append({
                "cdn_domain": domain,
                "cdn_provider": cdn_provider,
                "origin_ip": ip,
                "origin_hostname": candidate.get("hostname"),
                "origin_accessible": None,  # Analyser will verify
                "waf_bypassed": None,       # Analyser will verify
                "same_content": None,       # Analyser will verify
                "detection_method": candidate["detection_method"],
                "confidence": candidate["confidence"],
                "evidence": {k: v for k, v in candidate.items()
                             if k not in ("ip", "hostname", "detection_method", "confidence")},
            })

        return results