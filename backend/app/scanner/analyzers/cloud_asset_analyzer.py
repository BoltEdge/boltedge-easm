# app/scanner/analyzers/cloud_asset_analyzer.py
"""
Cloud Asset Analyzer — interprets cloud_asset engine probe results
and produces FindingDraft entries for each confirmed exposure.

Covers four categories:
  1. Storage Buckets     — public access, directory listing, sensitive files
  2. Container Registries — unauthenticated catalogue access, pullable images
  3. Serverless Endpoints — unauthenticated function access, info leaks
  4. CDN Origin Exposure  — direct origin access bypassing WAF/CDN

Extends BaseAnalyzer. Reads from cloud_asset engine results in
ScanContext.engine_results["cloud_asset"].data. Produces
List[FindingDraft] with severity, remediation, CWE, and tags.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext

logger = logging.getLogger(__name__)


class CloudAssetAnalyzer(BaseAnalyzer):
    """
    Analyse cloud asset engine results and emit findings.

    Required engine: cloud_asset
    """

    name = "cloud_asset_analyzer"
    description = "Cloud asset exposure analysis (storage, registries, serverless, CDN)"
    required_engines = ("cloud_asset",)

    def analyze(self, context: ScanContext) -> List[FindingDraft]:
        """
        Read cloud_asset engine results and produce findings.
        """
        findings: List[FindingDraft] = []

        engine_result = context.engine_results.get("cloud_asset")
        if not engine_result or not engine_result.success:
            return findings

        data = engine_result.data or {}

        # ── Storage findings ──
        for result in data.get("storage", {}).get("results", []):
            finding = self._analyze_storage(result)
            if finding:
                findings.append(finding)

        # ── Registry findings ──
        for result in data.get("registries", {}).get("results", []):
            finding = self._analyze_registry(result)
            if finding:
                findings.append(finding)

        # ── Serverless findings ──
        for result in data.get("serverless", {}).get("results", []):
            finding = self._analyze_serverless(result)
            if finding:
                findings.append(finding)

        # ── CDN origin findings ──
        for result in data.get("cdn_origin", {}).get("results", []):
            finding = self._analyze_cdn_origin(result)
            if finding:
                findings.append(finding)

        logger.info(
            f"cloud_asset_analyzer: produced {len(findings)} findings "
            f"for {context.asset_value}"
        )
        return findings

    # ═══════════════════════════════════════════════════════════════
    # STORAGE BUCKET ANALYSIS
    # ═══════════════════════════════════════════════════════════════

    def _analyze_storage(self, result: Dict[str, Any]) -> Optional[FindingDraft]:
        """Produce a finding for a storage bucket probe result."""

        provider = result.get("provider", "unknown")
        name = result.get("bucket_name", "unknown")
        url = result.get("url", "")
        is_public = result.get("is_public", False)
        listing = result.get("listing_enabled", False)
        sensitive = result.get("sensitive_files", [])
        exists = result.get("exists", False)

        provider_label = {
            "aws_s3": "AWS S3",
            "azure_blob": "Azure Blob Storage",
            "gcs": "Google Cloud Storage",
        }.get(provider, provider)

        if not exists:
            return None

        # ── Public bucket with sensitive files (Critical) ──
        if is_public and sensitive:
            return FindingDraft(
                template_id="cloud-storage-sensitive-files",
                title=f"Public {provider_label} Bucket with Sensitive Files: {name}",
                severity="critical",
                category="cloud",
                description=(
                    f"The {provider_label} bucket '{name}' is publicly accessible "
                    f"and contains files with sensitive extensions: "
                    f"{', '.join(sensitive[:10])}. "
                    f"These files may contain credentials, database dumps, "
                    f"configuration secrets, or customer data."
                ),
                remediation=(
                    f"1. Immediately restrict public access on the bucket '{name}'.\n"
                    f"2. Review and remove or rotate any exposed credentials.\n"
                    f"3. Enable server-side encryption on all objects.\n"
                    f"4. Implement bucket policies that enforce private access.\n"
                    f"5. Enable access logging to detect any prior unauthorized access.\n"
                    f"6. Consider enabling versioning to track object changes."
                ),
                finding_type="cloud_storage",
                cwe="CWE-552",  # Files or Directories Accessible to External Parties
                confidence="high",
                tags=["cloud", "storage", provider, "sensitive-data", "public-access"],
                engine="cloud_asset",
                details={
                    "provider": provider,
                    "bucket_name": name,
                    "url": url,
                    "is_public": True,
                    "listing_enabled": listing,
                    "sensitive_files": sensitive[:20],
                    "response_code": result.get("response_code"),
                },
                dedupe_fields={
                    "provider": provider,
                    "bucket_name": name,
                    "template": "cloud-storage-sensitive-files",
                },
            )

        # ── Public bucket with directory listing (Critical) ──
        if is_public and listing:
            return FindingDraft(
                template_id="cloud-storage-listing-enabled",
                title=f"Public {provider_label} Bucket with Directory Listing: {name}",
                severity="critical",
                category="cloud",
                description=(
                    f"The {provider_label} bucket '{name}' is publicly accessible "
                    f"with directory listing enabled. Anyone can enumerate and "
                    f"download all objects in the bucket. This is a common source "
                    f"of data breaches."
                ),
                remediation=(
                    f"1. Disable public access on the bucket '{name}'.\n"
                    f"2. Remove any bucket policies or ACLs granting public read.\n"
                    f"3. Enable 'Block Public Access' settings (S3) or equivalent.\n"
                    f"4. Audit bucket contents for sensitive data.\n"
                    f"5. Review access logs for unauthorized downloads."
                ),
                finding_type="cloud_storage",
                cwe="CWE-552",
                confidence="high",
                tags=["cloud", "storage", provider, "directory-listing", "public-access"],
                engine="cloud_asset",
                details={
                    "provider": provider,
                    "bucket_name": name,
                    "url": url,
                    "is_public": True,
                    "listing_enabled": True,
                    "response_code": result.get("response_code"),
                },
                dedupe_fields={
                    "provider": provider,
                    "bucket_name": name,
                    "template": "cloud-storage-listing-enabled",
                },
            )

        # ── Public bucket, no listing (High) ──
        if is_public:
            return FindingDraft(
                template_id="cloud-storage-public-access",
                title=f"Publicly Accessible {provider_label} Bucket: {name}",
                severity="high",
                category="cloud",
                description=(
                    f"The {provider_label} bucket '{name}' allows public access. "
                    f"While directory listing is not enabled, individual objects "
                    f"may still be downloadable if their keys are known or guessable."
                ),
                remediation=(
                    f"1. Review whether public access is intentional for '{name}'.\n"
                    f"2. If not required, restrict to private access only.\n"
                    f"3. If public access is needed (e.g. static assets), ensure "
                    f"no sensitive data is stored in the bucket.\n"
                    f"4. Enable access logging to monitor download activity."
                ),
                finding_type="cloud_storage",
                cwe="CWE-732",  # Incorrect Permission Assignment for Critical Resource
                confidence="high",
                tags=["cloud", "storage", provider, "public-access"],
                engine="cloud_asset",
                details={
                    "provider": provider,
                    "bucket_name": name,
                    "url": url,
                    "is_public": True,
                    "listing_enabled": False,
                    "response_code": result.get("response_code"),
                },
                dedupe_fields={
                    "provider": provider,
                    "bucket_name": name,
                    "template": "cloud-storage-public-access",
                },
            )

        # ── Bucket exists but is private (Informational) ──
        if exists and not is_public:
            return FindingDraft(
                template_id="cloud-storage-private-tracked",
                title=f"{provider_label} Bucket Detected (Private): {name}",
                severity="info",
                category="cloud",
                description=(
                    f"The {provider_label} bucket '{name}' exists and is configured "
                    f"with private access. This is the expected secure configuration. "
                    f"Tracked for inventory purposes."
                ),
                remediation="No action required. Bucket access is correctly restricted.",
                finding_type="cloud_storage",
                cwe="",
                confidence="high",
                tags=["cloud", "storage", provider, "inventory"],
                engine="cloud_asset",
                details={
                    "provider": provider,
                    "bucket_name": name,
                    "url": url,
                    "is_public": False,
                    "response_code": result.get("response_code"),
                },
                dedupe_fields={
                    "provider": provider,
                    "bucket_name": name,
                    "template": "cloud-storage-private-tracked",
                },
            )

        return None

    # ═══════════════════════════════════════════════════════════════
    # CONTAINER REGISTRY ANALYSIS
    # ═══════════════════════════════════════════════════════════════

    def _analyze_registry(self, result: Dict[str, Any]) -> Optional[FindingDraft]:
        """Produce a finding for a container registry probe result."""

        provider = result.get("provider", "unknown")
        name = result.get("registry_name", "unknown")
        url = result.get("registry_url", "")
        is_public = result.get("is_public", False)
        repos = result.get("repositories", [])
        image_count = result.get("image_count", 0)
        exists = result.get("exists", False)

        provider_label = {
            "acr": "Azure Container Registry",
            "gcr": "Google Container Registry",
            "ecr_public": "AWS ECR Public",
            "dockerhub": "Docker Hub",
        }.get(provider, provider)

        if not exists:
            return None

        # ── Public registry with pullable images (Critical) ──
        if is_public and image_count > 0:
            severity = "critical" if image_count > 10 else "high"
            return FindingDraft(
                template_id="cloud-registry-public-images",
                title=f"Public {provider_label} with {image_count} Pullable Images: {name}",
                severity=severity,
                category="cloud",
                description=(
                    f"The {provider_label} '{name}' allows unauthenticated access "
                    f"to {image_count} container image(s). Exposed container images "
                    f"can leak source code, embedded credentials (API keys, database "
                    f"passwords in environment variables), internal architecture "
                    f"details, and supply chain dependencies. "
                    f"Repositories found: {', '.join(repos[:10])}"
                    f"{'...' if len(repos) > 10 else ''}"
                ),
                remediation=(
                    f"1. Restrict the registry '{name}' to authenticated access only.\n"
                    f"2. Review all images for embedded secrets and credentials.\n"
                    f"3. Rotate any credentials that may have been exposed.\n"
                    f"4. Move sensitive images to a private registry.\n"
                    f"5. Implement image scanning for secrets before pushing.\n"
                    f"6. If Docker Hub, ensure repositories are set to 'Private'."
                ),
                finding_type="cloud_registry",
                cwe="CWE-200",  # Exposure of Sensitive Information
                confidence="high",
                tags=["cloud", "registry", "container", provider, "public-access"],
                engine="cloud_asset",
                details={
                    "provider": provider,
                    "registry_name": name,
                    "registry_url": url,
                    "is_public": True,
                    "repositories": repos[:50],
                    "image_count": image_count,
                    "response_code": result.get("response_code"),
                },
                dedupe_fields={
                    "provider": provider,
                    "registry_name": name,
                    "template": "cloud-registry-public-images",
                },
            )

        # ── Public registry, no images enumerated (High) ──
        if is_public:
            return FindingDraft(
                template_id="cloud-registry-public-access",
                title=f"Public {provider_label} Detected: {name}",
                severity="high",
                category="cloud",
                description=(
                    f"The {provider_label} '{name}' allows unauthenticated access "
                    f"to its catalogue API. Even if no images were enumerated, "
                    f"the registry is exposed and may contain private images."
                ),
                remediation=(
                    f"1. Restrict the registry '{name}' to authenticated access.\n"
                    f"2. Enable authentication on the Docker V2 API endpoint.\n"
                    f"3. Review registry contents for sensitive images."
                ),
                finding_type="cloud_registry",
                cwe="CWE-306",  # Missing Authentication for Critical Function
                confidence="medium",
                tags=["cloud", "registry", "container", provider, "public-access"],
                engine="cloud_asset",
                details={
                    "provider": provider,
                    "registry_name": name,
                    "registry_url": url,
                    "is_public": True,
                    "image_count": 0,
                    "response_code": result.get("response_code"),
                },
                dedupe_fields={
                    "provider": provider,
                    "registry_name": name,
                    "template": "cloud-registry-public-access",
                },
            )

        # ── Registry exists, auth required (Informational) ──
        if exists and not is_public:
            return FindingDraft(
                template_id="cloud-registry-private-tracked",
                title=f"{provider_label} Detected (Private): {name}",
                severity="info",
                category="cloud",
                description=(
                    f"The {provider_label} '{name}' exists and requires "
                    f"authentication. Tracked for inventory purposes."
                ),
                remediation="No action required. Registry access is correctly restricted.",
                finding_type="cloud_registry",
                cwe="",
                confidence="high",
                tags=["cloud", "registry", "container", provider, "inventory"],
                engine="cloud_asset",
                details={
                    "provider": provider,
                    "registry_name": name,
                    "registry_url": url,
                    "is_public": False,
                    "response_code": result.get("response_code"),
                },
                dedupe_fields={
                    "provider": provider,
                    "registry_name": name,
                    "template": "cloud-registry-private-tracked",
                },
            )

        return None

    # ═══════════════════════════════════════════════════════════════
    # SERVERLESS ENDPOINT ANALYSIS
    # ═══════════════════════════════════════════════════════════════

    def _analyze_serverless(self, result: Dict[str, Any]) -> Optional[FindingDraft]:
        """Produce a finding for a serverless endpoint probe result."""

        provider = result.get("provider", "unknown")
        name = result.get("app_name", "unknown")
        url = result.get("endpoint_url", "")
        is_accessible = result.get("is_accessible", False)
        auth_required = result.get("auth_required", True)
        paths = result.get("accessible_paths", [])
        leaks = result.get("leaked_info", [])

        provider_label = {
            "azure_functions": "Azure Functions",
            "cloud_run": "Google Cloud Run",
            "lambda": "AWS Lambda",
        }.get(provider, provider)

        if not is_accessible:
            return None

        # Determine severity based on what was leaked
        has_config_leak = any(l.get("category") == "config_leak" for l in leaks)
        has_stack_trace = any(l.get("category") == "stack_trace" for l in leaks)
        has_debug = any(l.get("category") == "debug_mode" for l in leaks)

        # ── Serverless endpoint leaking sensitive info (Critical) ──
        if has_config_leak or has_debug:
            return FindingDraft(
                template_id="cloud-serverless-config-leak",
                title=f"{provider_label} Endpoint Leaking Configuration: {name}",
                severity="critical",
                category="cloud",
                description=(
                    f"The {provider_label} app '{name}' is publicly accessible "
                    f"without authentication and is leaking sensitive configuration "
                    f"data. Detected leaks: "
                    f"{', '.join(l.get('indicator', '') for l in leaks)}. "
                    f"Accessible paths: {', '.join(paths[:5])}"
                ),
                remediation=(
                    f"1. Immediately add authentication to the function app '{name}'.\n"
                    f"2. Disable debug mode in production.\n"
                    f"3. Remove sensitive data from response bodies.\n"
                    f"4. Rotate any leaked credentials or API keys.\n"
                    f"5. Review function code for hardcoded secrets.\n"
                    f"6. Use managed identity / environment-level secrets."
                ),
                finding_type="cloud_serverless",
                cwe="CWE-215",  # Insertion of Sensitive Information Into Debugging Code
                confidence="high",
                tags=["cloud", "serverless", provider, "config-leak", "public-access"],
                engine="cloud_asset",
                details={
                    "provider": provider,
                    "app_name": name,
                    "endpoint_url": url,
                    "accessible_paths": paths,
                    "leaked_info": leaks,
                    "response_code": result.get("response_code"),
                    "response_type": result.get("response_type"),
                },
                dedupe_fields={
                    "provider": provider,
                    "app_name": name,
                    "template": "cloud-serverless-config-leak",
                },
            )

        # ── Serverless endpoint with stack traces (High) ──
        if has_stack_trace:
            return FindingDraft(
                template_id="cloud-serverless-stack-trace",
                title=f"{provider_label} Endpoint Leaking Stack Traces: {name}",
                severity="high",
                category="cloud",
                description=(
                    f"The {provider_label} app '{name}' is publicly accessible "
                    f"and returns stack traces in error responses. This reveals "
                    f"internal code structure, file paths, and dependency versions "
                    f"that aid attackers in crafting targeted exploits."
                ),
                remediation=(
                    f"1. Add authentication to the function app '{name}'.\n"
                    f"2. Implement proper error handling that returns generic messages.\n"
                    f"3. Disable detailed error output in production.\n"
                    f"4. Use structured logging instead of stack trace responses."
                ),
                finding_type="cloud_serverless",
                cwe="CWE-209",  # Generation of Error Message Containing Sensitive Info
                confidence="high",
                tags=["cloud", "serverless", provider, "stack-trace", "public-access"],
                engine="cloud_asset",
                details={
                    "provider": provider,
                    "app_name": name,
                    "endpoint_url": url,
                    "accessible_paths": paths,
                    "leaked_info": leaks,
                    "response_code": result.get("response_code"),
                },
                dedupe_fields={
                    "provider": provider,
                    "app_name": name,
                    "template": "cloud-serverless-stack-trace",
                },
            )

        # ── Serverless endpoint accessible without auth (High) ──
        if not auth_required:
            return FindingDraft(
                template_id="cloud-serverless-no-auth",
                title=f"Unauthenticated {provider_label} Endpoint: {name}",
                severity="high",
                category="cloud",
                description=(
                    f"The {provider_label} app '{name}' is publicly accessible "
                    f"without authentication on {len(paths)} path(s): "
                    f"{', '.join(paths[:5])}. "
                    f"Unauthenticated serverless endpoints may expose business "
                    f"logic, allow data exfiltration, or enable abuse of "
                    f"compute resources."
                ),
                remediation=(
                    f"1. Add authentication to the function app '{name}'.\n"
                    f"2. For Azure Functions, use function-level or app-level auth keys.\n"
                    f"3. For Cloud Run, configure IAM invoker restrictions.\n"
                    f"4. For Lambda URLs, enable IAM or JWT authorization.\n"
                    f"5. If public access is intentional, ensure proper rate limiting "
                    f"and input validation are in place."
                ),
                finding_type="cloud_serverless",
                cwe="CWE-306",  # Missing Authentication for Critical Function
                confidence="medium",
                tags=["cloud", "serverless", provider, "no-auth", "public-access"],
                engine="cloud_asset",
                details={
                    "provider": provider,
                    "app_name": name,
                    "endpoint_url": url,
                    "accessible_paths": paths,
                    "response_code": result.get("response_code"),
                    "response_type": result.get("response_type"),
                },
                dedupe_fields={
                    "provider": provider,
                    "app_name": name,
                    "template": "cloud-serverless-no-auth",
                },
            )

        return None

    # ═══════════════════════════════════════════════════════════════
    # CDN ORIGIN EXPOSURE ANALYSIS
    # ═══════════════════════════════════════════════════════════════

    def _analyze_cdn_origin(self, result: Dict[str, Any]) -> Optional[FindingDraft]:
        """Produce a finding for a CDN origin exposure result."""

        domain = result.get("cdn_domain", "unknown")
        cdn_provider = result.get("cdn_provider", "unknown")
        origin_ip = result.get("origin_ip", "")
        origin_host = result.get("origin_hostname", "")
        method = result.get("detection_method", "unknown")
        confidence_level = result.get("confidence", "low")

        cdn_label = {
            "cloudfront": "CloudFront",
            "cloudflare": "Cloudflare",
            "azure_cdn": "Azure CDN",
            "fastly": "Fastly",
            "akamai": "Akamai",
        }.get(cdn_provider, cdn_provider)

        origin_desc = origin_ip or origin_host or "unknown"

        method_desc = {
            "dns_non_cdn_ip": "Non-CDN IP address found in DNS A records alongside CDN CNAME",
            "header_leak": "Origin IP leaked via HTTP response headers",
            "shodan_historical": "Historical IP found in Shodan data",
            "cert_san": "Origin hostname found in SSL certificate SANs",
        }.get(method, method)

        # Severity depends on detection confidence
        if confidence_level == "high":
            severity = "high"
        elif confidence_level == "medium":
            severity = "medium"
        else:
            severity = "low"

        return FindingDraft(
            template_id="cloud-cdn-origin-exposed",
            title=f"CDN Origin Server Potentially Exposed: {domain} → {origin_desc}",
            severity=severity,
            category="cloud",
            description=(
                f"The domain '{domain}' is fronted by {cdn_label}, but the "
                f"origin server at {origin_desc} may be directly accessible "
                f"on the internet. Detection method: {method_desc}. "
                f"If the origin is directly reachable, attackers can bypass "
                f"CDN-level protections including WAF rules, rate limiting, "
                f"DDoS mitigation, and bot management by targeting the "
                f"origin IP directly."
            ),
            remediation=(
                f"1. Verify whether {origin_desc} is directly accessible on ports 80/443.\n"
                f"2. If accessible, restrict the origin firewall to only accept "
                f"traffic from {cdn_label} IP ranges.\n"
                f"3. Remove any DNS A records pointing directly to the origin.\n"
                f"4. Use origin cloaking (e.g. Cloudflare Tunnel, CloudFront Origin Shield).\n"
                f"5. Ensure response headers do not leak internal IPs "
                f"(X-Served-By, Via, X-Backend-Server).\n"
                f"6. Rotate the origin IP if it has been exposed long-term."
            ),
            finding_type="cloud_cdn",
            cwe="CWE-16",  # Configuration
            confidence=confidence_level,
            tags=["cloud", "cdn", cdn_provider, "origin-exposure", "waf-bypass"],
            engine="cloud_asset",
            details={
                "cdn_domain": domain,
                "cdn_provider": cdn_provider,
                "origin_ip": origin_ip,
                "origin_hostname": origin_host,
                "detection_method": method,
                "evidence": result.get("evidence", {}),
            },
            dedupe_fields={
                "cdn_domain": domain,
                "origin_ip": origin_ip or origin_host,
                "template": "cloud-cdn-origin-exposed",
            },
        )