# app/scanner/analyzers/cloud_asset_analyzer.py
"""
Cloud Asset Analyzer — interprets cloud_asset engine probe results
and produces FindingDraft entries for each confirmed exposure.

Covers four categories:
  1. Storage Buckets      — public access, directory listing, sensitive files
  2. Container Registries — unauthenticated catalogue access, pullable images
  3. Serverless Endpoints — unauthenticated function access, info leaks
  4. CDN Origin Exposure  — direct origin access bypassing WAF/CDN

All copy (title / description / remediation / summary / references)
comes from the curated FindingTemplate registry. The analyzer maps
runtime context onto template placeholders ({asset}, {value},
{provider}) and creates the draft.

Required engine: cloud_asset
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext
from app.scanner.templates import FindingTemplate, get_template

logger = logging.getLogger(__name__)


# ─── Provider label mappings ─────────────────────────────────────────────
# Technical key → human-readable label that goes into the rendered title /
# description. Keys without a mapping pass through unchanged so we degrade
# gracefully if the engine adds a new provider before we update this table.

_STORAGE_PROVIDERS = {
    "aws_s3":     "AWS S3",
    "azure_blob": "Azure Blob Storage",
    "gcs":        "Google Cloud Storage",
}
_REGISTRY_PROVIDERS = {
    "acr":        "Azure Container Registry",
    "gcr":        "Google Container Registry",
    "ecr_public": "AWS ECR Public",
    "dockerhub":  "Docker Hub",
}
_SERVERLESS_PROVIDERS = {
    "azure_functions": "Azure Functions",
    "cloud_run":       "Google Cloud Run",
    "lambda":          "AWS Lambda",
}
_CDN_PROVIDERS = {
    "cloudfront": "CloudFront",
    "cloudflare": "Cloudflare",
    "azure_cdn":  "Azure CDN",
    "fastly":     "Fastly",
    "akamai":     "Akamai",
}


# ─── Render helpers ──────────────────────────────────────────────────────

def _render(text: Optional[str], **subs: Any) -> Optional[str]:
    """Replace {key} placeholders with runtime values.

    Uses str.replace rather than str.format so curly braces inside
    Markdown / code snippets in templates don't blow up when a
    placeholder dict doesn't cover every brace pair.
    """
    if not text:
        return text
    out = text
    for k, v in subs.items():
        if v is None or v == "":
            continue
        out = out.replace("{" + k + "}", str(v))
    return out


def _draft_from_template(
    template: FindingTemplate,
    *,
    template_id: str,
    severity_override: Optional[str] = None,
    confidence: str,
    asset: str,
    value: str,
    provider_label: str,
    url: str,
    extra_tags: List[str],
    details: Dict[str, Any],
    dedupe_fields: Dict[str, Any],
    finding_type: str,
) -> FindingDraft:
    """Build a FindingDraft by rendering the registered template.

    `severity_override` lets the analyzer downgrade or upgrade the
    template's default severity for context-dependent cases (e.g.,
    registry with few images becomes 'high' rather than 'critical';
    cdn-origin severity tracks the engine's confidence level).
    """
    title = _render(
        template.title,
        asset=asset, value=value, provider=provider_label, url=url,
    )
    description = _render(
        template.description,
        asset=asset, value=value, provider=provider_label, url=url,
    )
    remediation = _render(
        template.remediation,
        asset=asset, value=value, provider=provider_label, url=url,
    )

    return FindingDraft(
        template_id=template_id,
        title=title or f"Cloud finding for {asset}",
        severity=severity_override or template.severity or "medium",
        category=template.category or "cloud",
        description=description or "",
        remediation=remediation,
        finding_type=finding_type,
        engine="cloud_asset",
        confidence=confidence,
        cwe=template.cwe,
        references=list(template.references),
        tags=list(template.tags) + extra_tags,
        details=details,
        dedupe_fields=dedupe_fields,
    )


class CloudAssetAnalyzer(BaseAnalyzer):
    """
    Analyse cloud asset engine results and emit findings.

    Required engine: cloud_asset
    """

    name = "cloud_asset_analyzer"
    description = "Cloud asset exposure analysis (storage, registries, serverless, CDN)"
    required_engines = ("cloud_asset",)

    def analyze(self, context: ScanContext) -> List[FindingDraft]:
        findings: List[FindingDraft] = []

        engine_result = context.engine_results.get("cloud_asset")
        if not engine_result or not engine_result.success:
            return findings

        data = engine_result.data or {}

        for result in data.get("storage", {}).get("results", []):
            finding = self._analyze_storage(result, context)
            if finding:
                findings.append(finding)

        for result in data.get("registries", {}).get("results", []):
            finding = self._analyze_registry(result, context)
            if finding:
                findings.append(finding)

        for result in data.get("serverless", {}).get("results", []):
            finding = self._analyze_serverless(result, context)
            if finding:
                findings.append(finding)

        for result in data.get("cdn_origin", {}).get("results", []):
            finding = self._analyze_cdn_origin(result, context)
            if finding:
                findings.append(finding)

        logger.info(
            "cloud_asset_analyzer: produced %d findings for %s",
            len(findings), context.asset_value,
        )
        return findings

    # ═══════════════════════════════════════════════════════════════
    # STORAGE BUCKET ANALYSIS
    # ═══════════════════════════════════════════════════════════════

    def _analyze_storage(self, result: Dict[str, Any], ctx: ScanContext) -> Optional[FindingDraft]:
        provider_key = result.get("provider", "unknown")
        name = result.get("bucket_name", "unknown")
        url = result.get("url", "")
        is_public = result.get("is_public", False)
        listing = result.get("listing_enabled", False)
        sensitive = result.get("sensitive_files", []) or []
        exists = result.get("exists", False)

        if not exists:
            return None

        provider_label = _STORAGE_PROVIDERS.get(provider_key, provider_key)

        # Pick the most severe matching template.
        if is_public and sensitive:
            tid = "cloud-storage-sensitive-files"
        elif is_public and listing:
            tid = "cloud-storage-listing-enabled"
        elif is_public:
            tid = "cloud-storage-public-access"
        else:
            tid = "cloud-storage-private-tracked"

        template = get_template(tid)
        if template is None:
            logger.warning("Missing storage template: %s", tid)
            return None

        details = {
            "value": name,
            "provider": provider_key,
            "provider_label": provider_label,
            "bucket_name": name,
            "url": url,
            "is_public": is_public,
            "listing_enabled": listing,
            "sensitive_files": sensitive[:20] if sensitive else [],
            "response_code": result.get("response_code"),
        }

        return _draft_from_template(
            template,
            template_id=tid,
            confidence="high",
            asset=ctx.asset_value,
            value=name,
            provider_label=provider_label,
            url=url,
            extra_tags=[provider_key] if provider_key not in template.tags else [],
            details=details,
            dedupe_fields={
                "provider": provider_key,
                "bucket_name": name,
                "template": tid,
            },
            finding_type="cloud_storage",
        )

    # ═══════════════════════════════════════════════════════════════
    # CONTAINER REGISTRY ANALYSIS
    # ═══════════════════════════════════════════════════════════════

    def _analyze_registry(self, result: Dict[str, Any], ctx: ScanContext) -> Optional[FindingDraft]:
        provider_key = result.get("provider", "unknown")
        name = result.get("registry_name", "unknown")
        url = result.get("registry_url", "")
        is_public = result.get("is_public", False)
        repos = result.get("repositories", []) or []
        image_count = result.get("image_count", 0)
        exists = result.get("exists", False)

        if not exists:
            return None

        provider_label = _REGISTRY_PROVIDERS.get(provider_key, provider_key)

        # Severity downgrade for small registries — a public registry
        # with 1–10 images is still a finding but doesn't warrant the
        # full critical severity that 100+ pullable images would.
        severity_override: Optional[str] = None

        if is_public and image_count > 0:
            tid = "cloud-registry-public-images"
            if image_count <= 10:
                severity_override = "high"
        elif is_public:
            tid = "cloud-registry-public-access"
        else:
            tid = "cloud-registry-private-tracked"

        template = get_template(tid)
        if template is None:
            logger.warning("Missing registry template: %s", tid)
            return None

        details = {
            "value": name,
            "provider": provider_key,
            "provider_label": provider_label,
            "registry_name": name,
            "registry_url": url,
            "is_public": is_public,
            "repositories": repos[:50],
            "image_count": image_count,
            "response_code": result.get("response_code"),
        }

        return _draft_from_template(
            template,
            template_id=tid,
            severity_override=severity_override,
            confidence="high" if image_count > 0 else "medium",
            asset=ctx.asset_value,
            value=name,
            provider_label=provider_label,
            url=url,
            extra_tags=[provider_key] if provider_key not in template.tags else [],
            details=details,
            dedupe_fields={
                "provider": provider_key,
                "registry_name": name,
                "template": tid,
            },
            finding_type="cloud_registry",
        )

    # ═══════════════════════════════════════════════════════════════
    # SERVERLESS ENDPOINT ANALYSIS
    # ═══════════════════════════════════════════════════════════════

    def _analyze_serverless(self, result: Dict[str, Any], ctx: ScanContext) -> Optional[FindingDraft]:
        provider_key = result.get("provider", "unknown")
        name = result.get("app_name", "unknown")
        url = result.get("endpoint_url", "")
        is_accessible = result.get("is_accessible", False)
        auth_required = result.get("auth_required", True)
        paths = result.get("accessible_paths", []) or []
        leaks = result.get("leaked_info", []) or []

        if not is_accessible:
            return None

        provider_label = _SERVERLESS_PROVIDERS.get(provider_key, provider_key)

        has_config_leak = any(l.get("category") == "config_leak" for l in leaks)
        has_stack_trace = any(l.get("category") == "stack_trace" for l in leaks)
        has_debug = any(l.get("category") == "debug_mode" for l in leaks)

        if has_config_leak or has_debug:
            tid = "cloud-serverless-config-leak"
            confidence = "high"
        elif has_stack_trace:
            tid = "cloud-serverless-stack-trace"
            confidence = "high"
        elif not auth_required:
            tid = "cloud-serverless-no-auth"
            confidence = "medium"
        else:
            return None

        template = get_template(tid)
        if template is None:
            logger.warning("Missing serverless template: %s", tid)
            return None

        details = {
            "value": name,
            "provider": provider_key,
            "provider_label": provider_label,
            "app_name": name,
            "endpoint_url": url,
            "url": url,
            "accessible_paths": paths,
            "leaked_info": leaks,
            "response_code": result.get("response_code"),
            "response_type": result.get("response_type"),
        }

        return _draft_from_template(
            template,
            template_id=tid,
            confidence=confidence,
            asset=ctx.asset_value,
            value=name,
            provider_label=provider_label,
            url=url,
            extra_tags=[provider_key] if provider_key not in template.tags else [],
            details=details,
            dedupe_fields={
                "provider": provider_key,
                "app_name": name,
                "template": tid,
            },
            finding_type="cloud_serverless",
        )

    # ═══════════════════════════════════════════════════════════════
    # CDN ORIGIN EXPOSURE ANALYSIS
    # ═══════════════════════════════════════════════════════════════

    def _analyze_cdn_origin(self, result: Dict[str, Any], ctx: ScanContext) -> Optional[FindingDraft]:
        domain = result.get("cdn_domain", "unknown")
        cdn_provider_key = result.get("cdn_provider", "unknown")
        origin_ip = result.get("origin_ip", "")
        origin_host = result.get("origin_hostname", "")
        method = result.get("detection_method", "unknown")
        confidence_level = result.get("confidence", "low")

        provider_label = _CDN_PROVIDERS.get(cdn_provider_key, cdn_provider_key)
        origin_desc = origin_ip or origin_host or "unknown"

        # Severity tracks the engine's detection confidence — a header-
        # leaked origin IP is high-confidence and 'high' severity, but
        # a Shodan-historical match alone is low-confidence and 'low'.
        severity_override = {
            "high":   "high",
            "medium": "medium",
            "low":    "low",
        }.get(confidence_level, "medium")

        tid = "cloud-cdn-origin-exposed"
        template = get_template(tid)
        if template is None:
            logger.warning("Missing CDN template: %s", tid)
            return None

        details = {
            "value": domain,
            "provider": cdn_provider_key,
            "provider_label": provider_label,
            "cdn_domain": domain,
            "cdn_provider": cdn_provider_key,
            "origin_ip": origin_ip,
            "origin_hostname": origin_host,
            "detection_method": method,
            "evidence": result.get("evidence", {}),
        }

        return _draft_from_template(
            template,
            template_id=tid,
            severity_override=severity_override,
            confidence=confidence_level,
            asset=ctx.asset_value,
            value=domain,
            provider_label=provider_label,
            url="",
            extra_tags=[cdn_provider_key] if cdn_provider_key not in template.tags else [],
            details=details,
            dedupe_fields={
                "cdn_domain": domain,
                "origin_ip": origin_ip or origin_host,
                "template": tid,
            },
            finding_type="cloud_cdn",
        )
