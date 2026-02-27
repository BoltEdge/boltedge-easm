# app/discovery/modules/cloud_enum.py
"""
Cloud Asset Enumeration discovery module.

Generates candidate names for cloud assets based on the target
organisation's domain, company name, and brand keywords. Candidates
are returned as DiscoveredItem entries with asset_type "cloud" that
the cloud_asset_engine then probes for public accessibility.

Covers four cloud asset categories:
  - Storage buckets     (S3, Azure Blob, GCS)
  - Container registries (ECR, ACR, GCR, Docker Hub)
  - Serverless endpoints (Lambda URLs, Azure Functions, Cloud Run)
  - CDN origins          (detected later by the engine from other scan data)

CDN origin candidates are NOT generated here — they are derived by
cloud_asset_engine from dns/http/shodan/ssl engine results at scan time.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Set

from app.discovery.base_module import BaseDiscoveryModule, DiscoveredItem, ModuleType

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
# SUFFIX / PREFIX WORDLISTS
# ═══════════════════════════════════════════════════════════════

# General-purpose suffixes applied to every base word
GENERAL_SUFFIXES = [
    "",               # bare base word
    "-backup", "-backups",
    "-dev", "-development",
    "-staging", "-stg",
    "-prod", "-production",
    "-assets", "-static",
    "-media", "-images",
    "-logs", "-log",
    "-data", "-db", "-database",
    "-uploads", "-files",
    "-public",
    "-private",
    "-internal",
    "-test", "-testing", "-qa",
    "-archive", "-archives",
    "-cdn",
    "-www",
    "-api",
    "-web", "-app",
    "-config", "-configs",
    "-secrets",
    "-tmp", "-temp",
    "-docs", "-documents",
    "-reports",
]

# Prefixes applied to every base word (prefix-{base})
GENERAL_PREFIXES = [
    "dev-",
    "staging-",
    "stg-",
    "prod-",
    "test-",
    "backup-",
    "old-",
]

# Extra suffixes specific to container registries
REGISTRY_SUFFIXES = [
    "-containers", "-container",
    "-registry", "-docker",
    "-images", "-imgs",
    "-packages", "-pkg",
    "-ci", "-cicd",
    "-build", "-builds",
    "-releases", "-release",
    "-artifacts",
]

# Extra suffixes specific to serverless / function apps
SERVERLESS_SUFFIXES = [
    "-lambda", "-lambdas",
    "-functions", "-func", "-funcs",
    "-api", "-apis",
    "-webhook", "-webhooks",
    "-worker", "-workers",
    "-trigger", "-triggers",
    "-service", "-svc",
    "-backend",
    "-auth",
    "-notify", "-notifications",
    "-processor",
    "-handler",
]

# Common serverless function endpoint paths to probe
SERVERLESS_PATHS = [
    "/api/health",
    "/api/status",
    "/api/version",
    "/api/info",
    "/api/webhook",
    "/api/trigger",
    "/health",
    "/healthz",
    "/status",
    "/ping",
    "/graphql",
    "/.well-known/openid-configuration",
]

# Characters allowed in cloud resource names (S3 is the most restrictive)
SAFE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")


# ═══════════════════════════════════════════════════════════════
# CANDIDATE GENERATION HELPERS
# ═══════════════════════════════════════════════════════════════

def _extract_base_words(target: str, config: Optional[dict] = None) -> List[str]:
    """
    Extract base words from the target and optional config.

    Returns a deduplicated list of lowercase base words derived from:
      - Domain without TLD  (example.com → example)
      - Full domain dashed  (sub.example.com → sub-example-com)
      - Company name from config
      - Brand keywords from config
    """
    bases: Set[str] = set()
    config = config or {}

    # Domain-based bases
    domain = target.strip().lower().rstrip(".")
    if domain:
        # Remove TLD
        parts = domain.split(".")
        if len(parts) >= 2:
            bases.add(parts[0])                        # e.g. "example"
            bases.add(".".join(parts[:-1]))             # e.g. "sub.example"
            bases.add("-".join(parts[:-1]))             # e.g. "sub-example"
            bases.add("-".join(parts))                  # e.g. "sub-example-com"
        else:
            bases.add(domain)

    # Company name
    company = config.get("company_name", "").strip().lower()
    if company:
        bases.add(company)
        bases.add(company.replace(" ", "-"))
        bases.add(company.replace(" ", ""))

    # Brand keywords
    for brand in config.get("brand_keywords", []):
        b = brand.strip().lower()
        if b:
            bases.add(b)
            bases.add(b.replace(" ", "-"))

    # Custom base words from config
    for custom in config.get("custom_bases", []):
        c = custom.strip().lower()
        if c:
            bases.add(c)

    # Remove empties and single-char bases (too noisy)
    return sorted(b for b in bases if len(b) >= 2)


def _generate_candidates(
    bases: List[str],
    suffixes: List[str],
    prefixes: Optional[List[str]] = None,
    max_candidates: int = 200,
) -> List[str]:
    """
    Generate candidate names by combining bases with suffixes and prefixes.
    Deduplicates and validates against cloud naming rules.
    """
    candidates: Set[str] = set()
    prefixes = prefixes or []

    for base in bases:
        # base + suffix
        for suffix in suffixes:
            name = f"{base}{suffix}"
            candidates.add(name)
            if len(candidates) >= max_candidates:
                break

        # prefix + base
        for prefix in prefixes:
            name = f"{prefix}{base}"
            candidates.add(name)
            if len(candidates) >= max_candidates:
                break

        if len(candidates) >= max_candidates:
            break

    # Validate: cloud resource names must be 3-63 chars, lowercase
    # alphanumeric + hyphens + dots, no consecutive dots, no leading/trailing hyphen
    valid: List[str] = []
    for name in sorted(candidates):
        name = name.lower().strip("-. ")
        if len(name) < 3 or len(name) > 63:
            continue
        if ".." in name or "--" in name:
            continue
        if not re.match(r"^[a-z0-9][a-z0-9.\-]*[a-z0-9]$", name):
            continue
        valid.append(name)

    return valid[:max_candidates]


# ═══════════════════════════════════════════════════════════════
# MODULE CLASS
# ═══════════════════════════════════════════════════════════════

class CloudEnumModule(BaseDiscoveryModule):
    """
    Cloud asset candidate name generator.

    Generates candidate names for cloud storage buckets, container
    registries, and serverless function apps based on the target
    organisation. Returned as DiscoveredItem entries with asset_type
    "cloud" and category metadata.

    CDN origin candidates are NOT generated here — they are derived
    at scan time from other engine results (DNS, HTTP, Shodan, SSL).
    """

    name = "cloud_enum"
    description = "Generate candidate cloud asset names (storage, registries, serverless)"
    module_type = ModuleType.PASSIVE
    requires_api_key = False
    min_plan = "professional"
    supported_target_types = ("domain",)

    def discover(
        self,
        target: str,
        target_type: str,
        config: Optional[dict] = None,
    ) -> List[DiscoveredItem]:
        """
        Generate cloud asset candidate names for the target.

        Config options:
            company_name (str):      Organisation name for name generation
            brand_keywords (list):   Additional brand/product names
            custom_bases (list):     Custom base words to include
            max_storage (int):       Max storage bucket candidates (default 200)
            max_registries (int):    Max container registry candidates (default 80)
            max_serverless (int):    Max serverless endpoint candidates (default 60)
            include_storage (bool):  Generate storage candidates (default True)
            include_registries (bool): Generate registry candidates (default True)
            include_serverless (bool): Generate serverless candidates (default True)

        Returns:
            List of DiscoveredItem with asset_type="cloud" and metadata
            containing the cloud_category and candidate_names list.
        """
        config = config or {}
        items: List[DiscoveredItem] = []

        bases = _extract_base_words(target, config)
        if not bases:
            logger.warning(f"cloud_enum: no base words derived from target '{target}'")
            return items

        logger.info(f"cloud_enum: {len(bases)} base words for target '{target}': {bases[:5]}...")

        # ── Storage bucket candidates ──
        if config.get("include_storage", True):
            max_storage = config.get("max_storage", 200)
            storage_names = _generate_candidates(
                bases, GENERAL_SUFFIXES, GENERAL_PREFIXES, max_candidates=max_storage
            )
            if storage_names:
                items.append(DiscoveredItem(
                    asset_type="cloud",
                    value=f"storage:{target}",
                    source_module=self.name,
                    confidence=0.5,  # candidates — not yet confirmed
                    metadata={
                        "cloud_category": "storage",
                        "candidate_names": storage_names,
                        "candidate_count": len(storage_names),
                        "providers": ["aws_s3", "azure_blob", "gcs"],
                        "base_words": bases,
                    },
                ))
                logger.info(f"cloud_enum: generated {len(storage_names)} storage candidates")

        # ── Container registry candidates ──
        if config.get("include_registries", True):
            max_registries = config.get("max_registries", 80)
            # Combine general + registry-specific suffixes
            registry_names = _generate_candidates(
                bases,
                GENERAL_SUFFIXES[:15] + REGISTRY_SUFFIXES,  # smaller general set + registry-specific
                GENERAL_PREFIXES[:4],
                max_candidates=max_registries,
            )
            if registry_names:
                items.append(DiscoveredItem(
                    asset_type="cloud",
                    value=f"registry:{target}",
                    source_module=self.name,
                    confidence=0.5,
                    metadata={
                        "cloud_category": "registry",
                        "candidate_names": registry_names,
                        "candidate_count": len(registry_names),
                        "providers": ["ecr_public", "acr", "gcr", "dockerhub"],
                        "base_words": bases,
                    },
                ))
                logger.info(f"cloud_enum: generated {len(registry_names)} registry candidates")

        # ── Serverless endpoint candidates ──
        if config.get("include_serverless", True):
            max_serverless = config.get("max_serverless", 60)
            serverless_names = _generate_candidates(
                bases,
                GENERAL_SUFFIXES[:10] + SERVERLESS_SUFFIXES,  # smaller general set + serverless-specific
                GENERAL_PREFIXES[:3],
                max_candidates=max_serverless,
            )
            if serverless_names:
                items.append(DiscoveredItem(
                    asset_type="cloud",
                    value=f"serverless:{target}",
                    source_module=self.name,
                    confidence=0.5,
                    metadata={
                        "cloud_category": "serverless",
                        "candidate_names": serverless_names,
                        "candidate_count": len(serverless_names),
                        "providers": ["azure_functions", "cloud_run"],
                        "probe_paths": SERVERLESS_PATHS,
                        "base_words": bases,
                    },
                ))
                logger.info(f"cloud_enum: generated {len(serverless_names)} serverless candidates")

        # ── CDN origin: no candidates generated ──
        # CDN origin detection reads from dns/http/shodan/ssl engine results
        # at scan time. We just emit a marker so the engine knows to run.
        items.append(DiscoveredItem(
            asset_type="cloud",
            value=f"cdn_origin:{target}",
            source_module=self.name,
            confidence=0.3,
            metadata={
                "cloud_category": "cdn_origin",
                "candidate_names": [],
                "candidate_count": 0,
                "note": "CDN origin detection runs at scan time using other engine results",
            },
        ))

        total = sum(
            item.metadata.get("candidate_count", 0) for item in items
        )
        logger.info(
            f"cloud_enum: total {total} candidates across "
            f"{len(items)} categories for '{target}'"
        )

        return items