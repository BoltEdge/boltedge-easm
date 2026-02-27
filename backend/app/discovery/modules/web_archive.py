# FILE: app/discovery/modules/web_archive.py
"""
Web Archive (Wayback Machine) Discovery Module — finds historical subdomains
from the Internet Archive's CDX API.

Uses: Wayback Machine CDX Server API (free, no key)
Finds: subdomains, URLs that were historically crawled

This is powerful because it finds subdomains that may no longer be in DNS
but could still be resolving or have dangling CNAME records (subdomain takeover).
"""

from __future__ import annotations

import logging
import re
from typing import List, Set
from urllib.parse import urlparse

import requests

from ..base_module import BaseDiscoveryModule, DiscoveredItem, ModuleType

logger = logging.getLogger(__name__)

TIMEOUT = 15  # Wayback can be slow
HEADERS = {"User-Agent": "boltedgeeasm-discovery/2.0"}


def _normalize(d: str) -> str:
    return (d or "").strip().lower().rstrip(".")


def _in_scope(apex: str, name: str) -> bool:
    apex = _normalize(apex)
    name = _normalize(name)
    return name == apex or name.endswith("." + apex)


def _extract_hostname(url: str) -> str:
    """Extract hostname from a URL."""
    try:
        if not url.startswith("http"):
            url = "http://" + url
        parsed = urlparse(url)
        return _normalize(parsed.hostname or "")
    except Exception:
        return ""


class WebArchiveModule(BaseDiscoveryModule):
    name = "web_archive"
    description = "Wayback Machine — historical subdomain discovery from web archives"
    module_type = ModuleType.PASSIVE
    requires_api_key = False
    min_plan = "starter"
    supported_target_types = ("domain",)

    def discover(self, target: str, target_type: str, config: dict = None) -> List[DiscoveredItem]:
        if target_type != "domain":
            return []
        return self._wayback_subdomains(target)

    def _wayback_subdomains(self, domain: str) -> List[DiscoveredItem]:
        """Query Wayback Machine CDX API for all URLs under *.domain."""
        domain = _normalize(domain)
        items: List[DiscoveredItem] = []
        seen_hosts: Set[str] = set()

        try:
            # CDX API: get all URLs matching *.domain
            r = requests.get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{domain}/*",
                    "output": "text",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": "5000",
                },
                timeout=TIMEOUT, headers=HEADERS,
            )
            if r.status_code != 200:
                logger.debug("WebArchive: CDX returned %d for %s", r.status_code, domain)
                return items
        except requests.Timeout:
            logger.warning("WebArchive: CDX timed out for %s", domain)
            return items
        except Exception as e:
            logger.debug("WebArchive: CDX error for %s: %s", domain, e)
            return items

        for line in r.text.strip().splitlines():
            url = line.strip()
            if not url:
                continue

            hostname = _extract_hostname(url)
            if not hostname or hostname in seen_hosts:
                continue
            if not _in_scope(domain, hostname):
                continue

            seen_hosts.add(hostname)
            asset_type = "domain" if hostname == domain else "subdomain"

            items.append(DiscoveredItem(
                asset_type=asset_type, value=hostname,
                source_module=self.name,
                metadata={"discovered_via": "wayback_machine", "historical": True},
                confidence=0.65,  # Lower confidence — may no longer exist
            ))

        logger.info("WebArchive: %d unique hosts for %s", len(seen_hosts), domain)
        return items