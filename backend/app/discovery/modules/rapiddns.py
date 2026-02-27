# FILE: app/discovery/modules/rapiddns.py
"""
RapidDNS Discovery Module — scrapes rapiddns.io for subdomain data.

Uses: rapiddns.io (free, no key, no rate limit published)
Finds: subdomains, IPs

RapidDNS aggregates DNS data from multiple sources and is a good
complement to CT logs and brute-force enumeration.
"""

from __future__ import annotations

import logging
import re
from typing import List, Set

import requests

from ..base_module import BaseDiscoveryModule, DiscoveredItem, ModuleType

logger = logging.getLogger(__name__)

TIMEOUT = 10
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; boltedgeeasm-discovery/2.0)",
    "Accept": "text/html",
}

# Regex to extract subdomains and IPs from the HTML table
SUBDOMAIN_RE = re.compile(r'<td>([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})</td>', re.IGNORECASE)
IP_RE = re.compile(r'<td>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</td>')


def _normalize(d: str) -> str:
    return (d or "").strip().lower().rstrip(".")


def _in_scope(apex: str, name: str) -> bool:
    apex = _normalize(apex)
    name = _normalize(name)
    return name == apex or name.endswith("." + apex)


class RapidDNSModule(BaseDiscoveryModule):
    name = "rapiddns"
    description = "RapidDNS — aggregated DNS subdomain data"
    module_type = ModuleType.PASSIVE
    requires_api_key = False
    min_plan = "free"
    supported_target_types = ("domain",)

    def discover(self, target: str, target_type: str, config: dict = None) -> List[DiscoveredItem]:
        if target_type != "domain":
            return []
        return self._search_subdomains(target)

    def _search_subdomains(self, domain: str) -> List[DiscoveredItem]:
        domain = _normalize(domain)
        items: List[DiscoveredItem] = []
        seen_hosts: Set[str] = set()
        seen_ips: Set[str] = set()

        try:
            r = requests.get(
                f"https://rapiddns.io/subdomain/{domain}",
                params={"full": "1"},
                timeout=TIMEOUT, headers=HEADERS,
            )
            if r.status_code != 200:
                logger.debug("RapidDNS: returned %d for %s", r.status_code, domain)
                return items
        except Exception as e:
            logger.debug("RapidDNS: error for %s: %s", domain, e)
            return items

        html = r.text

        # Extract hostnames
        for match in SUBDOMAIN_RE.finditer(html):
            hostname = _normalize(match.group(1))
            if not hostname or hostname in seen_hosts:
                continue
            if not _in_scope(domain, hostname):
                continue

            seen_hosts.add(hostname)
            asset_type = "domain" if hostname == domain else "subdomain"

            items.append(DiscoveredItem(
                asset_type=asset_type, value=hostname,
                source_module=self.name,
                metadata={"discovered_via": "rapiddns"},
                confidence=0.8,
            ))

        # Extract IPs
        for match in IP_RE.finditer(html):
            ip = match.group(1)
            if ip not in seen_ips:
                seen_ips.add(ip)
                items.append(DiscoveredItem(
                    asset_type="ip", value=ip,
                    source_module=self.name,
                    metadata={"discovered_via": "rapiddns", "parent_domain": domain},
                    confidence=0.75,
                ))

        logger.info("RapidDNS: %d hosts, %d IPs for %s", len(seen_hosts), len(seen_ips), domain)
        return items