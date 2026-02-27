# FILE: app/discovery/modules/threatcrowd.py
"""
ThreatCrowd Discovery Module — queries the free ThreatCrowd API.

Uses: ThreatCrowd API (free, no key, rate limited to 1 req/10s)
Finds: subdomains, IPs, related emails

ThreatCrowd aggregates data from multiple OSINT sources including
VirusTotal, passive DNS, and WHOIS records.
"""

from __future__ import annotations

import logging
import time
from typing import List, Set

import requests

from ..base_module import BaseDiscoveryModule, DiscoveredItem, ModuleType

logger = logging.getLogger(__name__)

TIMEOUT = 10
BASE_URL = "https://www.threatcrowd.org/searchApi/v2"
HEADERS = {"User-Agent": "boltedgeeasm-discovery/2.0", "Accept": "application/json"}


def _normalize(d: str) -> str:
    return (d or "").strip().lower().rstrip(".")


def _in_scope(apex: str, name: str) -> bool:
    apex = _normalize(apex)
    name = _normalize(name)
    return name == apex or name.endswith("." + apex)


class ThreatCrowdModule(BaseDiscoveryModule):
    name = "threatcrowd"
    description = "ThreatCrowd — OSINT aggregation for subdomains and IPs"
    module_type = ModuleType.PASSIVE
    requires_api_key = False
    min_plan = "professional"
    supported_target_types = ("domain", "ip")

    def discover(self, target: str, target_type: str, config: dict = None) -> List[DiscoveredItem]:
        items: List[DiscoveredItem] = []

        if target_type == "domain":
            items.extend(self._domain_search(target))
        elif target_type == "ip":
            items.extend(self._ip_search(target))

        return items

    def _domain_search(self, domain: str) -> List[DiscoveredItem]:
        domain = _normalize(domain)
        items: List[DiscoveredItem] = []

        try:
            r = requests.get(
                f"{BASE_URL}/domain/report/",
                params={"domain": domain},
                timeout=TIMEOUT, headers=HEADERS,
            )
            if r.status_code != 200:
                logger.debug("ThreatCrowd: %d for domain %s", r.status_code, domain)
                return items

            data = r.json()
        except Exception as e:
            logger.debug("ThreatCrowd: error for %s: %s", domain, e)
            return items

        if data.get("response_code", "0") == "0":
            return items

        # Subdomains
        seen_hosts: Set[str] = set()
        for sub in data.get("subdomains", []):
            hostname = _normalize(sub)
            if not hostname or hostname in seen_hosts:
                continue
            if not _in_scope(domain, hostname):
                continue
            seen_hosts.add(hostname)

            asset_type = "domain" if hostname == domain else "subdomain"
            items.append(DiscoveredItem(
                asset_type=asset_type, value=hostname,
                source_module=self.name,
                metadata={"discovered_via": "threatcrowd"},
                confidence=0.75,
            ))

        # IPs from resolutions
        seen_ips: Set[str] = set()
        for resolution in data.get("resolutions", []):
            ip = (resolution.get("ip_address", "") or "").strip()
            last_resolved = resolution.get("last_resolved", "")
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                items.append(DiscoveredItem(
                    asset_type="ip", value=ip,
                    source_module=self.name,
                    metadata={
                        "discovered_via": "threatcrowd",
                        "parent_domain": domain,
                        "last_resolved": last_resolved,
                    },
                    confidence=0.7,
                ))

        logger.info("ThreatCrowd: %d hosts, %d IPs for %s", len(seen_hosts), len(seen_ips), domain)
        return items

    def _ip_search(self, ip: str) -> List[DiscoveredItem]:
        items: List[DiscoveredItem] = []

        try:
            r = requests.get(
                f"{BASE_URL}/ip/report/",
                params={"ip": ip},
                timeout=TIMEOUT, headers=HEADERS,
            )
            if r.status_code != 200:
                return items

            data = r.json()
        except Exception as e:
            logger.debug("ThreatCrowd: IP error for %s: %s", ip, e)
            return items

        if data.get("response_code", "0") == "0":
            return items

        seen: Set[str] = set()
        for resolution in data.get("resolutions", []):
            hostname = _normalize(resolution.get("domain", ""))
            if hostname and hostname not in seen:
                seen.add(hostname)
                items.append(DiscoveredItem(
                    asset_type="domain", value=hostname,
                    source_module=self.name,
                    metadata={
                        "resolved_from_ip": ip,
                        "last_resolved": resolution.get("last_resolved", ""),
                    },
                    confidence=0.65,
                ))

        logger.info("ThreatCrowd: %d domains for IP %s", len(seen), ip)
        return items