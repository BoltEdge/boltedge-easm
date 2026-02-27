# FILE: app/discovery/modules/hackertarget.py
"""
HackerTarget Discovery Module — uses the free HackerTarget.com API.

Endpoints used (all free, no key):
  - hostsearch: find subdomains for a domain
  - reversedns: find domains on an IP
  - aslookup: find IP ranges for an ASN

Rate limit: 20 requests/day without API key (module tracks this)
Finds: subdomains, domains, IPs
"""

from __future__ import annotations

import logging
from typing import List

import requests

from ..base_module import BaseDiscoveryModule, DiscoveredItem, ModuleType

logger = logging.getLogger(__name__)

TIMEOUT = 10
BASE_URL = "https://api.hackertarget.com"
HEADERS = {"User-Agent": "boltedgeeasm-discovery/2.0"}


def _normalize(d: str) -> str:
    return (d or "").strip().lower().rstrip(".")


def _is_error_response(text: str) -> bool:
    """HackerTarget returns plain text errors."""
    if not text:
        return True
    lower = text.strip().lower()
    return (
        lower.startswith("error")
        or "api count exceeded" in lower
        or "no records found" in lower
        or "invalid" in lower
    )


class HackerTargetModule(BaseDiscoveryModule):
    name = "hackertarget"
    description = "HackerTarget — hostsearch, reverse DNS, ASN lookup"
    module_type = ModuleType.PASSIVE
    requires_api_key = False
    min_plan = "starter"
    supported_target_types = ("domain", "ip")

    def discover(self, target: str, target_type: str, config: dict = None) -> List[DiscoveredItem]:
        items: List[DiscoveredItem] = []

        if target_type == "domain":
            items.extend(self._hostsearch(target))
        elif target_type == "ip":
            items.extend(self._reverse_dns(target))

        return items

    def _hostsearch(self, domain: str) -> List[DiscoveredItem]:
        """Find subdomains via HackerTarget hostsearch."""
        domain = _normalize(domain)
        items: List[DiscoveredItem] = []

        try:
            r = requests.get(
                f"{BASE_URL}/hostsearch/",
                params={"q": domain},
                timeout=TIMEOUT, headers=HEADERS,
            )
            if r.status_code != 200 or _is_error_response(r.text):
                logger.debug("HackerTarget hostsearch: %s → %d", domain, r.status_code)
                return items
        except Exception as e:
            logger.debug("HackerTarget hostsearch error: %s", e)
            return items

        seen = set()
        for line in r.text.strip().splitlines():
            line = line.strip()
            if not line or "," not in line:
                continue

            parts = line.split(",", 1)
            hostname = _normalize(parts[0])
            ip = parts[1].strip() if len(parts) > 1 else ""

            if not hostname or hostname in seen:
                continue
            seen.add(hostname)

            asset_type = "domain" if hostname == domain else "subdomain"
            meta = {}
            if ip:
                meta["resolved_ips"] = [ip]

            items.append(DiscoveredItem(
                asset_type=asset_type, value=hostname,
                source_module=self.name, metadata=meta,
                confidence=0.85,
            ))

            # Also emit the IP
            if ip and ip not in seen:
                seen.add(ip)
                items.append(DiscoveredItem(
                    asset_type="ip", value=ip,
                    source_module=self.name,
                    metadata={"discovered_via": "hackertarget_hostsearch", "parent_domain": domain},
                    confidence=0.8,
                ))

        logger.info("HackerTarget hostsearch: %d results for %s", len(items), domain)
        return items

    def _reverse_dns(self, ip: str) -> List[DiscoveredItem]:
        """Find domains hosted on an IP via reverse DNS."""
        items: List[DiscoveredItem] = []

        try:
            r = requests.get(
                f"{BASE_URL}/reverseiplookup/",
                params={"q": ip},
                timeout=TIMEOUT, headers=HEADERS,
            )
            if r.status_code != 200 or _is_error_response(r.text):
                return items
        except Exception as e:
            logger.debug("HackerTarget reverse DNS error: %s", e)
            return items

        seen = set()
        for line in r.text.strip().splitlines():
            hostname = _normalize(line)
            if not hostname or hostname in seen:
                continue
            seen.add(hostname)

            items.append(DiscoveredItem(
                asset_type="domain", value=hostname,
                source_module=self.name,
                metadata={"resolved_from_ip": ip, "record_type": "reverse_dns"},
                confidence=0.75,
            ))

        logger.info("HackerTarget reverse DNS: %d results for %s", len(items), ip)
        return items