# FILE: app/discovery/modules/alienvault_otx.py
"""
AlienVault OTX Discovery Module — queries the free OTX API for passive DNS data.

Uses: OTX DirectConnect API (free, no key required for basic queries)
Endpoints:
  - /indicators/domain/{domain}/passive_dns — historical DNS records
  - /indicators/domain/{domain}/url_list — known URLs
  - /indicators/IPv4/{ip}/passive_dns — reverse passive DNS for IPs

Finds: subdomains, IPs, URLs
"""

from __future__ import annotations

import logging
from typing import List, Set

import requests

from ..base_module import BaseDiscoveryModule, DiscoveredItem, ModuleType

logger = logging.getLogger(__name__)

TIMEOUT = 10
BASE_URL = "https://otx.alienvault.com/api/v1"
HEADERS = {"User-Agent": "boltedgeeasm-discovery/2.0", "Accept": "application/json"}


def _normalize(d: str) -> str:
    return (d or "").strip().lower().rstrip(".")


def _in_scope(apex: str, name: str) -> bool:
    apex = _normalize(apex)
    name = _normalize(name)
    return name == apex or name.endswith("." + apex)


class AlienVaultOTXModule(BaseDiscoveryModule):
    name = "alienvault_otx"
    description = "AlienVault OTX — passive DNS and URL intelligence"
    module_type = ModuleType.PASSIVE
    requires_api_key = False
    min_plan = "starter"
    supported_target_types = ("domain", "ip")

    def discover(self, target: str, target_type: str, config: dict = None) -> List[DiscoveredItem]:
        items: List[DiscoveredItem] = []

        if target_type == "domain":
            items.extend(self._passive_dns_domain(target))
            items.extend(self._url_list(target))
        elif target_type == "ip":
            items.extend(self._passive_dns_ip(target))

        return items

    def _passive_dns_domain(self, domain: str) -> List[DiscoveredItem]:
        """Get passive DNS records for a domain — finds subdomains and IPs."""
        domain = _normalize(domain)
        items: List[DiscoveredItem] = []
        seen_hosts: Set[str] = set()
        seen_ips: Set[str] = set()

        try:
            r = requests.get(
                f"{BASE_URL}/indicators/domain/{domain}/passive_dns",
                timeout=TIMEOUT, headers=HEADERS,
            )
            if r.status_code != 200:
                logger.debug("OTX passive DNS: %d for %s", r.status_code, domain)
                return items

            data = r.json()
        except Exception as e:
            logger.debug("OTX passive DNS error for %s: %s", domain, e)
            return items

        for record in data.get("passive_dns", []):
            hostname = _normalize(record.get("hostname", ""))
            address = (record.get("address", "") or "").strip()
            record_type = record.get("record_type", "")
            first_seen = record.get("first", "")
            last_seen = record.get("last", "")

            # Collect hostnames (subdomains)
            if hostname and hostname not in seen_hosts and _in_scope(domain, hostname):
                seen_hosts.add(hostname)
                asset_type = "domain" if hostname == domain else "subdomain"
                meta = {"record_type": record_type}
                if first_seen:
                    meta["first_seen"] = first_seen
                if last_seen:
                    meta["last_seen"] = last_seen
                if address:
                    meta["resolved_ips"] = [address]

                items.append(DiscoveredItem(
                    asset_type=asset_type, value=hostname,
                    source_module=self.name, metadata=meta,
                    confidence=0.8,
                ))

            # Collect IPs
            if address and address not in seen_ips and record_type in ("A", "AAAA"):
                seen_ips.add(address)
                items.append(DiscoveredItem(
                    asset_type="ip", value=address,
                    source_module=self.name,
                    metadata={
                        "discovered_via": "otx_passive_dns",
                        "parent_domain": domain,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                    },
                    confidence=0.75,
                ))

        logger.info("OTX passive DNS: %d hosts, %d IPs for %s", len(seen_hosts), len(seen_ips), domain)
        return items

    def _url_list(self, domain: str) -> List[DiscoveredItem]:
        """Get known URLs — can reveal subdomains and paths."""
        domain = _normalize(domain)
        items: List[DiscoveredItem] = []
        seen: Set[str] = set()

        try:
            r = requests.get(
                f"{BASE_URL}/indicators/domain/{domain}/url_list",
                params={"limit": 200},
                timeout=TIMEOUT, headers=HEADERS,
            )
            if r.status_code != 200:
                return items

            data = r.json()
        except Exception as e:
            logger.debug("OTX URL list error for %s: %s", domain, e)
            return items

        for entry in data.get("url_list", []):
            url = (entry.get("url", "") or "").strip()
            hostname = (entry.get("hostname", "") or "").strip().lower()

            # Extract hostnames from URLs
            if hostname and hostname not in seen and _in_scope(domain, hostname):
                seen.add(hostname)
                if hostname != domain:
                    items.append(DiscoveredItem(
                        asset_type="subdomain", value=hostname,
                        source_module=self.name,
                        metadata={"discovered_via": "otx_url_list"},
                        confidence=0.7,
                    ))

        logger.info("OTX URL list: %d unique hosts for %s", len(seen), domain)
        return items

    def _passive_dns_ip(self, ip: str) -> List[DiscoveredItem]:
        """Reverse passive DNS for an IP — find domains that resolved to it."""
        items: List[DiscoveredItem] = []
        seen: Set[str] = set()

        try:
            r = requests.get(
                f"{BASE_URL}/indicators/IPv4/{ip}/passive_dns",
                timeout=TIMEOUT, headers=HEADERS,
            )
            if r.status_code != 200:
                return items

            data = r.json()
        except Exception as e:
            logger.debug("OTX IP passive DNS error for %s: %s", ip, e)
            return items

        for record in data.get("passive_dns", []):
            hostname = _normalize(record.get("hostname", ""))
            if hostname and hostname not in seen:
                seen.add(hostname)
                items.append(DiscoveredItem(
                    asset_type="domain", value=hostname,
                    source_module=self.name,
                    metadata={
                        "resolved_from_ip": ip,
                        "first_seen": record.get("first", ""),
                        "last_seen": record.get("last", ""),
                    },
                    confidence=0.7,
                ))

        logger.info("OTX IP reverse DNS: %d domains for %s", len(seen), ip)
        return items