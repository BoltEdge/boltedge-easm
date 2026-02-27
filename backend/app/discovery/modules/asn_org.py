# FILE: app/discovery/modules/asn_org.py
"""
ASN & Organization Name Discovery Module — maps an ASN or organization name
to IP ranges, individual IPs, and domains via reverse DNS.

Target types:
  - asn:      e.g. "AS13335" — looks up all prefixes for that ASN
  - org_name: e.g. "Cloudflare" — searches for ASNs matching that name, then expands

Uses: BGPView API (free, no key)
Finds: IP ranges, IPs, domains (via reverse DNS on discovered IPs)
"""

from __future__ import annotations

import logging
import socket
from typing import List, Set

import requests

from ..base_module import BaseDiscoveryModule, DiscoveredItem, ModuleType

logger = logging.getLogger(__name__)

TIMEOUT = 10
HEADERS = {"User-Agent": "boltedgeeasm-discovery/2.0", "Accept": "application/json"}
BGP_BASE = "https://api.bgpview.io"


def _normalize(d: str) -> str:
    return (d or "").strip().lower().rstrip(".")


def _reverse_dns(ip: str) -> str:
    """Attempt reverse DNS lookup for an IP."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return _normalize(hostname)
    except (socket.herror, socket.gaierror, OSError):
        return ""


class ASNOrgModule(BaseDiscoveryModule):
    name = "asn_org"
    description = "ASN & Org Name — discover netblocks, IPs, and domains from ASN or organization"
    module_type = ModuleType.PASSIVE
    requires_api_key = False
    min_plan = "starter"
    supported_target_types = ("asn", "org_name")

    def discover(self, target: str, target_type: str, config: dict = None) -> List[DiscoveredItem]:
        if target_type == "asn":
            return self._discover_asn(target)
        elif target_type == "org_name":
            return self._discover_org(target)
        return []

    def _discover_asn(self, asn: str) -> List[DiscoveredItem]:
        """Look up all prefixes for an ASN and optionally reverse-DNS sample IPs."""
        asn_num = asn.upper().replace("AS", "")
        items: List[DiscoveredItem] = []

        # Get ASN details
        try:
            r = requests.get(
                f"{BGP_BASE}/asn/AS{asn_num}",
                timeout=TIMEOUT, headers=HEADERS,
            )
            if r.status_code != 200:
                logger.debug("ASN lookup: %d for AS%s", r.status_code, asn_num)
                return items
            asn_data = r.json().get("data", {})
        except Exception as e:
            logger.debug("ASN lookup error for AS%s: %s", asn_num, e)
            return items

        asn_name = asn_data.get("name", "")
        asn_desc = asn_data.get("description_short", "")

        # Get prefixes (IPv4 + IPv6)
        try:
            r = requests.get(
                f"{BGP_BASE}/asn/AS{asn_num}/prefixes",
                timeout=TIMEOUT, headers=HEADERS,
            )
            if r.status_code != 200:
                return items
            prefix_data = r.json().get("data", {})
        except Exception as e:
            logger.debug("ASN prefixes error for AS%s: %s", asn_num, e)
            return items

        seen_prefixes: Set[str] = set()
        seen_domains: Set[str] = set()
        sample_ips: List[str] = []

        # Process IPv4 prefixes
        for prefix_info in prefix_data.get("ipv4_prefixes", []):
            cidr = prefix_info.get("prefix", "")
            if not cidr or cidr in seen_prefixes:
                continue
            seen_prefixes.add(cidr)

            items.append(DiscoveredItem(
                asset_type="ip_range", value=cidr,
                source_module=self.name,
                metadata={
                    "asn": f"AS{asn_num}",
                    "asn_name": asn_name,
                    "asn_description": asn_desc,
                    "prefix_name": prefix_info.get("name", ""),
                    "prefix_description": prefix_info.get("description", ""),
                    "country_code": prefix_info.get("country_code", ""),
                },
                confidence=0.9,
            ))

            # Collect first IP of each prefix for reverse DNS sampling
            base_ip = cidr.split("/")[0]
            if base_ip and len(sample_ips) < 50:
                sample_ips.append(base_ip)

        # Process IPv6 prefixes
        for prefix_info in prefix_data.get("ipv6_prefixes", []):
            cidr = prefix_info.get("prefix", "")
            if not cidr or cidr in seen_prefixes:
                continue
            seen_prefixes.add(cidr)

            items.append(DiscoveredItem(
                asset_type="ip_range", value=cidr,
                source_module=self.name,
                metadata={
                    "asn": f"AS{asn_num}",
                    "asn_name": asn_name,
                    "ip_version": 6,
                },
                confidence=0.9,
            ))

        # Reverse DNS on sample IPs to discover domains
        for ip in sample_ips:
            hostname = _reverse_dns(ip)
            if hostname and hostname not in seen_domains:
                seen_domains.add(hostname)
                items.append(DiscoveredItem(
                    asset_type="domain", value=hostname,
                    source_module=self.name,
                    metadata={
                        "resolved_from_ip": ip,
                        "asn": f"AS{asn_num}",
                        "record_type": "PTR",
                    },
                    confidence=0.7,
                ))

            # Also add the IP itself
            items.append(DiscoveredItem(
                asset_type="ip", value=ip,
                source_module=self.name,
                metadata={
                    "asn": f"AS{asn_num}",
                    "asn_name": asn_name,
                    "discovered_via": "asn_prefix",
                },
                confidence=0.85,
            ))

        logger.info(
            "ASN discovery: AS%s — %d prefixes, %d IPs sampled, %d domains found",
            asn_num, len(seen_prefixes), len(sample_ips), len(seen_domains),
        )
        return items

    def _discover_org(self, org_name: str) -> List[DiscoveredItem]:
        """Search for ASNs matching an organization name, then expand each."""
        items: List[DiscoveredItem] = []

        # Search BGPView for ASNs matching the org name
        try:
            r = requests.get(
                f"{BGP_BASE}/search",
                params={"query_term": org_name},
                timeout=TIMEOUT, headers=HEADERS,
            )
            if r.status_code != 200:
                logger.debug("Org search: %d for '%s'", r.status_code, org_name)
                return items

            data = r.json().get("data", {})
        except Exception as e:
            logger.debug("Org search error for '%s': %s", org_name, e)
            return items

        # Extract matching ASNs
        asns_found = []
        for asn_info in data.get("asns", []):
            asn = asn_info.get("asn")
            name = asn_info.get("name", "")
            desc = asn_info.get("description", "")

            if asn:
                asns_found.append({"asn": asn, "name": name, "description": desc})

        if not asns_found:
            logger.info("Org search: no ASNs found for '%s'", org_name)
            return items

        logger.info("Org search: found %d ASN(s) for '%s'", len(asns_found), org_name)

        # Expand each ASN (limit to first 5 to avoid excessive API calls)
        for asn_info in asns_found[:5]:
            asn_str = f"AS{asn_info['asn']}"
            asn_items = self._discover_asn(asn_str)
            items.extend(asn_items)

        # Also check for domains directly in search results
        seen_domains: set = set()
        for ipv4_info in data.get("ipv4_prefixes", []):
            # BGPView search sometimes returns prefix info too
            cidr = ipv4_info.get("prefix", "")
            if cidr:
                items.append(DiscoveredItem(
                    asset_type="ip_range", value=cidr,
                    source_module=self.name,
                    metadata={"discovered_via": "org_search", "org_name": org_name},
                    confidence=0.75,
                ))

        return items