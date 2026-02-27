# FILE: app/discovery/modules/whois_asn.py
"""
WHOIS & ASN Discovery Module — finds domain registration data, nameservers,
related netblocks, and ASN information.

Uses: RDAP (free, no key), ip-api.com (free tier), bgpview.io (free)
Finds: domains, IPs, IP ranges, registrar/org metadata
"""

from __future__ import annotations

import json
import logging
import re
import socket
from typing import List

import requests

from ..base_module import BaseDiscoveryModule, DiscoveredItem, ModuleType

logger = logging.getLogger(__name__)

TIMEOUT = 10
HEADERS = {"User-Agent": "boltedgeeasm-discovery/2.0", "Accept": "application/json"}


def _normalize(d: str) -> str:
    return (d or "").strip().lower().rstrip(".")


class WHOISASNModule(BaseDiscoveryModule):
    name = "whois_asn"
    description = "WHOIS & ASN lookup — registration data, nameservers, netblocks"
    module_type = ModuleType.PASSIVE
    requires_api_key = False
    min_plan = "starter"
    supported_target_types = ("domain", "ip")

    def discover(self, target: str, target_type: str, config: dict = None) -> List[DiscoveredItem]:
        items: List[DiscoveredItem] = []

        if target_type == "domain":
            items.extend(self._rdap_domain(target))
            items.extend(self._resolve_and_asn(target))
        elif target_type == "ip":
            items.extend(self._ip_asn(target))

        return items

    def _rdap_domain(self, domain: str) -> List[DiscoveredItem]:
        """Query RDAP for domain registration info."""
        items: List[DiscoveredItem] = []
        domain = _normalize(domain)

        try:
            r = requests.get(
                f"https://rdap.org/domain/{domain}",
                timeout=TIMEOUT, headers=HEADERS,
            )
            if r.status_code != 200:
                logger.debug("WHOIS: RDAP returned %d for %s", r.status_code, domain)
                return items

            data = r.json()
        except Exception as e:
            logger.debug("WHOIS: RDAP error for %s: %s", domain, e)
            return items

        # Extract nameservers — each is a subdomain/domain worth tracking
        nameservers = data.get("nameservers", [])
        for ns in nameservers:
            ns_name = _normalize(ns.get("ldhName", ""))
            if ns_name and ns_name != domain:
                items.append(DiscoveredItem(
                    asset_type="domain" if "." in ns_name else "subdomain",
                    value=ns_name,
                    source_module=self.name,
                    metadata={"role": "nameserver", "parent_domain": domain},
                    confidence=0.85,
                ))

        # Extract registrar, dates, status for metadata enrichment
        registrar = ""
        events = data.get("events", [])
        dates = {}
        for evt in events:
            action = evt.get("eventAction", "")
            date = evt.get("eventDate", "")
            if action and date:
                dates[action] = date

        entities = data.get("entities", [])
        for ent in entities:
            roles = ent.get("roles", [])
            if "registrar" in roles:
                vcard = ent.get("vcardArray", [])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            registrar = field[3]
                            break

        # Add the domain itself with enriched metadata
        items.append(DiscoveredItem(
            asset_type="domain", value=domain, source_module=self.name,
            metadata={
                "registrar": registrar,
                "registration_date": dates.get("registration", ""),
                "expiration_date": dates.get("expiration", ""),
                "last_updated": dates.get("last changed", dates.get("last update", "")),
                "status": [s.get("status", "") for s in data.get("status", []) if isinstance(s, dict)]
                         if isinstance(data.get("status"), list) else data.get("status", []),
                "nameserver_count": len(nameservers),
            },
            confidence=1.0,
        ))

        return items

    def _resolve_and_asn(self, domain: str) -> List[DiscoveredItem]:
        """Resolve domain to IP, then look up ASN info."""
        domain = _normalize(domain)
        items: List[DiscoveredItem] = []

        try:
            ips = [sockaddr[0] for *_, sockaddr in socket.getaddrinfo(domain, None)]
            ips = list(dict.fromkeys(ips))  # dedupe preserving order
        except (socket.gaierror, OSError):
            return items

        for ip in ips[:3]:  # limit to first 3 IPs
            items.extend(self._ip_asn(ip, parent_domain=domain))

        return items

    def _ip_asn(self, ip: str, parent_domain: str = None) -> List[DiscoveredItem]:
        """Look up ASN, org, and netblock for an IP."""
        items: List[DiscoveredItem] = []

        try:
            r = requests.get(
                f"https://api.bgpview.io/ip/{ip}",
                timeout=TIMEOUT, headers=HEADERS,
            )
            if r.status_code != 200:
                return items

            data = r.json().get("data", {})
        except Exception as e:
            logger.debug("WHOIS: BGPView error for %s: %s", ip, e)
            return items

        prefixes = data.get("prefixes", [])
        for prefix_info in prefixes:
            cidr = prefix_info.get("prefix", "")
            asn_info = prefix_info.get("asn", {})
            asn = asn_info.get("asn")
            asn_name = asn_info.get("name", "")
            asn_desc = asn_info.get("description", "")

            if cidr:
                meta = {
                    "asn": asn,
                    "asn_name": asn_name,
                    "asn_description": asn_desc,
                    "rir": prefix_info.get("rir_allocation", {}).get("rir_name", ""),
                }
                if parent_domain:
                    meta["parent_domain"] = parent_domain

                items.append(DiscoveredItem(
                    asset_type="ip_range", value=cidr,
                    source_module=self.name,
                    metadata=meta,
                    confidence=0.7,
                ))

        # Also emit the IP itself with ASN metadata
        ip_meta = {"discovered_via": "asn_lookup"}
        if parent_domain:
            ip_meta["parent_domain"] = parent_domain
        if prefixes:
            asn_info = prefixes[0].get("asn", {})
            ip_meta["asn"] = asn_info.get("asn")
            ip_meta["asn_name"] = asn_info.get("name", "")

        items.append(DiscoveredItem(
            asset_type="ip", value=ip, source_module=self.name,
            metadata=ip_meta,
            confidence=0.9,
        ))

        return items