# FILE: app/discovery/modules/cidr_enum.py
"""
CIDR Range Discovery Module — enumerates an IP range to find live hosts and domains.

Takes a CIDR (e.g. 192.168.1.0/24) and:
  1. Iterates all usable IPs in the range
  2. Reverse DNS on each to find hostnames
  3. Emits IPs and discovered domains

Range size is enforced by the route:
  - standard: max /28 (16 hosts)
  - deep:     max /24 (256 hosts)
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import List, Set

from ..base_module import BaseDiscoveryModule, DiscoveredItem, ModuleType

logger = logging.getLogger(__name__)


def _normalize(d: str) -> str:
    return (d or "").strip().lower().rstrip(".")


def _reverse_dns(ip_str: str) -> str:
    """Attempt reverse DNS lookup for an IP."""
    try:
        hostname = socket.gethostbyaddr(ip_str)[0]
        return _normalize(hostname)
    except (socket.herror, socket.gaierror, OSError):
        return ""


class CIDREnumModule(BaseDiscoveryModule):
    name = "cidr_enum"
    description = "CIDR enumeration — reverse DNS and host discovery on IP ranges"
    module_type = ModuleType.ACTIVE
    requires_api_key = False
    min_plan = "starter"
    supported_target_types = ("cidr",)

    def discover(self, target: str, target_type: str, config: dict = None) -> List[DiscoveredItem]:
        if target_type != "cidr":
            return []
        return self._enumerate_cidr(target)

    def _enumerate_cidr(self, cidr: str) -> List[DiscoveredItem]:
        try:
            network = ipaddress.IPv4Network(cidr, strict=False)
        except (ValueError, ipaddress.AddressValueError) as e:
            logger.error("CIDR Enum: invalid CIDR %s: %s", cidr, e)
            return []

        hosts = list(network.hosts()) or [network.network_address]

        logger.info("CIDR Enum: scanning %s (%d hosts)", cidr, len(hosts))

        items: List[DiscoveredItem] = []
        seen_domains: Set[str] = set()
        found_count = 0

        # Emit the range itself
        items.append(DiscoveredItem(
            asset_type="ip_range", value=cidr,
            source_module=self.name,
            metadata={"total_hosts": len(hosts)},
            confidence=1.0,
        ))

        for i, ip_addr in enumerate(hosts):
            ip_str = str(ip_addr)
            hostname = _reverse_dns(ip_str)

            # Emit the IP
            ip_meta = {"cidr": cidr, "discovered_via": "cidr_enumeration"}
            if hostname:
                ip_meta["reverse_dns"] = hostname

            items.append(DiscoveredItem(
                asset_type="ip", value=ip_str,
                source_module=self.name,
                metadata=ip_meta,
                confidence=0.9,
            ))

            # Emit domain from reverse DNS
            if hostname and hostname not in seen_domains:
                seen_domains.add(hostname)
                found_count += 1
                items.append(DiscoveredItem(
                    asset_type="domain", value=hostname,
                    source_module=self.name,
                    metadata={
                        "resolved_from_ip": ip_str,
                        "cidr": cidr,
                        "record_type": "PTR",
                    },
                    confidence=0.75,
                ))

            if (i + 1) % 50 == 0:
                logger.info(
                    "CIDR Enum: %d/%d IPs checked, %d domains found",
                    i + 1, len(hosts), found_count,
                )

        logger.info(
            "CIDR Enum: finished %s — %d IPs, %d domains",
            cidr, len(hosts), found_count,
        )
        return items