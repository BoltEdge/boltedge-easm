# FILE: app/discovery/modules/shodan_search.py
"""
Shodan Discovery Module — uses the Shodan API to discover assets.

PURPOSE: Find NEW ASSETS (subdomains, IPs, related domains).
This is NOT for scanning — port/service/vuln data is handled by the scan engine.

Target types:
  - domain: finds subdomains and associated IPs via Shodan's DNS + host search
  - ip:     reverse DNS to find domains hosted on that IP

Requires: SHODAN_API_KEY environment variable (same key used by scan engine)
Uses: Shodan REST API (paid key required)
"""

from __future__ import annotations

import logging
import os
from typing import List, Set

import requests

from ..base_module import BaseDiscoveryModule, DiscoveredItem, ModuleType

logger = logging.getLogger(__name__)

TIMEOUT = 15
SHODAN_BASE = "https://api.shodan.io"


def _normalize(d: str) -> str:
    return (d or "").strip().lower().rstrip(".")


class ShodanDiscoveryModule(BaseDiscoveryModule):
    name = "shodan"
    description = "Shodan — discover subdomains, IPs, and related domains"
    module_type = ModuleType.PASSIVE
    requires_api_key = True
    min_plan = "starter"
    supported_target_types = ("domain", "ip")

    def is_available(self) -> bool:
        return bool(self._get_api_key())

    def _get_api_key(self) -> str:
        return os.environ.get("SHODAN_API_KEY", "").strip()

    def discover(self, target: str, target_type: str, config: dict = None) -> List[DiscoveredItem]:
        api_key = self._get_api_key()
        if not api_key:
            logger.warning("Shodan API key not configured, skipping")
            return []

        if target_type == "domain":
            return self._discover_domain(target, api_key, config)
        elif target_type == "ip":
            return self._discover_ip(target, api_key)
        return []

    def _discover_domain(self, domain: str, api_key: str, config: dict = None) -> List[DiscoveredItem]:
        """Find subdomains and IPs associated with a domain."""
        items: List[DiscoveredItem] = []
        seen_domains: Set[str] = set()
        seen_ips: Set[str] = set()
        config = config or {}
        scan_depth = config.get("scan_depth", "standard")

        # ── 1. Shodan DNS database — richest source of subdomains ──
        try:
            r = requests.get(
                f"{SHODAN_BASE}/dns/domain/{domain}",
                params={"key": api_key},
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                data = r.json()

                for record in data.get("data", []):
                    subdomain = record.get("subdomain", "")
                    record_type = record.get("type", "")
                    value_field = record.get("value", "")

                    fqdn = _normalize(f"{subdomain}.{domain}" if subdomain else domain)
                    if not fqdn or fqdn in seen_domains:
                        continue
                    seen_domains.add(fqdn)

                    metadata = {"record_type": record_type}

                    # Collect resolved IPs from A/AAAA records
                    if record_type in ("A", "AAAA") and value_field:
                        metadata["resolved_ips"] = [value_field]
                        seen_ips.add(value_field)

                    items.append(DiscoveredItem(
                        asset_type="subdomain" if subdomain else "domain",
                        value=fqdn,
                        source_module=self.name,
                        metadata=metadata,
                        confidence=0.95,
                    ))

                logger.info("Shodan DNS: %d subdomains for %s", len(seen_domains), domain)

            elif r.status_code == 401:
                logger.error("Shodan: invalid API key")
                return items
            elif r.status_code == 429:
                logger.warning("Shodan: rate limited")
            else:
                logger.debug("Shodan DNS: %d for %s", r.status_code, domain)

        except Exception as e:
            logger.debug("Shodan DNS error for %s: %s", domain, e)

        # ── 2. Host search — find additional IPs and subdomains from hostname matches ──
        try:
            query = f'hostname:"{domain}"'
            page_limit = 2 if scan_depth == "deep" else 1

            for page in range(1, page_limit + 1):
                r = requests.get(
                    f"{SHODAN_BASE}/shodan/host/search",
                    params={"key": api_key, "query": query, "page": page, "minify": True},
                    timeout=TIMEOUT,
                )
                if r.status_code != 200:
                    break

                data = r.json()
                matches = data.get("matches", [])
                if not matches:
                    break

                for match in matches:
                    ip = match.get("ip_str", "")

                    # Discover hostnames from this IP
                    for hostname in match.get("hostnames", []):
                        hn = _normalize(hostname)
                        if hn and hn not in seen_domains and (hn.endswith(f".{domain}") or hn == domain):
                            seen_domains.add(hn)
                            items.append(DiscoveredItem(
                                asset_type="subdomain" if hn != domain else "domain",
                                value=hn,
                                source_module=self.name,
                                metadata={"resolved_ips": [ip] if ip else [], "discovered_via": "shodan_host_search"},
                                confidence=0.9,
                            ))

                    # Add IP if new
                    if ip and ip not in seen_ips:
                        seen_ips.add(ip)
                        items.append(DiscoveredItem(
                            asset_type="ip", value=ip,
                            source_module=self.name,
                            metadata={"discovered_via": "shodan_host_search"},
                            confidence=0.85,
                        ))

                total = data.get("total", 0)
                if page * 100 >= total:
                    break

            logger.info("Shodan host search: %d IPs for %s", len(seen_ips), domain)

        except Exception as e:
            logger.debug("Shodan host search error for %s: %s", domain, e)

        # ── 3. SSL cert search (deep only) — find IPs serving certs for this domain ──
        if scan_depth == "deep":
            try:
                r = requests.get(
                    f"{SHODAN_BASE}/shodan/host/search",
                    params={"key": api_key, "query": f'ssl.cert.subject.cn:"{domain}"', "page": 1, "minify": True},
                    timeout=TIMEOUT,
                )
                if r.status_code == 200:
                    for match in r.json().get("matches", []):
                        ip = match.get("ip_str", "")
                        if ip and ip not in seen_ips:
                            seen_ips.add(ip)
                            items.append(DiscoveredItem(
                                asset_type="ip", value=ip,
                                source_module=self.name,
                                metadata={"discovered_via": "shodan_ssl_cert"},
                                confidence=0.8,
                            ))

                        # Extract domain from SSL CN
                        ssl_cn = _normalize(
                            match.get("ssl", {}).get("cert", {}).get("subject", {}).get("CN", "")
                        )
                        if ssl_cn and ssl_cn not in seen_domains and (ssl_cn.endswith(f".{domain}") or ssl_cn == domain):
                            seen_domains.add(ssl_cn)
                            items.append(DiscoveredItem(
                                asset_type="subdomain", value=ssl_cn,
                                source_module=self.name,
                                metadata={"resolved_ips": [ip] if ip else [], "discovered_via": "shodan_ssl_cert"},
                                confidence=0.85,
                            ))

            except Exception as e:
                logger.debug("Shodan SSL search error: %s", e)

        logger.info("Shodan discovery: %s — %d domains, %d IPs", domain, len(seen_domains), len(seen_ips))
        return items

    def _discover_ip(self, ip: str, api_key: str) -> List[DiscoveredItem]:
        """Reverse lookup: find domains hosted on this IP."""
        items: List[DiscoveredItem] = []

        try:
            r = requests.get(
                f"{SHODAN_BASE}/shodan/host/{ip}",
                params={"key": api_key, "minify": True},
                timeout=TIMEOUT,
            )
            if r.status_code != 200:
                return items

            data = r.json()

            # Extract hostnames — these are the discovered assets
            for hostname in data.get("hostnames", []):
                hn = _normalize(hostname)
                if hn:
                    items.append(DiscoveredItem(
                        asset_type="domain", value=hn,
                        source_module=self.name,
                        metadata={"resolved_ips": [ip], "discovered_via": "shodan_reverse_dns"},
                        confidence=0.85,
                    ))

            logger.info("Shodan IP lookup: %s — %d hostnames", ip, len(data.get("hostnames", [])))

        except Exception as e:
            logger.debug("Shodan IP lookup error: %s", e)

        return items