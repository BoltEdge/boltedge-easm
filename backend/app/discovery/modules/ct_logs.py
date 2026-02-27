# FILE: app/discovery/modules/ct_logs.py
"""
CT Log Discovery Module — queries crt.sh for certificates issued to the target domain.

Finds: subdomains, related domains from certificate transparency logs.
Rate limit: None (public API)
API key: Not required
"""

from __future__ import annotations

import json
import logging
import re
from typing import List

import requests

from ..base_module import BaseDiscoveryModule, DiscoveredItem, ModuleType

logger = logging.getLogger(__name__)

DOMAIN_RE = re.compile(r"^(?:\*\.)?([a-z0-9-]+\.)+[a-z]{2,63}$", re.IGNORECASE)
CT_LIMIT_DEFAULT = 2000


def _normalize_domain(d: str) -> str:
    d = (d or "").strip().lower()
    if d.startswith("http://") or d.startswith("https://"):
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0]
    d = d.strip().strip(".")
    if d.startswith("*."):
        d = d[2:]
    return d


def _is_valid_domain(d: str) -> bool:
    d = _normalize_domain(d)
    if not d or len(d) > 253:
        return False
    return DOMAIN_RE.match(d) is not None


def _in_scope(apex: str, name: str) -> bool:
    apex = _normalize_domain(apex)
    name = _normalize_domain(name)
    return name == apex or name.endswith("." + apex)


class CTLogModule(BaseDiscoveryModule):
    name = "ct_logs"
    description = "Certificate Transparency log search via crt.sh"
    module_type = ModuleType.PASSIVE
    requires_api_key = False
    min_plan = "free"
    supported_target_types = ("domain",)

    def discover(self, target: str, target_type: str, config: dict = None) -> List[DiscoveredItem]:
        config = config or {}
        apex = _normalize_domain(target)
        limit = int(config.get("ct_limit", CT_LIMIT_DEFAULT))

        logger.info("CT Logs: querying crt.sh for *.%s", apex)

        # crt.sh can be very slow — use aggressive timeout with one retry
        rows = None
        for attempt in range(2):
            try:
                r = requests.get(
                    "https://crt.sh/",
                    params={"q": f"%.{apex}", "output": "json"},
                    timeout=12,
                    headers={"User-Agent": "boltedgeeasm-discovery/2.0", "Accept": "application/json"},
                )
                if r.status_code != 200:
                    logger.warning("CT Logs: crt.sh returned %d (attempt %d)", r.status_code, attempt + 1)
                    continue

                body = (r.text or "").strip()
                if not body:
                    return []

                rows = json.loads(body)
                break
            except requests.Timeout:
                logger.warning("CT Logs: crt.sh timed out (attempt %d)", attempt + 1)
                continue
            except Exception as e:
                logger.error("CT Logs: crt.sh error: %s", e)
                return []

        if rows is None:
            logger.warning("CT Logs: crt.sh failed after retries — skipping")
            return []

        seen = set()
        items: List[DiscoveredItem] = []

        for row in rows:
            if not isinstance(row, dict):
                continue
            name_value = row.get("name_value")
            if not name_value:
                continue

            for line in str(name_value).splitlines():
                domain = _normalize_domain(line)
                if not domain or domain in seen:
                    continue
                if not _is_valid_domain(domain):
                    continue
                if not _in_scope(apex, domain):
                    continue

                seen.add(domain)
                asset_type = "domain" if domain == apex else "subdomain"

                items.append(DiscoveredItem(
                    asset_type=asset_type,
                    value=domain,
                    source_module=self.name,
                    metadata={
                        "issuer_name": row.get("issuer_name", ""),
                        "not_before": row.get("not_before", ""),
                        "not_after": row.get("not_after", ""),
                    },
                    confidence=0.95,
                ))

                if limit and len(items) >= limit:
                    break
            if limit and len(items) >= limit:
                break

        logger.info("CT Logs: found %d unique domains/subdomains for %s", len(items), apex)
        return items