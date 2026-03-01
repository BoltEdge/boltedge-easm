# FILE: app/discovery/modules/dns_enum.py
"""
DNS Enumeration Module — comprehensive DNS record lookups and IP resolution.

Discovery depths:
  - standard: ~5,000 prefixes from wordlist (fast, 30-60s)
  - deep:     ~20,000 prefixes from wordlist (thorough, 3-5 min)
  - fallback: ~120 hardcoded high-hit-rate prefixes if wordlists missing

Finds: subdomains (from brute-force), IPs (from resolution), DNS records.
Rate limit: Self-throttled
API key: Not required
"""

from __future__ import annotations

import logging
import os
import socket
from typing import Dict, List, Set

from ..base_module import BaseDiscoveryModule, DiscoveredItem, ModuleType

logger = logging.getLogger(__name__)

# ── Fallback: hardcoded high-hit-rate prefixes (~120) ──
# Used only if wordlist files are missing
FALLBACK_PREFIXES = [
    # ── Core infrastructure (highest hit rate) ──
    "www", "www1", "www2", "www3", "mail", "mail2", "mail3", "email",
    "smtp", "smtp2", "imap", "imap2", "pop", "pop3", "webmail",
    "mx", "mx1", "mx2", "mx3", "ns", "ns1", "ns2", "ns3", "ns4",
    "dns", "dns1", "dns2", "relay",

    # ── Email / Exchange ──
    "autodiscover", "autoconfig", "owa", "exchange", "outlook",

    # ── Applications ──
    "api", "api2", "app", "app2", "portal", "portal2",
    "admin", "dashboard", "panel", "console",
    "login", "auth", "sso", "oauth", "accounts", "id", "identity",
    "signup", "register",

    # ── Content management ──
    "cms", "wp", "wordpress", "jira", "confluence",

    # ── Development environments ──
    "dev", "dev2", "test", "test2", "testing", "staging", "staging2",
    "stage", "qa", "qa2", "uat", "uat2",
    "beta", "alpha", "demo", "sandbox", "preview",
    "preprod", "prod", "production",

    # ── Content / media ──
    "cdn", "cdn1", "cdn2", "static", "static1", "static2",
    "assets", "assets2", "media", "media2",
    "img", "img2", "images", "files", "files2",
    "download", "uploads", "video", "streaming",

    # ── Services ──
    "docs", "wiki", "help", "support",
    "blog", "news", "forum", "forums", "community",
    "shop", "store", "pay", "billing", "checkout", "orders",
    "search", "data", "analytics", "report", "reports",
    "jobs", "careers", "events", "partners",
    "feedback", "survey",

    # ── Infrastructure / Ops ──
    "vpn", "vpn2", "remote", "gateway", "proxy", "proxy2",
    "lb", "lb2", "loadbalancer", "origin",
    "monitor", "status", "health", "metrics",
    "grafana", "prometheus", "kibana", "splunk", "sentry",
    "log", "logs",
    "jenkins", "ci", "cd", "git", "gitlab", "bitbucket", "svn",
    "build", "deploy",

    # ── Database / Cache / Queue ──
    "db", "db1", "db2", "database", "mysql", "postgres", "redis",
    "mongo", "elastic", "elasticsearch",
    "cache", "memcached", "rabbitmq", "kafka",

    # ── Cloud / Services ──
    "cloud", "aws", "azure", "gcp", "s3", "storage", "storage2",
    "k8s", "kubernetes", "docker", "registry",
    "heroku", "netlify", "vercel",

    # ── Security ──
    "secure", "ssl", "tls", "cert", "firewall", "waf",
    "vault", "secrets", "okta", "auth0", "keycloak",

    # ── Hosting panels ──
    "cpanel", "whm", "plesk",

    # ── FTP / File ──
    "ftp", "ftp2", "sftp", "backup", "backups", "backup2",

    # ── Networking ──
    "dmz", "bastion", "jump", "tunnel",
    "fw", "fw1", "router", "switch",
    "ntp", "snmp",
    "sip", "voip", "pbx",

    # ── Business apps ──
    "crm", "erp", "hr", "accounting",
    "chat", "live", "meet", "calendar",
    "ticket", "tickets",

    # ── Web servers ──
    "web", "web1", "web2", "web3",
    "server1", "server2", "node1", "node2",
    "host1", "host2", "worker1", "worker2",

    # ── Numbered variants ──
    "app1", "app3", "api1", "api3",
    "mail4", "ns5", "ns6",
    "dev1", "dev3", "test1", "test3",
    "qa1", "uat1", "prod1", "prod2",
    "stage1", "stage2",

    # ── Misc common ──
    "internal", "intranet", "extranet", "corp", "office",
    "m", "mobile", "ws", "wss", "socket", "realtime",
    "old", "new", "legacy", "v2",
    "go", "link", "links", "redirect",

    # ── Geographic ──
    "us", "eu", "uk", "au", "ca", "de", "fr", "jp",
    "asia", "apac", "emea",

    # ── User / account ──
    "my", "account", "profile", "user", "member",

    # ── Developer ──
    "developer", "sdk", "webhook", "swagger", "openapi",

    # ── More services ──
    "about", "info", "contact", "site", "service",
    "services", "platform", "hub",
]

# Path to wordlists (relative to this file)
WORDLIST_DIR = os.path.join(os.path.dirname(__file__), "..", "wordlists")
STANDARD_WORDLIST = os.path.join(WORDLIST_DIR, "subdomains-standard.txt")
DEEP_WORDLIST = os.path.join(WORDLIST_DIR, "subdomains-deep.txt")

SCAN_DEPTHS = ("standard", "deep")


def _load_wordlist(path: str) -> List[str]:
    """Load a newline-delimited wordlist file."""
    try:
        with open(path, "r") as f:
            return [line.strip().lower() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        logger.warning("Wordlist not found: %s", path)
        return []


def _get_prefixes_for_depth(depth: str) -> List[str]:
    """Return the prefix list for the given discovery depth."""
    if depth == "deep":
        wordlist = _load_wordlist(DEEP_WORDLIST)
        if wordlist:
            logger.info("Loaded deep wordlist: %d prefixes", len(wordlist))
            return wordlist
        logger.warning("Deep wordlist missing — falling back to standard")

    # Standard: try wordlist first, fall back to hardcoded
    wordlist = _load_wordlist(STANDARD_WORDLIST)
    if wordlist:
        logger.info("Loaded standard wordlist: %d prefixes", len(wordlist))
        return wordlist

    logger.warning("Standard wordlist missing — using hardcoded fallback (%d prefixes)", len(FALLBACK_PREFIXES))
    return FALLBACK_PREFIXES


def _normalize(d: str) -> str:
    d = (d or "").strip().lower()
    if d.endswith("."):
        d = d[:-1]
    return d


def _resolve_hostname(name: str) -> List[str]:
    name = _normalize(name)
    if not name:
        return []
    ips: List[str] = []
    try:
        for *_rest, sockaddr in socket.getaddrinfo(name, None):
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    except (socket.gaierror, socket.herror, OSError):
        pass
    return ips


def _wildcard_check(apex: str) -> bool:
    test_name = f"boltedgeeasm-wildcard-test-{id(apex) % 99999}.{apex}"
    return len(_resolve_hostname(test_name)) > 0


class DNSEnumModule(BaseDiscoveryModule):
    name = "dns_enum"
    description = "DNS enumeration — brute-force subdomains + resolve IPs"
    module_type = ModuleType.ACTIVE
    requires_api_key = False
    min_plan = "free"
    supported_target_types = ("domain", "ip")

    def discover(self, target: str, target_type: str, config: dict = None) -> List[DiscoveredItem]:
        config = config or {}
        if target_type == "ip":
            return self._discover_ip(target)
        return self._discover_domain(target, config)

    def _discover_domain(self, target: str, config: dict) -> List[DiscoveredItem]:
        apex = _normalize(target)

        # Determine discovery depth from config (default: standard)
        depth = str(config.get("scan_depth", "standard")).lower()
        if depth not in SCAN_DEPTHS:
            depth = "standard"

        prefixes = _get_prefixes_for_depth(depth)

        logger.info(
            "DNS Enum: enumerating %s (depth=%s, prefixes=%d)",
            apex, depth, len(prefixes),
        )

        items: List[DiscoveredItem] = []
        all_ips: Set[str] = set()

        # 1. Resolve apex
        apex_ips = _resolve_hostname(apex)
        if apex_ips:
            items.append(DiscoveredItem(
                asset_type="domain", value=apex, source_module=self.name,
                metadata={"resolved_ips": apex_ips, "record_type": "A/AAAA"},
                confidence=1.0,
            ))
            all_ips.update(apex_ips)

        # 2. Wildcard detection
        has_wildcard = _wildcard_check(apex)
        wildcard_ips = set()
        if has_wildcard:
            logger.info("DNS Enum: wildcard detected for %s — filtering false positives", apex)
            wildcard_ips = set(_resolve_hostname(f"wildcard-baseline-check.{apex}"))

        # 3. Brute-force subdomains
        found_count = 0
        for i, prefix in enumerate(prefixes):
            subdomain = f"{prefix}.{apex}"
            ips = _resolve_hostname(subdomain)

            if not ips:
                continue
            if has_wildcard and set(ips) == wildcard_ips:
                continue

            found_count += 1
            items.append(DiscoveredItem(
                asset_type="subdomain", value=subdomain, source_module=self.name,
                metadata={"resolved_ips": ips, "record_type": "A/AAAA"},
                confidence=0.9,
            ))
            all_ips.update(ips)

            # Log progress every 500 prefixes
            if (i + 1) % 500 == 0:
                logger.info(
                    "DNS Enum: progress %d/%d prefixes checked, %d found so far",
                    i + 1, len(prefixes), found_count,
                )

        # 4. Create IP entries
        for ip in all_ips:
            items.append(DiscoveredItem(
                asset_type="ip", value=ip, source_module=self.name,
                metadata={"discovered_via": "dns_resolution", "parent_domain": apex},
                confidence=0.85,
            ))

        logger.info(
            "DNS Enum: finished %s (depth=%s) — %d subdomains, %d IPs, %d prefixes checked",
            apex, depth, found_count, len(all_ips), len(prefixes),
        )
        return items

    def _discover_ip(self, target: str) -> List[DiscoveredItem]:
        items: List[DiscoveredItem] = []
        try:
            hostnames = socket.gethostbyaddr(target)
            primary = hostnames[0]
            aliases = hostnames[1] if len(hostnames) > 1 else []

            if primary:
                items.append(DiscoveredItem(
                    asset_type="domain", value=_normalize(primary), source_module=self.name,
                    metadata={"resolved_from_ip": target, "record_type": "PTR"},
                    confidence=0.8,
                ))
            for alias in (aliases or []):
                if alias:
                    items.append(DiscoveredItem(
                        asset_type="domain", value=_normalize(alias), source_module=self.name,
                        metadata={"resolved_from_ip": target, "record_type": "PTR"},
                        confidence=0.7,
                    ))
        except (socket.herror, socket.gaierror, OSError):
            logger.debug("DNS Enum: no PTR for %s", target)

        return items