# app/scanner/engines/dns_engine.py
"""
DNS Reconnaissance engine.

Queries DNS records for a domain and collects configuration data for
security analysis.

Uses dnspython (dns.resolver) if available, falls back to stdlib socket
for basic A/AAAA resolution.

What this engine collects:
    - A records (IPv4 addresses)
    - AAAA records (IPv6 addresses)
    - MX records (mail servers + priorities)
    - NS records (nameservers)
    - TXT records (SPF, DKIM, DMARC, verification tokens)
    - CNAME records
    - SOA record (primary NS, admin email, serial)
    - SPF record parsed separately
    - DMARC record parsed separately
    - Zone transfer attempt result (AXFR)
    - Discovered subdomains from Shodan/CT data
    - Subdomain takeover checks (dangling CNAME detection)
      Now checks BOTH root domain AND discovered subdomains

Output data structure (stored in EngineResult.data):
    {
        "records": {
            "A": ["1.2.3.4"],
            "AAAA": ["2001:db8::1"],
            "MX": [{"priority": 10, "host": "mail.example.com"}],
            "NS": ["ns1.example.com", "ns2.example.com"],
            "TXT": ["v=spf1 include:_spf.google.com ~all", ...],
            "CNAME": ["example.com.cdn.cloudflare.net"],
            "SOA": {"primary_ns": "ns1.example.com", "admin": "admin.example.com", "serial": 2025010101}
        },
        "spf": {"raw": "v=spf1 ...", "mechanisms": [...], "all_qualifier": "~"},
        "dmarc": {"raw": "v=DMARC1; ...", "policy": "reject", "rua": "...", "pct": 100},
        "dkim_selectors_found": ["google", "selector1"],
        "zone_transfer": {"attempted": true, "successful": false, "server": "ns1.example.com"},
        "subdomains": ["www", "mail", "api"],
        "subdomain_takeover_checks": [
            {"domain": "blog.example.com", "cname_target": "example.herokuapp.com",
             "service": "Heroku", "vulnerable": true, "evidence": "...", "detection_method": "http_fingerprint"}
        ],
        "nameserver_count": 2,
        "has_ipv6": true,
        "has_mail": true
    }

Profile config options:
    attempt_zone_transfer:  bool  — try AXFR (default: False for Quick, True for Deep)
    check_dkim_selectors:   list  — common DKIM selectors to check
    timeout:                int   — query timeout in seconds (default: 5)
    max_subdomain_takeover_checks: int — max subdomains to check for takeover (default: 50)
"""

from __future__ import annotations

import logging
import re
import socket
import ssl as _ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from app.scanner.base import BaseEngine, EngineResult, ScanContext

logger = logging.getLogger(__name__)

# Common DKIM selectors to probe
DEFAULT_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "k1", "k2", "mail", "dkim", "s1", "s2",
    "mandrill", "amazonses", "zendesk",
]

# ---------------------------------------------------------------------------
# Subdomain takeover fingerprints
# ---------------------------------------------------------------------------
# Maps CNAME suffix patterns to service info. When a CNAME target matches
# a pattern, the engine probes the original domain for the fingerprint
# string in the HTTP response body or checks for NXDOMAIN on the target.
#
# Sources: https://github.com/EdOverflow/can-i-take-over-xyz
# ---------------------------------------------------------------------------

TAKEOVER_FINGERPRINTS = {
    # ── Cloud Platforms ──
    ".amazonaws.com": {
        "service": "AWS S3 / CloudFront",
        "fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
    },
    ".cloudfront.net": {
        "service": "AWS CloudFront",
        "fingerprints": [
            "Bad request",
            "ERROR: The request could not be satisfied",
        ],
    },
    ".elasticbeanstalk.com": {
        "service": "AWS Elastic Beanstalk",
        "fingerprints": [],
        "nxdomain_vulnerable": True,
    },
    ".azurewebsites.net": {
        "service": "Azure App Service",
        "fingerprints": [
            "404 Web Site not found",
            "Microsoft Azure App Service",
        ],
    },
    ".blob.core.windows.net": {
        "service": "Azure Blob Storage",
        "fingerprints": [
            "The specified resource does not exist",
            "BlobNotFound",
        ],
    },
    ".cloudapp.azure.com": {
        "service": "Azure Virtual Machine",
        "fingerprints": [],
        "nxdomain_vulnerable": True,
    },
    ".azureedge.net": {
        "service": "Azure CDN",
        "fingerprints": [
            "404 Web Site not found",
            "<h2>Our services aren't available right now</h2>",
        ],
    },
    ".trafficmanager.net": {
        "service": "Azure Traffic Manager",
        "fingerprints": [],
        "nxdomain_vulnerable": True,
    },
    ".azure-api.net": {
        "service": "Azure API Management",
        "fingerprints": [
            "ResourceNotFound",
        ],
    },
    ".storage.googleapis.com": {
        "service": "Google Cloud Storage",
        "fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
    },

    # ── Hosting / PaaS ──
    ".herokuapp.com": {
        "service": "Heroku",
        "fingerprints": [
            "No such app",
            "no-such-app",
            "herokucdn.com/error-pages/no-such-app",
        ],
    },
    ".ghost.io": {
        "service": "Ghost",
        "fingerprints": [
            "The thing you were looking for is no longer here",
            "404 — Ghost",
        ],
    },
    ".pantheonsite.io": {
        "service": "Pantheon",
        "fingerprints": [
            "404 error unknown site",
            "The gods are wise",
        ],
    },
    ".netlify.app": {
        "service": "Netlify",
        "fingerprints": [
            "Not Found - Request ID",
        ],
    },
    ".netlify.com": {
        "service": "Netlify",
        "fingerprints": [
            "Not Found - Request ID",
        ],
    },
    ".fly.dev": {
        "service": "Fly.io",
        "fingerprints": [],
        "nxdomain_vulnerable": True,
    },
    ".vercel.app": {
        "service": "Vercel",
        "fingerprints": [],
        "nxdomain_vulnerable": True,
    },
    ".render.com": {
        "service": "Render",
        "fingerprints": [],
        "nxdomain_vulnerable": True,
    },
    ".surge.sh": {
        "service": "Surge.sh",
        "fingerprints": [
            "project not found",
        ],
    },

    # ── Git Pages ──
    ".github.io": {
        "service": "GitHub Pages",
        "fingerprints": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
    },
    ".gitlab.io": {
        "service": "GitLab Pages",
        "fingerprints": [],
        "nxdomain_vulnerable": True,
    },
    ".bitbucket.io": {
        "service": "Bitbucket Pages",
        "fingerprints": [
            "Repository not found",
        ],
    },

    # ── E-commerce / CMS ──
    ".myshopify.com": {
        "service": "Shopify",
        "fingerprints": [
            "Sorry, this shop is currently unavailable",
            "Only one step left",
        ],
    },
    ".wordpress.com": {
        "service": "WordPress.com",
        "fingerprints": [
            "Do you want to register",
        ],
    },
    ".tumblr.com": {
        "service": "Tumblr",
        "fingerprints": [
            "Whatever you were looking for doesn't currently exist at this address",
            "There's nothing here",
        ],
    },

    # ── Helpdesk / SaaS ──
    ".zendesk.com": {
        "service": "Zendesk",
        "fingerprints": [
            "Help Center Closed",
        ],
    },
    ".freshdesk.com": {
        "service": "Freshdesk",
        "fingerprints": [
            "May be this is still fresh",
            "There is no helpdesk here",
        ],
    },
    ".helpjuice.com": {
        "service": "Helpjuice",
        "fingerprints": [
            "We could not find what you're looking for",
        ],
    },
    ".helpscoutdocs.com": {
        "service": "HelpScout",
        "fingerprints": [
            "No settings were found for this company",
        ],
    },
    ".tilda.ws": {
        "service": "Tilda",
        "fingerprints": [
            "Domain is not configured",
            "Please renew your subscription",
        ],
    },

    # ── Marketing / Landing pages ──
    ".unbounce.com": {
        "service": "Unbounce",
        "fingerprints": [
            "The requested URL was not found on this server",
        ],
    },
    ".launchrock.com": {
        "service": "LaunchRock",
        "fingerprints": [
            "It looks like you may have taken a wrong turn somewhere",
        ],
    },
    ".landingi.com": {
        "service": "Landingi",
        "fingerprints": [],
        "nxdomain_vulnerable": True,
    },
    ".cargocollective.com": {
        "service": "Cargo Collective",
        "fingerprints": [
            "404 Not Found",
        ],
    },
    ".webflow.io": {
        "service": "Webflow",
        "fingerprints": [
            "The page you are looking for doesn't exist or has been moved",
        ],
    },

    # ── CDN / DNS ──
    ".fastly.net": {
        "service": "Fastly",
        "fingerprints": [
            "Fastly error: unknown domain",
        ],
    },
    ".cdn.cloudflare.net": {
        "service": "Cloudflare",
        "fingerprints": [],
        "nxdomain_vulnerable": True,
    },

    # ── Status pages / Docs ──
    ".statuspage.io": {
        "service": "Statuspage (Atlassian)",
        "fingerprints": [
            "You are being <a href=",
            "StatusPage",
        ],
    },
    ".readme.io": {
        "service": "ReadMe.io",
        "fingerprints": [
            "Project doesnt exist",
        ],
    },

    # ── Feedback / Engagement ──
    ".uservoice.com": {
        "service": "UserVoice",
        "fingerprints": [
            "This UserVoice subdomain is currently available",
        ],
    },
    ".feedpress.me": {
        "service": "Feedpress",
        "fingerprints": [
            "The feed has not been found",
        ],
    },

    # ── Project Management ──
    ".teamwork.com": {
        "service": "Teamwork",
        "fingerprints": [
            "Oops - We didn't find your site",
        ],
    },
}


# Check if dnspython is available
_HAS_DNSPYTHON = False
try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.rdatatype
    _HAS_DNSPYTHON = True
except ImportError:
    logger.info("dnspython not available — DNS engine will use limited socket fallback")


class DNSEngine(BaseEngine):
    """
    Queries DNS records for security analysis.

    Uses dnspython for full DNS record enumeration. Falls back to
    stdlib socket for basic A/AAAA lookups if dnspython is not installed.

    Profile config:
        attempt_zone_transfer: bool — try AXFR (default: False)
        check_dkim_selectors:  list — DKIM selectors to probe
        timeout:               int  — query timeout (default: 5)
        max_subdomain_takeover_checks: int — max subdomains to check (default: 50)
    """

    @property
    def name(self) -> str:
        return "dns"

    @property
    def supported_asset_types(self) -> List[str]:
        return ["domain"]

    def execute(self, ctx: ScanContext, config: Dict[str, Any]) -> EngineResult:
        result = EngineResult(engine_name=self.name)

        domain = ctx.asset_value.strip().lower()
        if domain.startswith("*."):
            domain = domain[2:]

        if not domain:
            result.success = False
            result.add_error("Empty domain")
            return result

        timeout = config.get("timeout", 5)
        attempt_axfr = config.get("attempt_zone_transfer", False)
        dkim_selectors = config.get("check_dkim_selectors", DEFAULT_DKIM_SELECTORS)
        max_takeover_checks = config.get("max_subdomain_takeover_checks", 50)

        if _HAS_DNSPYTHON:
            records = self._query_all_records(domain, timeout)
        else:
            records = self._fallback_query(domain)

        # Parse SPF from TXT records
        spf = self._parse_spf(records.get("TXT", []))

        # Parse DMARC
        dmarc = None
        if _HAS_DNSPYTHON:
            dmarc = self._query_dmarc(domain, timeout)

        # Check DKIM selectors
        dkim_found = []
        if _HAS_DNSPYTHON:
            dkim_found = self._check_dkim_selectors(domain, dkim_selectors, timeout)

        # Attempt zone transfer
        zone_transfer = {"attempted": False, "successful": False}
        if attempt_axfr and _HAS_DNSPYTHON:
            ns_servers = records.get("NS", [])
            zone_transfer = self._attempt_zone_transfer(domain, ns_servers, timeout)

        # Extract subdomains from Shodan data
        subdomains = self._extract_subdomains_from_context(ctx, domain)

        # --- Subdomain takeover detection ---
        # Check root domain CNAMEs
        cname_records = records.get("CNAME", [])
        takeover_checks = []
        if cname_records:
            takeover_checks = self._check_subdomain_takeover(
                domain=domain,
                cname_records=cname_records,
                timeout=timeout,
            )

        # Check discovered subdomains for dangling CNAMEs
        if _HAS_DNSPYTHON and subdomains:
            sub_checks = self._check_subdomain_cnames_for_takeover(
                parent_domain=domain,
                subdomains=subdomains,
                timeout=timeout,
                max_checks=max_takeover_checks,
            )
            takeover_checks.extend(sub_checks)

        if takeover_checks:
            logger.info(
                f"DNS Engine: {len(takeover_checks)} takeover check(s) for "
                f"{domain} ({sum(1 for c in takeover_checks if c.get('vulnerable'))} vulnerable)"
            )

        # Build summary flags
        has_ipv6 = len(records.get("AAAA", [])) > 0
        has_mail = len(records.get("MX", [])) > 0
        ns_count = len(records.get("NS", []))

        result.data = {
            "domain": domain,
            "records": records,
            "spf": spf,
            "dmarc": dmarc,
            "dkim_selectors_found": dkim_found,
            "zone_transfer": zone_transfer,
            "subdomains": subdomains,
            "subdomain_takeover_checks": takeover_checks,
            "nameserver_count": ns_count,
            "has_ipv6": has_ipv6,
            "has_mail": has_mail,
        }

        result.metadata = {
            "dnspython_available": _HAS_DNSPYTHON,
            "record_types_queried": list(records.keys()),
            "dkim_selectors_checked": len(dkim_selectors),
            "takeover_checks_count": len(takeover_checks),
            "subdomains_checked_for_takeover": min(len(subdomains), max_takeover_checks),
        }

        return result

    # -------------------------------------------------------------------
    # Full DNS queries (dnspython)
    # -------------------------------------------------------------------

    def _query_all_records(self, domain: str, timeout: int) -> Dict[str, List]:
        """Query all DNS record types using dnspython."""
        records: Dict[str, List] = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout * 2

        # A records
        records["A"] = self._query_record(resolver, domain, "A")

        # AAAA records
        records["AAAA"] = self._query_record(resolver, domain, "AAAA")

        # MX records
        mx_raw = self._query_record(resolver, domain, "MX")
        records["MX"] = []
        for entry in mx_raw:
            # MX entries come as "priority host"
            parts = str(entry).split()
            if len(parts) >= 2:
                try:
                    records["MX"].append({
                        "priority": int(parts[0]),
                        "host": parts[1].rstrip("."),
                    })
                except ValueError:
                    records["MX"].append({"priority": 0, "host": str(entry)})

        # NS records
        ns_raw = self._query_record(resolver, domain, "NS")
        records["NS"] = [str(r).rstrip(".") for r in ns_raw]

        # TXT records
        txt_raw = self._query_record(resolver, domain, "TXT")
        records["TXT"] = []
        for entry in txt_raw:
            # TXT records may be split into multiple strings
            txt_val = str(entry).strip('"')
            records["TXT"].append(txt_val)

        # CNAME records
        records["CNAME"] = [
            str(r).rstrip(".") for r in self._query_record(resolver, domain, "CNAME")
        ]

        # SOA record
        soa_raw = self._query_record(resolver, domain, "SOA")
        if soa_raw:
            soa_str = str(soa_raw[0])
            soa_parts = soa_str.split()
            if len(soa_parts) >= 2:
                records["SOA"] = {
                    "primary_ns": soa_parts[0].rstrip("."),
                    "admin": soa_parts[1].rstrip("."),
                    "serial": int(soa_parts[2]) if len(soa_parts) > 2 else None,
                    "refresh": int(soa_parts[3]) if len(soa_parts) > 3 else None,
                    "retry": int(soa_parts[4]) if len(soa_parts) > 4 else None,
                    "expire": int(soa_parts[5]) if len(soa_parts) > 5 else None,
                    "min_ttl": int(soa_parts[6]) if len(soa_parts) > 6 else None,
                }

        return records

    def _query_record(
        self,
        resolver: "dns.resolver.Resolver",
        domain: str,
        rdtype: str,
    ) -> List:
        """Query a single DNS record type. Returns empty list on failure."""
        try:
            answers = resolver.resolve(domain, rdtype)
            return [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoNameservers:
            return []
        except dns.resolver.LifetimeTimeout:
            return []
        except Exception as e:
            logger.debug(f"DNS query failed for {domain} {rdtype}: {e}")
            return []

    def _query_dmarc(self, domain: str, timeout: int) -> Optional[Dict[str, Any]]:
        """Query DMARC record at _dmarc.domain."""
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout * 2

        dmarc_domain = f"_dmarc.{domain}"
        txt_records = self._query_record(resolver, dmarc_domain, "TXT")

        for txt in txt_records:
            txt_clean = str(txt).strip('"')
            if txt_clean.lower().startswith("v=dmarc1"):
                return self._parse_dmarc(txt_clean)

        return None

    def _check_dkim_selectors(
        self,
        domain: str,
        selectors: List[str],
        timeout: int,
    ) -> List[str]:
        """Check which DKIM selectors exist for the domain."""
        found = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        for selector in selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            result = self._query_record(resolver, dkim_domain, "TXT")
            if result:
                found.append(selector)

        return found

    def _attempt_zone_transfer(
        self,
        domain: str,
        nameservers: List[str],
        timeout: int,
    ) -> Dict[str, Any]:
        """Attempt AXFR zone transfer against nameservers."""
        result = {"attempted": True, "successful": False, "server": None, "records_count": 0}

        for ns in nameservers[:3]:  # Try first 3 NS
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns, domain, timeout=timeout)
                )
                if zone:
                    names = [str(name) for name in zone.nodes.keys()]
                    result["successful"] = True
                    result["server"] = ns
                    result["records_count"] = len(names)
                    result["sample_records"] = names[:50]  # Cap sample
                    return result
            except Exception:
                continue

        return result

    # -------------------------------------------------------------------
    # Fallback queries (stdlib socket only)
    # -------------------------------------------------------------------

    def _fallback_query(self, domain: str) -> Dict[str, List]:
        """Basic DNS query using stdlib socket when dnspython is unavailable."""
        records: Dict[str, List] = {}

        # A records
        ips_v4 = []
        ips_v6 = []
        try:
            for family, *_rest, sockaddr in socket.getaddrinfo(domain, None):
                ip = sockaddr[0]
                if family == socket.AF_INET and ip not in ips_v4:
                    ips_v4.append(ip)
                elif family == socket.AF_INET6 and ip not in ips_v6:
                    ips_v6.append(ip)
        except Exception as e:
            logger.debug(f"Fallback DNS failed for {domain}: {e}")

        records["A"] = ips_v4
        records["AAAA"] = ips_v6
        records["MX"] = []
        records["NS"] = []
        records["TXT"] = []
        records["CNAME"] = []

        return records

    # -------------------------------------------------------------------
    # Record parsers
    # -------------------------------------------------------------------

    def _parse_spf(self, txt_records: List[str]) -> Optional[Dict[str, Any]]:
        """Parse SPF record from TXT records."""
        for txt in txt_records:
            if txt.lower().startswith("v=spf1"):
                return self._parse_spf_record(txt)
        return None

    def _parse_spf_record(self, raw: str) -> Dict[str, Any]:
        """Parse an SPF record into structured data."""
        result: Dict[str, Any] = {"raw": raw, "mechanisms": [], "all_qualifier": None}

        parts = raw.split()
        for part in parts[1:]:  # Skip "v=spf1"
            part_lower = part.lower()

            # Detect the "all" mechanism and its qualifier
            if part_lower.endswith("all"):
                prefix = part_lower.replace("all", "")
                result["all_qualifier"] = prefix or "+"
                result["mechanisms"].append(part)
                continue

            result["mechanisms"].append(part)

        return result

    def _parse_dmarc(self, raw: str) -> Dict[str, Any]:
        """Parse a DMARC record into structured data."""
        result: Dict[str, Any] = {"raw": raw}

        # Parse tag=value pairs
        for part in raw.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            tag, value = part.split("=", 1)
            tag = tag.strip().lower()
            value = value.strip()

            if tag == "p":
                result["policy"] = value.lower()
            elif tag == "sp":
                result["subdomain_policy"] = value.lower()
            elif tag == "rua":
                result["rua"] = value
            elif tag == "ruf":
                result["ruf"] = value
            elif tag == "pct":
                try:
                    result["pct"] = int(value)
                except ValueError:
                    result["pct"] = value
            elif tag == "adkim":
                result["dkim_alignment"] = "strict" if value.lower() == "s" else "relaxed"
            elif tag == "aspf":
                result["spf_alignment"] = "strict" if value.lower() == "s" else "relaxed"

        return result

    # -------------------------------------------------------------------
    # Subdomain extraction from context
    # -------------------------------------------------------------------

    def _extract_subdomains_from_context(
        self, ctx: ScanContext, domain: str
    ) -> List[str]:
        """Extract subdomains from Shodan hostnames data."""
        subdomains = set()

        # From Shodan
        shodan_data = ctx.get_engine_data("shodan")
        for hostname in shodan_data.get("hostnames", []):
            hostname = hostname.lower().rstrip(".")
            if hostname.endswith(f".{domain}"):
                sub = hostname[: -(len(domain) + 1)]
                if sub:
                    subdomains.add(sub)

        # From services hostnames
        for svc in shodan_data.get("services", []):
            for hostname in svc.get("hostnames", []):
                hostname = hostname.lower().rstrip(".")
                if hostname.endswith(f".{domain}"):
                    sub = hostname[: -(len(domain) + 1)]
                    if sub:
                        subdomains.add(sub)

        return sorted(subdomains)

    # -------------------------------------------------------------------
    # Subdomain takeover detection
    # -------------------------------------------------------------------

    def _check_subdomain_cnames_for_takeover(
        self,
        parent_domain: str,
        subdomains: List[str],
        timeout: int,
        max_checks: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        Query CNAME records for discovered subdomains and check each
        for dangling references to third-party services.

        This extends the root-domain takeover check to cover subdomains
        like blog.example.com, shop.example.com, etc., which are the
        most common targets for subdomain takeover attacks.

        Args:
            parent_domain: The root domain (e.g., "example.com")
            subdomains:    List of subdomain prefixes (e.g., ["blog", "shop", "api"])
            timeout:       DNS query timeout in seconds
            max_checks:    Maximum number of subdomains to check (prevents slow scans)

        Returns:
            List of takeover check results (same format as _check_subdomain_takeover)
        """
        all_checks: List[Dict[str, Any]] = []

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout * 2

        checked = 0
        for sub in subdomains:
            if checked >= max_checks:
                logger.info(
                    f"Reached max subdomain takeover checks ({max_checks}) for {parent_domain}"
                )
                break

            fqdn = f"{sub}.{parent_domain}"

            # Query CNAME for this subdomain
            cname_records = self._query_record(resolver, fqdn, "CNAME")
            if not cname_records:
                checked += 1
                continue

            # Clean up CNAME values
            cname_clean = [str(r).rstrip(".") for r in cname_records]

            # Run takeover checks on these CNAMEs
            checks = self._check_subdomain_takeover(
                domain=fqdn,
                cname_records=cname_clean,
                timeout=timeout,
            )
            all_checks.extend(checks)
            checked += 1

        if all_checks:
            logger.info(
                f"Subdomain CNAME takeover: checked {checked}/{len(subdomains)} "
                f"subdomains of {parent_domain}, found {len(all_checks)} result(s)"
            )

        return all_checks

    def _check_subdomain_takeover(
        self,
        domain: str,
        cname_records: List[str],
        timeout: int,
    ) -> List[Dict[str, Any]]:
        """
        Check if CNAME targets point to decommissioned services.

        For each CNAME record:
          1. Match against known vulnerable service patterns
          2. Check if the CNAME target resolves (NXDOMAIN = possible takeover)
          3. Make an HTTP request to the original domain and check for
             fingerprint strings in the response body

        Returns a list of check results (only for CNAMEs that match a
        known service pattern — non-matching CNAMEs are skipped).
        """
        results: List[Dict[str, Any]] = []

        for cname_target in cname_records:
            cname_lower = cname_target.lower().rstrip(".")

            # Find matching service fingerprint
            matched_pattern = None
            service_info = None
            for pattern, info in TAKEOVER_FINGERPRINTS.items():
                if cname_lower.endswith(pattern):
                    matched_pattern = pattern
                    service_info = info
                    break

            if not service_info:
                continue  # CNAME doesn't match any known vulnerable service

            check_result: Dict[str, Any] = {
                "domain": domain,
                "cname_target": cname_target,
                "service": service_info["service"],
                "pattern_matched": matched_pattern,
                "vulnerable": False,
                "evidence": None,
                "detection_method": None,
            }

            # Step 1: Check if CNAME target resolves
            target_resolves = self._does_resolve(cname_lower, timeout)

            if not target_resolves and service_info.get("nxdomain_vulnerable"):
                # CNAME target doesn't resolve and service is known to be
                # claimable when NXDOMAIN — confirmed vulnerable
                check_result["vulnerable"] = True
                check_result["evidence"] = (
                    f"CNAME target {cname_target} does not resolve (NXDOMAIN)"
                )
                check_result["detection_method"] = "nxdomain"
                results.append(check_result)
                continue

            if not target_resolves and not service_info.get("fingerprints"):
                # Doesn't resolve and no HTTP fingerprints to check — suspicious
                check_result["evidence"] = (
                    f"CNAME target {cname_target} does not resolve"
                )
                check_result["detection_method"] = "nxdomain_unconfirmed"
                results.append(check_result)
                continue

            # Step 2: HTTP fingerprint check
            if service_info.get("fingerprints"):
                http_result = self._http_fingerprint_check(
                    domain=domain,
                    fingerprints=service_info["fingerprints"],
                    timeout=timeout,
                )
                if http_result["matched"]:
                    check_result["vulnerable"] = True
                    check_result["evidence"] = http_result["evidence"]
                    check_result["detection_method"] = "http_fingerprint"
                    check_result["http_status"] = http_result.get("status_code")
                elif http_result.get("error"):
                    check_result["evidence"] = http_result["error"]
                    check_result["detection_method"] = "http_error"

            results.append(check_result)

        return results

    def _does_resolve(self, hostname: str, timeout: int = 3) -> bool:
        """Check if a hostname resolves to any IP address."""
        try:
            socket.setdefaulttimeout(timeout)
            socket.getaddrinfo(hostname, None)
            return True
        except (socket.gaierror, socket.herror, OSError):
            return False
        finally:
            socket.setdefaulttimeout(None)

    def _http_fingerprint_check(
        self,
        domain: str,
        fingerprints: List[str],
        timeout: int = 5,
    ) -> Dict[str, Any]:
        """
        Make an HTTP(S) request to the domain and check if the response
        body contains any of the known fingerprint strings.

        Tries HTTPS first, falls back to HTTP.
        """
        result: Dict[str, Any] = {
            "matched": False,
            "evidence": None,
            "status_code": None,
            "error": None,
        }

        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                req = Request(url, headers={
                    "User-Agent": "Mozilla/5.0 (compatible; BoltEdge EASM Scanner)",
                    "Accept": "text/html,*/*",
                })

                ssl_ctx = None
                if scheme == "https":
                    ssl_ctx = _ssl.create_default_context()
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = _ssl.CERT_NONE

                response = urlopen(req, timeout=timeout, context=ssl_ctx)
                body = response.read(65536).decode("utf-8", errors="replace")
                status = response.status

                result["status_code"] = status

                for fp in fingerprints:
                    if fp.lower() in body.lower():
                        result["matched"] = True
                        result["evidence"] = (
                            f"HTTP {status} response from {url} contains "
                            f"fingerprint: \"{fp}\""
                        )
                        return result

                # Got a response but no fingerprint matched
                return result

            except HTTPError as e:
                # Some services return 404 with the fingerprint in the error page
                body = ""
                try:
                    body = e.read(65536).decode("utf-8", errors="replace")
                except Exception:
                    pass

                result["status_code"] = e.code

                for fp in fingerprints:
                    if fp.lower() in body.lower():
                        result["matched"] = True
                        result["evidence"] = (
                            f"HTTP {e.code} response from {url} contains "
                            f"fingerprint: \"{fp}\""
                        )
                        return result

                return result

            except URLError:
                continue  # Try next scheme
            except Exception as e:
                result["error"] = f"{type(e).__name__}: {str(e)}"
                continue  # Try next scheme

        if not result["error"]:
            result["error"] = f"Could not connect to {domain} on HTTP or HTTPS"

        return result