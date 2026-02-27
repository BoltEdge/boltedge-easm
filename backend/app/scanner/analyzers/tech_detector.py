# app/scanner/analyzers/tech_detector.py
"""
Technology Fingerprinting Analyzer.

Reads data from Shodan services, HTTP headers, and page content to identify
what technologies are running on the target. Flags outdated or end-of-life
software versions.

Detection sources:
    - Shodan: product/version fields, CPE strings, banners
    - HTTP:   Server header, X-Powered-By, page title, meta generators
    - HTTP:   Response headers that indicate specific technologies
    - HTTP:   Cookie names that fingerprint frameworks

Produces:
    INFO:     Technology detected (always — builds asset inventory)
    LOW:      Outdated software version (update available)
    MEDIUM:   End-of-life software (no longer receiving security patches)
    HIGH:     Known-vulnerable version detected

Technology categories:
    web_server:  nginx, Apache, IIS, LiteSpeed, Caddy
    framework:   PHP, ASP.NET, Django, Rails, Express, Spring, Laravel
    cms:         WordPress, Drupal, Joomla, Magento
    cdn_waf:     Cloudflare, AWS CloudFront, Akamai, Fastly, Sucuri
    database:    MySQL, PostgreSQL, Redis (from Shodan product fields)
    os:          Linux, Windows, FreeBSD (from Shodan OS field)
    other:       Anything else identifiable
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Technology signatures
# ---------------------------------------------------------------------------

# Header-based detection: { header_name_lower: [(regex, tech_name, category)] }
HEADER_SIGNATURES: Dict[str, List[Tuple[str, str, str]]] = {
    "server": [
        (r"nginx[/ ]?([\d.]+)?", "nginx", "web_server"),
        (r"Apache[/ ]?([\d.]+)?", "Apache", "web_server"),
        (r"Microsoft-IIS[/ ]?([\d.]+)?", "IIS", "web_server"),
        (r"LiteSpeed[/ ]?([\d.]+)?", "LiteSpeed", "web_server"),
        (r"Caddy[/ ]?([\d.]+)?", "Caddy", "web_server"),
        (r"openresty[/ ]?([\d.]+)?", "OpenResty", "web_server"),
        (r"Cloudflare", "Cloudflare", "cdn_waf"),
        (r"AmazonS3", "Amazon S3", "cloud"),
        (r"Varnish", "Varnish", "cache"),
        (r"gunicorn[/ ]?([\d.]+)?", "Gunicorn", "web_server"),
    ],
    "x-powered-by": [
        (r"PHP[/ ]?([\d.]+)?", "PHP", "framework"),
        (r"ASP\.NET[/ ]?([\d.]+)?", "ASP.NET", "framework"),
        (r"Express", "Express.js", "framework"),
        (r"Next\.js[/ ]?([\d.]+)?", "Next.js", "framework"),
        (r"Phusion Passenger", "Passenger", "web_server"),
        (r"Servlet[/ ]?([\d.]+)?", "Java Servlet", "framework"),
    ],
    "x-aspnet-version": [
        (r"([\d.]+)", "ASP.NET", "framework"),
    ],
    "x-drupal-cache": [
        (r".*", "Drupal", "cms"),
    ],
    "x-generator": [
        (r"WordPress[/ ]?([\d.]+)?", "WordPress", "cms"),
        (r"Drupal[/ ]?([\d.]+)?", "Drupal", "cms"),
        (r"Joomla[/ ]?([\d.]+)?", "Joomla", "cms"),
    ],
    "x-varnish": [
        (r".*", "Varnish", "cache"),
    ],
}

# CDN/WAF detection from various headers
CDN_WAF_HEADERS: Dict[str, Tuple[str, str]] = {
    "cf-ray": ("Cloudflare", "cdn_waf"),
    "cf-cache-status": ("Cloudflare", "cdn_waf"),
    "x-amz-cf-id": ("AWS CloudFront", "cdn_waf"),
    "x-amz-cf-pop": ("AWS CloudFront", "cdn_waf"),
    "x-cache": ("CDN Cache", "cdn_waf"),  # Generic CDN
    "x-fastly-request-id": ("Fastly", "cdn_waf"),
    "x-sucuri-id": ("Sucuri WAF", "cdn_waf"),
    "x-sucuri-cache": ("Sucuri WAF", "cdn_waf"),
    "x-akamai-transformed": ("Akamai", "cdn_waf"),
    "x-azure-ref": ("Azure CDN", "cdn_waf"),
    "x-vercel-id": ("Vercel", "cloud"),
    "x-netlify-request-id": ("Netlify", "cloud"),
    "fly-request-id": ("Fly.io", "cloud"),
}

# Cookie-based fingerprinting: { cookie_name_pattern: (tech, category) }
COOKIE_SIGNATURES: Dict[str, Tuple[str, str]] = {
    "PHPSESSID": ("PHP", "framework"),
    "ASP.NET_SessionId": ("ASP.NET", "framework"),
    "JSESSIONID": ("Java", "framework"),
    "laravel_session": ("Laravel", "framework"),
    "ci_session": ("CodeIgniter", "framework"),
    "rack.session": ("Ruby/Rack", "framework"),
    "connect.sid": ("Express.js", "framework"),
    "_rails": ("Ruby on Rails", "framework"),
    "wordpress_": ("WordPress", "cms"),
    "wp-settings": ("WordPress", "cms"),
    "Drupal.visitor": ("Drupal", "cms"),
    "joomla_": ("Joomla", "cms"),
}

# Title/body-based signatures
CONTENT_SIGNATURES: List[Tuple[str, str, str]] = [
    (r"WordPress", "WordPress", "cms"),
    (r"wp-content|wp-includes", "WordPress", "cms"),
    (r"Drupal\.settings", "Drupal", "cms"),
    (r"Joomla!", "Joomla", "cms"),
    (r"/wp-login\.php", "WordPress", "cms"),
    (r"<meta\s+name=[\"']generator[\"']\s+content=[\"']WordPress\s*([\d.]*)", "WordPress", "cms"),
]

# EOL / known-vulnerable versions
# Format: { tech_name_lower: [(version_regex, severity, message)] }
EOL_VERSIONS: Dict[str, List[Tuple[str, str, str]]] = {
    "php": [
        (r"^5\.", "high", "PHP 5.x is end-of-life since January 2019. No security patches."),
        (r"^7\.[0-3]\.", "medium", "PHP 7.0-7.3 are end-of-life. Upgrade to PHP 8.x."),
        (r"^7\.4\.", "low", "PHP 7.4 is end-of-life since November 2022. Upgrade to PHP 8.x."),
        (r"^8\.0\.", "low", "PHP 8.0 is end-of-life since November 2023. Upgrade to 8.2+."),
    ],
    "apache": [
        (r"^2\.2\.", "medium", "Apache 2.2.x is end-of-life. Upgrade to 2.4.x."),
        (r"^2\.0\.", "high", "Apache 2.0.x is severely outdated. Upgrade to 2.4.x."),
        (r"^1\.", "high", "Apache 1.x is ancient and has known vulnerabilities."),
    ],
    "nginx": [
        (r"^0\.", "high", "nginx 0.x is severely outdated with known vulnerabilities."),
        (r"^1\.(0|1|2|3|4|5|6|7|8|9|1[0-7])\.", "low", "Consider updating nginx to a more recent version."),
    ],
    "iis": [
        (r"^[5-7]\.", "high", "IIS 5-7 runs on end-of-life Windows versions. Upgrade urgently."),
        (r"^8\.", "medium", "IIS 8.x (Windows Server 2012) is approaching end-of-life."),
    ],
    "wordpress": [
        (r"^[1-4]\.", "high", "WordPress 4.x and below have known vulnerabilities. Update to latest."),
        (r"^5\.", "low", "WordPress 5.x — consider updating to WordPress 6.x for latest security fixes."),
    ],
    "drupal": [
        (r"^[1-6]\.", "high", "Drupal 6 and below are end-of-life. Major vulnerabilities exist."),
        (r"^7\.", "medium", "Drupal 7 reaches end-of-life in January 2025. Plan migration to Drupal 10+."),
    ],
    "openssl": [
        (r"^0\.", "high", "OpenSSL 0.x has critical vulnerabilities including Heartbleed."),
        (r"^1\.0\.", "high", "OpenSSL 1.0.x is end-of-life. Upgrade to 3.x."),
        (r"^1\.1\.0", "medium", "OpenSSL 1.1.0 is end-of-life. Upgrade to 3.x."),
    ],
}


class TechDetector(BaseAnalyzer):
    """
    Identifies technologies running on the target and flags outdated versions.

    Combines data from Shodan (banners, product fields) and HTTP engine
    (headers, cookies, page content) to build a technology inventory.

    For each technology found:
        1. Creates an info-level finding (technology inventory)
        2. Checks against EOL/vulnerable version database
        3. If outdated, creates an additional finding with appropriate severity
    """

    @property
    def name(self) -> str:
        return "tech_detector"

    @property
    def required_engines(self) -> List[str]:
        return ["shodan", "http"]

    def analyze(self, ctx: ScanContext) -> List[FindingDraft]:
        drafts: List[FindingDraft] = []

        # Build technology inventory from all sources
        technologies = self._detect_technologies(ctx)

        # Deduplicate by (tech_name, category)
        seen: set = set()

        for tech in technologies:
            tech_key = (tech["name"].lower(), tech["category"])
            if tech_key in seen:
                continue
            seen.add(tech_key)

            # Info finding: technology detected
            drafts.append(self._tech_info_finding(tech, ctx))

            # Check for outdated/EOL versions
            eol_finding = self._check_eol(tech, ctx)
            if eol_finding:
                drafts.append(eol_finding)

        return drafts

    # -------------------------------------------------------------------
    # Technology detection
    # -------------------------------------------------------------------

    def _detect_technologies(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """Combine all detection sources into a unified tech list."""
        techs: List[Dict[str, Any]] = []

        # From Shodan product/version fields
        techs.extend(self._detect_from_shodan(ctx))

        # From HTTP headers
        techs.extend(self._detect_from_http_headers(ctx))

        # From cookies
        techs.extend(self._detect_from_cookies(ctx))

        # From page content
        techs.extend(self._detect_from_content(ctx))

        # OS from Shodan
        shodan_data = ctx.get_engine_data("shodan")
        os_info = shodan_data.get("os")
        if os_info:
            techs.append({
                "name": os_info,
                "version": None,
                "category": "os",
                "source": "shodan",
                "confidence": "medium",
            })

        return techs

    def _detect_from_shodan(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """Extract technologies from Shodan service product/version fields."""
        techs: List[Dict[str, Any]] = []
        shodan_data = ctx.get_engine_data("shodan")

        for svc in shodan_data.get("services", []):
            product = svc.get("product")
            version = svc.get("version")

            if not product:
                continue

            # Determine category from product name
            category = self._categorize_product(product)

            techs.append({
                "name": product,
                "version": version,
                "category": category,
                "source": "shodan",
                "port": svc.get("port"),
                "confidence": "high",
            })

            # Check CPE strings for additional tech
            for cpe in svc.get("cpe", []):
                cpe_tech = self._parse_cpe(cpe)
                if cpe_tech:
                    techs.append(cpe_tech)

        return techs

    def _detect_from_http_headers(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """Extract technologies from HTTP response headers."""
        techs: List[Dict[str, Any]] = []
        http_data = ctx.get_engine_data("http")

        for probe in http_data.get("probes", []):
            headers = probe.get("headers", {})
            if not headers:
                continue

            headers_lower = {k.lower(): v for k, v in headers.items()}

            # Check signature-based headers
            for header_name, signatures in HEADER_SIGNATURES.items():
                header_val = headers_lower.get(header_name, "")
                if not header_val:
                    continue

                for pattern, tech_name, category in signatures:
                    match = re.search(pattern, header_val, re.IGNORECASE)
                    if match:
                        version = match.group(1) if match.lastindex else None
                        techs.append({
                            "name": tech_name,
                            "version": version,
                            "category": category,
                            "source": "http_header",
                            "header": header_name,
                            "port": probe.get("port"),
                            "confidence": "high",
                        })

            # Check CDN/WAF indicator headers
            for header_name, (tech_name, category) in CDN_WAF_HEADERS.items():
                if header_name in headers_lower:
                    techs.append({
                        "name": tech_name,
                        "version": None,
                        "category": category,
                        "source": "http_header",
                        "header": header_name,
                        "port": probe.get("port"),
                        "confidence": "high",
                    })

        return techs

    def _detect_from_cookies(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """Detect technologies from cookie names."""
        techs: List[Dict[str, Any]] = []
        http_data = ctx.get_engine_data("http")

        for probe in http_data.get("probes", []):
            for cookie in probe.get("cookies", []):
                cookie_name = cookie.get("name", "")
                for pattern, (tech_name, category) in COOKIE_SIGNATURES.items():
                    if pattern.lower() in cookie_name.lower():
                        techs.append({
                            "name": tech_name,
                            "version": None,
                            "category": category,
                            "source": "cookie",
                            "cookie_name": cookie_name,
                            "port": probe.get("port"),
                            "confidence": "medium",
                        })
                        break

        return techs

    def _detect_from_content(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """Detect technologies from page title and body content."""
        techs: List[Dict[str, Any]] = []
        http_data = ctx.get_engine_data("http")

        for probe in http_data.get("probes", []):
            title = probe.get("title", "") or ""

            for pattern, tech_name, category in CONTENT_SIGNATURES:
                match = re.search(pattern, title, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex else None
                    techs.append({
                        "name": tech_name,
                        "version": version,
                        "category": category,
                        "source": "page_content",
                        "port": probe.get("port"),
                        "confidence": "medium",
                    })

        return techs

    # -------------------------------------------------------------------
    # Finding generators
    # -------------------------------------------------------------------

    def _tech_info_finding(
        self, tech: Dict[str, Any], ctx: ScanContext
    ) -> FindingDraft:
        """Create an info finding for a detected technology."""
        name = tech["name"]
        version = tech.get("version")
        category = tech["category"]

        title = f"Technology detected: {name}"
        if version:
            title += f" {version}"

        category_labels = {
            "web_server": "Web Server",
            "framework": "Framework/Language",
            "cms": "Content Management System",
            "cdn_waf": "CDN/WAF",
            "database": "Database",
            "os": "Operating System",
            "cache": "Cache Server",
            "cloud": "Cloud Platform",
        }
        cat_label = category_labels.get(category, category.title())

        return FindingDraft(
            template_id=f"tech-{name.lower().replace(' ', '-').replace('.', '-')}",
            title=title,
            severity="info",
            category="technology",
            description=(
                f"{cat_label} '{name}'"
                + (f" version {version}" if version else "")
                + f" detected on {ctx.asset_value}. "
                f"Detected via {tech.get('source', 'unknown')} with "
                f"{tech.get('confidence', 'medium')} confidence."
            ),
            finding_type="technology_detected",
            tags=["technology", category, name.lower()],
            engine=tech.get("source", "multiple"),
            confidence=tech.get("confidence", "medium"),
            details={
                "technology": name,
                "version": version,
                "category": category,
                "source": tech.get("source"),
                "port": tech.get("port"),
            },
            dedupe_fields={
                "tech": name.lower(),
                "category": category,
            },
        )

    def _check_eol(
        self, tech: Dict[str, Any], ctx: ScanContext
    ) -> Optional[FindingDraft]:
        """Check if a technology version is end-of-life or vulnerable."""
        name = tech["name"]
        version = tech.get("version")

        if not version:
            return None

        name_lower = name.lower()

        # Check EOL database
        eol_entries = EOL_VERSIONS.get(name_lower, [])

        for pattern, severity, message in eol_entries:
            if re.match(pattern, version):
                return FindingDraft(
                    template_id=f"tech-eol-{name_lower.replace(' ', '-')}",
                    title=f"Outdated {name} {version} on {ctx.asset_value}",
                    severity=severity,
                    category="technology",
                    description=(
                        f"{name} {version} is running on {ctx.asset_value}. "
                        f"{message} Outdated software may have unpatched "
                        "security vulnerabilities."
                    ),
                    remediation=(
                        f"Update {name} to the latest supported version. "
                        "Review the vendor's release notes for security fixes. "
                        "Test the upgrade in a staging environment first."
                    ),
                    finding_type="outdated_software",
                    cwe="CWE-1104",
                    tags=["technology", "outdated", name_lower],
                    engine=tech.get("source", "multiple"),
                    details={
                        "technology": name,
                        "current_version": version,
                        "eol_message": message,
                        "category": tech["category"],
                    },
                    dedupe_fields={
                        "tech": name_lower,
                        "check": "eol",
                    },
                )

        return None

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _categorize_product(self, product: str) -> str:
        """Guess a technology category from a Shodan product name."""
        p = product.lower()

        web_servers = ["nginx", "apache", "iis", "litespeed", "caddy", "openresty", "gunicorn", "tomcat"]
        databases = ["mysql", "postgresql", "postgres", "redis", "mongodb", "elasticsearch", "mariadb", "mssql"]
        mail = ["postfix", "exim", "dovecot", "sendmail", "exchange"]
        ssh = ["openssh", "dropbear"]

        for ws in web_servers:
            if ws in p:
                return "web_server"
        for db in databases:
            if db in p:
                return "database"
        for m in mail:
            if m in p:
                return "email"
        for s in ssh:
            if s in p:
                return "remote_access"

        return "other"

    def _parse_cpe(self, cpe: str) -> Optional[Dict[str, Any]]:
        """Parse a CPE string into a technology dict."""
        # CPE format: cpe:/a:vendor:product:version or cpe:2.3:a:vendor:product:version
        try:
            parts = cpe.split(":")
            if len(parts) >= 5:
                vendor = parts[3] if parts[1] == "2.3" else parts[2]
                product = parts[4] if parts[1] == "2.3" else parts[3]
                version = parts[5] if parts[1] == "2.3" and len(parts) > 5 else (
                    parts[4] if parts[1] != "2.3" and len(parts) > 4 else None
                )

                if version in ("*", "-", ""):
                    version = None

                return {
                    "name": product.replace("_", " ").title(),
                    "version": version,
                    "category": self._categorize_product(product),
                    "source": "cpe",
                    "cpe": cpe,
                    "confidence": "high",
                }
        except Exception:
            pass
        return None