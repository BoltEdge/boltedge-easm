# app/scanner/analyzers/header_analyzer.py
"""
HTTP Security Headers Analyzer.

Reads HTTP probe data and checks for missing or misconfigured security headers.

Checks performed:
    HIGH:
        - Missing X-Frame-Options (clickjacking)
        - Server header exposes version info (information leakage)
        - HTTP does not redirect to HTTPS

    MEDIUM:
        - Missing Strict-Transport-Security (HSTS)
        - Missing Content-Security-Policy (CSP)
        - Missing X-Content-Type-Options
        - Missing Referrer-Policy
        - Missing Permissions-Policy
        - Cookies without Secure flag (on HTTPS)
        - Cookies without HttpOnly flag
        - Cookies without SameSite attribute

    LOW:
        - X-Powered-By header exposes technology
        - Missing X-XSS-Protection (legacy but noted)

    INFO:
        - Security headers summary (which are present/missing)
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext

logger = logging.getLogger(__name__)


# Security headers to check — order matters for the summary
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": (
            "The Strict-Transport-Security (HSTS) header is missing. Without HSTS, "
            "users can be downgraded from HTTPS to HTTP via man-in-the-middle attacks. "
            "HSTS tells browsers to always use HTTPS for this domain."
        ),
        "remediation": (
            "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains. "
            "Start with a short max-age (e.g., 300) for testing, then increase to 1 year."
        ),
        "cwe": "CWE-319",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": (
            "The Content-Security-Policy (CSP) header is missing. CSP prevents "
            "cross-site scripting (XSS) and data injection attacks by controlling "
            "which resources the browser is allowed to load."
        ),
        "remediation": (
            "Add a Content-Security-Policy header. Start with a report-only policy "
            "to identify issues: Content-Security-Policy-Report-Only: default-src 'self'. "
            "Then tighten based on your application's needs."
        ),
        "cwe": "CWE-79",
    },
    "X-Frame-Options": {
        "severity": "high",
        "description": (
            "The X-Frame-Options header is missing. This allows the page to be "
            "embedded in iframes on other sites, enabling clickjacking attacks "
            "where users are tricked into clicking hidden elements."
        ),
        "remediation": (
            "Add the header: X-Frame-Options: DENY (or SAMEORIGIN if you need "
            "to embed the page on your own site). CSP frame-ancestors directive "
            "is the modern replacement."
        ),
        "cwe": "CWE-1021",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": (
            "The X-Content-Type-Options header is missing. Without it, browsers "
            "may MIME-sniff responses, potentially treating non-script files as "
            "scripts, enabling XSS attacks."
        ),
        "remediation": "Add the header: X-Content-Type-Options: nosniff",
        "cwe": "CWE-16",
    },
    "Referrer-Policy": {
        "severity": "medium",
        "description": (
            "The Referrer-Policy header is missing. By default, browsers send "
            "the full URL (including query parameters) as the Referer header "
            "when navigating, potentially leaking sensitive data."
        ),
        "remediation": (
            "Add the header: Referrer-Policy: strict-origin-when-cross-origin "
            "(recommended) or no-referrer for maximum privacy."
        ),
    },
    "Permissions-Policy": {
        "severity": "medium",
        "description": (
            "The Permissions-Policy (formerly Feature-Policy) header is missing. "
            "This header controls which browser features (camera, microphone, "
            "geolocation, etc.) can be used by the page and embedded content."
        ),
        "remediation": (
            "Add a Permissions-Policy header disabling features you don't need: "
            "Permissions-Policy: camera=(), microphone=(), geolocation=()"
        ),
    },
}


class HeaderAnalyzer(BaseAnalyzer):
    """
    Checks HTTP responses for missing or misconfigured security headers.

    Reads probe data from the HTTP engine and Shodan's HTTP data.
    For each HTTPS response, checks all security headers and produces
    findings for missing or weak ones.
    """

    @property
    def name(self) -> str:
        return "header_analyzer"

    @property
    def required_engines(self) -> List[str]:
        return ["http", "shodan"]

    def analyze(self, ctx: ScanContext) -> List[FindingDraft]:
        drafts: List[FindingDraft] = []

        # Collect HTTP probes from all sources
        probes = self._collect_probes(ctx)

        if not probes:
            return drafts

        # Analyze each probe
        seen_checks: set = set()

        for probe in probes:
            if probe.get("error"):
                continue

            headers = probe.get("headers", {})
            if not headers:
                continue

            port = probe.get("port", 0)
            scheme = probe.get("scheme", "http")
            url = probe.get("url", f"{scheme}://{ctx.asset_value}:{port}")

            # Only check security headers on the primary HTTPS probe
            # (avoid duplicate findings for same header on multiple ports)
            check_key = f"{scheme}:{port}"
            if check_key in seen_checks:
                continue
            seen_checks.add(check_key)

            # --- Missing security headers ---
            if scheme == "https" or port == 443:
                drafts.extend(
                    self._check_security_headers(headers, url, port, ctx)
                )

            # --- Server version leakage ---
            server_finding = self._check_server_header(headers, url, port)
            if server_finding:
                drafts.append(server_finding)

            # --- X-Powered-By leakage ---
            powered_finding = self._check_powered_by(headers, url, port)
            if powered_finding:
                drafts.append(powered_finding)

            # --- Cookie security ---
            cookies = probe.get("cookies", [])
            if cookies and (scheme == "https" or port == 443):
                drafts.extend(self._check_cookies(cookies, url, port))

            # --- HTTP to HTTPS redirect ---
            if scheme == "http" and probe.get("http_to_https_redirect") is False:
                drafts.append(self._no_https_redirect(url, port, ctx))

        return drafts

    def _collect_probes(self, ctx: ScanContext) -> List[Dict[str, Any]]:
        """Gather HTTP probes from all engines."""
        probes: List[Dict[str, Any]] = []

        # From HTTP engine
        http_data = ctx.get_engine_data("http")
        probes.extend(http_data.get("probes", []))

        # From Shodan (extract HTTP data from service entries)
        shodan_data = ctx.get_engine_data("shodan")
        for svc in shodan_data.get("services", []):
            http_info = svc.get("http")
            if not http_info or not isinstance(http_info, dict):
                continue

            # Build a probe-like dict from Shodan's HTTP data
            headers = {}
            raw_headers = http_info.get("headers") or ""
            if isinstance(raw_headers, str):
                for line in raw_headers.split("\r\n"):
                    if ": " in line:
                        key, val = line.split(": ", 1)
                        headers[key] = val

            port = svc.get("port", 80)
            scheme = "https" if svc.get("ssl") else "http"

            probes.append({
                "url": f"{scheme}://{ctx.asset_value}:{port}",
                "port": port,
                "scheme": scheme,
                "status_code": http_info.get("status"),
                "headers": headers,
                "title": http_info.get("title"),
                "server": http_info.get("server"),
                "cookies": [],
                "_source": "shodan",
            })

        return probes

    # -------------------------------------------------------------------
    # Security header checks
    # -------------------------------------------------------------------

    def _check_security_headers(
        self,
        headers: Dict[str, str],
        url: str,
        port: int,
        ctx: ScanContext,
    ) -> List[FindingDraft]:
        """Check for missing security headers on HTTPS responses."""
        drafts: List[FindingDraft] = []

        # Normalize header keys to lowercase for comparison
        headers_lower = {k.lower(): v for k, v in headers.items()}

        present = []
        missing = []

        for header_name, config in SECURITY_HEADERS.items():
            header_lower = header_name.lower()

            if header_lower in headers_lower:
                present.append(header_name)
                continue

            missing.append(header_name)

            template_id = f"header-missing-{header_name.lower().replace('-', '_')}"

            drafts.append(FindingDraft(
                template_id=template_id,
                title=f"Missing {header_name} header on {ctx.asset_value}:{port}",
                severity=config["severity"],
                category="headers",
                description=config["description"],
                remediation=config.get("remediation"),
                finding_type="missing_security_header",
                cwe=config.get("cwe"),
                tags=["headers", "security", header_name.lower()],
                engine="http",
                details={
                    "header": header_name,
                    "url": url,
                    "port": port,
                    "present_headers": present[:20],
                },
                dedupe_fields={
                    "port": port,
                    "header": header_name,
                },
            ))

        return drafts

    def _check_server_header(
        self,
        headers: Dict[str, str],
        url: str,
        port: int,
    ) -> Optional[FindingDraft]:
        """Check if Server header exposes version information."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        server = headers_lower.get("server", "")

        if not server:
            return None

        # Check if it contains version numbers
        has_version = bool(re.search(r"\d+\.\d+", server))

        if not has_version:
            return None

        return FindingDraft(
            template_id="header-server-version-leak",
            title=f"Server header exposes version: {server}",
            severity="high",
            category="headers",
            description=(
                f"The Server header reveals software and version: '{server}'. "
                "This information helps attackers identify known vulnerabilities "
                "for the specific software version running on the server."
            ),
            remediation=(
                "Remove or minimize the Server header. "
                "For nginx: server_tokens off; "
                "For Apache: ServerTokens Prod and ServerSignature Off"
            ),
            finding_type="server_info_leak",
            cwe="CWE-200",
            tags=["headers", "information-disclosure", "server"],
            engine="http",
            details={
                "server_header": server,
                "url": url,
                "port": port,
            },
            dedupe_fields={
                "port": port,
                "check": "server_version",
            },
        )

    def _check_powered_by(
        self,
        headers: Dict[str, str],
        url: str,
        port: int,
    ) -> Optional[FindingDraft]:
        """Check if X-Powered-By header leaks technology info."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        powered_by = headers_lower.get("x-powered-by", "")

        if not powered_by:
            return None

        return FindingDraft(
            template_id="header-powered-by-leak",
            title=f"X-Powered-By header exposes technology: {powered_by}",
            severity="low",
            category="headers",
            description=(
                f"The X-Powered-By header reveals: '{powered_by}'. "
                "This gives attackers information about the technology stack "
                "which can be used to find version-specific vulnerabilities."
            ),
            remediation=(
                "Remove the X-Powered-By header from responses. "
                "In PHP: add 'expose_php = Off' to php.ini. "
                "In Express.js: app.disable('x-powered-by'). "
                "Or remove it at the reverse proxy level."
            ),
            finding_type="tech_info_leak",
            cwe="CWE-200",
            tags=["headers", "information-disclosure"],
            engine="http",
            details={
                "powered_by": powered_by,
                "url": url,
                "port": port,
            },
            dedupe_fields={
                "port": port,
                "check": "powered_by",
            },
        )

    # -------------------------------------------------------------------
    # Cookie checks
    # -------------------------------------------------------------------

    def _check_cookies(
        self,
        cookies: List[Dict[str, Any]],
        url: str,
        port: int,
    ) -> List[FindingDraft]:
        """Check cookie security flags."""
        drafts: List[FindingDraft] = []

        for cookie in cookies:
            name = cookie.get("name", "unknown")

            if not cookie.get("secure"):
                drafts.append(FindingDraft(
                    template_id="cookie-missing-secure",
                    title=f"Cookie '{name}' missing Secure flag",
                    severity="medium",
                    category="headers",
                    description=(
                        f"The cookie '{name}' does not have the Secure flag set. "
                        "Without it, the cookie can be sent over unencrypted HTTP "
                        "connections, exposing it to network sniffing attacks."
                    ),
                    remediation=f"Set the Secure flag on the '{name}' cookie.",
                    finding_type="insecure_cookie",
                    cwe="CWE-614",
                    tags=["cookie", "secure"],
                    engine="http",
                    details={"cookie_name": name, "url": url, "port": port, "flags": cookie},
                    dedupe_fields={"port": port, "cookie": name, "check": "secure"},
                ))

            if not cookie.get("httponly"):
                drafts.append(FindingDraft(
                    template_id="cookie-missing-httponly",
                    title=f"Cookie '{name}' missing HttpOnly flag",
                    severity="medium",
                    category="headers",
                    description=(
                        f"The cookie '{name}' does not have the HttpOnly flag set. "
                        "Without it, the cookie can be read by client-side JavaScript, "
                        "making it vulnerable to theft via XSS attacks."
                    ),
                    remediation=f"Set the HttpOnly flag on the '{name}' cookie.",
                    finding_type="insecure_cookie",
                    cwe="CWE-1004",
                    tags=["cookie", "httponly"],
                    engine="http",
                    details={"cookie_name": name, "url": url, "port": port, "flags": cookie},
                    dedupe_fields={"port": port, "cookie": name, "check": "httponly"},
                ))

            if not cookie.get("samesite"):
                drafts.append(FindingDraft(
                    template_id="cookie-missing-samesite",
                    title=f"Cookie '{name}' missing SameSite attribute",
                    severity="medium",
                    category="headers",
                    description=(
                        f"The cookie '{name}' does not have a SameSite attribute. "
                        "Without SameSite, the cookie is sent with cross-site requests, "
                        "which can enable CSRF attacks."
                    ),
                    remediation=(
                        f"Set SameSite=Lax or SameSite=Strict on the '{name}' cookie. "
                        "Use Lax for most cases; Strict if the cookie is security-sensitive."
                    ),
                    finding_type="insecure_cookie",
                    cwe="CWE-1275",
                    tags=["cookie", "samesite"],
                    engine="http",
                    details={"cookie_name": name, "url": url, "port": port, "flags": cookie},
                    dedupe_fields={"port": port, "cookie": name, "check": "samesite"},
                ))

        return drafts

    # -------------------------------------------------------------------
    # HTTPS redirect check
    # -------------------------------------------------------------------

    def _no_https_redirect(
        self, url: str, port: int, ctx: ScanContext
    ) -> FindingDraft:
        """Finding for HTTP not redirecting to HTTPS."""
        return FindingDraft(
            template_id="http-no-https-redirect",
            title=f"HTTP does not redirect to HTTPS on {ctx.asset_value}",
            severity="high",
            category="headers",
            description=(
                f"Accessing {ctx.asset_value} over HTTP (port {port}) does not "
                "redirect to HTTPS. Users who type the URL without 'https://' "
                "will use an unencrypted connection, exposing their data to "
                "network interception."
            ),
            remediation=(
                "Configure your web server to redirect all HTTP requests to HTTPS. "
                "For nginx: return 301 https://$host$request_uri; "
                "For Apache: RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]"
            ),
            finding_type="no_https_redirect",
            cwe="CWE-319",
            tags=["http", "redirect", "https"],
            engine="http",
            details={"url": url, "port": port},
            dedupe_fields={"port": port, "check": "https_redirect"},
        )