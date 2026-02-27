# app/tools/header_check.py
"""
HTTP Header Check tool.

Connects to the target domain over HTTPS (and HTTP), retrieves
response headers, and analyses them for security best practices.

Checks for: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy, CORS, server disclosure,
cookie security, and more.
"""

from __future__ import annotations

import logging
import ssl
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

logger = logging.getLogger(__name__)

TIMEOUT = 8

# Security headers to check (name, severity if missing, description)
SECURITY_HEADERS = [
    {
        "header": "Strict-Transport-Security",
        "alias": "HSTS",
        "severity": "high",
        "missingTitle": "Missing HSTS header",
        "missingDesc": "The Strict-Transport-Security header is not set. This allows downgrade attacks from HTTPS to HTTP.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    {
        "header": "Content-Security-Policy",
        "alias": "CSP",
        "severity": "medium",
        "missingTitle": "Missing Content-Security-Policy header",
        "missingDesc": "No CSP header found. CSP prevents XSS attacks by restricting which resources can be loaded.",
        "recommendation": "Add a Content-Security-Policy header that restricts script-src, style-src, and default-src.",
    },
    {
        "header": "X-Frame-Options",
        "alias": "XFO",
        "severity": "medium",
        "missingTitle": "Missing X-Frame-Options header",
        "missingDesc": "No X-Frame-Options header found. This allows the site to be embedded in iframes, enabling clickjacking attacks.",
        "recommendation": "Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
    },
    {
        "header": "X-Content-Type-Options",
        "alias": "XCTO",
        "severity": "medium",
        "missingTitle": "Missing X-Content-Type-Options header",
        "missingDesc": "No X-Content-Type-Options header found. Browsers may MIME-sniff content types, leading to XSS via file uploads.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    {
        "header": "Referrer-Policy",
        "alias": "RP",
        "severity": "low",
        "missingTitle": "Missing Referrer-Policy header",
        "missingDesc": "No Referrer-Policy header found. The full URL (including query parameters) may be leaked to external sites.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "header": "Permissions-Policy",
        "alias": "PP",
        "severity": "low",
        "missingTitle": "Missing Permissions-Policy header",
        "missingDesc": "No Permissions-Policy header found. Browser features like camera, microphone, and geolocation are not restricted.",
        "recommendation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
]


def run_header_check(domain: str, full: bool = False) -> Dict[str, Any]:
    """
    Run an HTTP header check for the given domain.

    Args:
        domain: Target domain (e.g., "example.com")
        full:   If True, include all raw headers and detailed analysis

    Returns:
        Dict with header information and security analysis
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "https": None,
        "http": None,
        "issues": [],
        "grade": None,
        "error": None,
    }

    # Step 1: Check HTTPS
    https_data = _fetch_headers(f"https://{domain}", follow_redirects=True)
    if https_data:
        result["https"] = _format_probe_result(https_data, full)
    else:
        result["issues"].append({
            "severity": "high",
            "title": "HTTPS not available",
            "description": f"Could not connect to https://{domain}. The site may not support HTTPS.",
        })

    # Step 2: Check HTTP (does it redirect to HTTPS?)
    http_data = _fetch_headers(f"http://{domain}", follow_redirects=False)
    if http_data:
        result["http"] = _format_probe_result(http_data, full)

        # Check for HTTP → HTTPS redirect
        status = http_data.get("status")
        location = (http_data.get("headers") or {}).get("location", "")
        if status in (301, 302, 307, 308) and location.startswith("https://"):
            result["httpRedirectsToHttps"] = True
        else:
            result["httpRedirectsToHttps"] = False
            result["issues"].append({
                "severity": "medium",
                "title": "HTTP does not redirect to HTTPS",
                "description": "HTTP requests are not redirected to HTTPS. Users accessing the site via HTTP will use an unencrypted connection.",
            })

    # Step 3: Analyse security headers (from HTTPS response)
    headers = {}
    if https_data:
        headers = https_data.get("headers") or {}
    elif http_data:
        headers = http_data.get("headers") or {}

    if headers:
        header_issues = _analyse_security_headers(headers, full)
        result["issues"].extend(header_issues)

        # Check for server header disclosure
        server = headers.get("server", "")
        if server:
            # Check if version is disclosed
            import re
            if re.search(r"[\d.]+", server):
                result["issues"].append({
                    "severity": "low",
                    "title": f"Server version disclosed: {server}",
                    "description": f"The Server header reveals '{server}'. Version information helps attackers target known vulnerabilities.",
                })

        # Check X-Powered-By
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            result["issues"].append({
                "severity": "low",
                "title": f"Technology disclosed: X-Powered-By: {powered_by}",
                "description": "The X-Powered-By header reveals technology information. Remove it to reduce information leakage.",
            })

        # Full mode: cookie analysis
        if full:
            cookie_issues = _analyse_cookies(headers)
            result["issues"].extend(cookie_issues)

    # Calculate grade
    result["grade"] = _calculate_grade(result["issues"])

    # Summary counts
    result["headerSummary"] = _build_header_summary(headers)

    # No issues check
    if not result["issues"]:
        result["issues"].append({
            "severity": "info",
            "title": "No issues found",
            "description": "All checked security headers are properly configured.",
        })

    return result


def _fetch_headers(url: str, follow_redirects: bool = True) -> Optional[Dict[str, Any]]:
    """Fetch HTTP headers from a URL."""
    try:
        req = Request(url, method="GET", headers={
            "User-Agent": "Mozilla/5.0 (compatible; BoltEdge EASM Scanner)",
            "Accept": "text/html,application/xhtml+xml,*/*",
        })

        ssl_ctx = None
        if url.startswith("https://"):
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        if not follow_redirects:
            # Use a custom opener that doesn't follow redirects
            import urllib.request
            class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None  # Don't follow

            opener = urllib.request.build_opener(
                NoRedirectHandler,
                urllib.request.HTTPSHandler(context=ssl_ctx) if ssl_ctx else urllib.request.HTTPHandler,
            )

            try:
                response = opener.open(req, timeout=TIMEOUT)
                headers_dict = {k.lower(): v for k, v in response.headers.items()}
                return {
                    "url": url,
                    "status": response.status,
                    "headers": headers_dict,
                }
            except HTTPError as e:
                headers_dict = {k.lower(): v for k, v in e.headers.items()}
                return {
                    "url": url,
                    "status": e.code,
                    "headers": headers_dict,
                }
        else:
            response = urlopen(req, timeout=TIMEOUT, context=ssl_ctx)
            headers_dict = {k.lower(): v for k, v in response.headers.items()}
            return {
                "url": response.url,
                "status": response.status,
                "headers": headers_dict,
            }

    except HTTPError as e:
        headers_dict = {k.lower(): v for k, v in e.headers.items()}
        return {
            "url": url,
            "status": e.code,
            "headers": headers_dict,
        }
    except (URLError, Exception) as e:
        logger.debug(f"Header fetch failed for {url}: {e}")
        return None


def _format_probe_result(data: Dict[str, Any], full: bool) -> Dict[str, Any]:
    """Format probe result for API response."""
    result = {
        "url": data.get("url"),
        "statusCode": data.get("status"),
        "server": (data.get("headers") or {}).get("server"),
    }

    if full:
        result["headers"] = data.get("headers", {})

    return result


def _analyse_security_headers(headers: Dict[str, str], full: bool) -> List[Dict[str, str]]:
    """Check for missing or misconfigured security headers."""
    issues = []

    for check in SECURITY_HEADERS:
        header_name = check["header"].lower()
        value = headers.get(header_name)

        if not value:
            issue: Dict[str, str] = {
                "severity": check["severity"],
                "title": check["missingTitle"],
                "description": check["missingDesc"],
            }
            if full:
                issue["recommendation"] = check["recommendation"]
            issues.append(issue)
        else:
            # Check for weak configurations
            if header_name == "strict-transport-security":
                if "max-age=0" in value:
                    issues.append({
                        "severity": "high",
                        "title": "HSTS max-age is 0",
                        "description": "HSTS is effectively disabled with max-age=0. Set a value of at least 31536000 (1 year).",
                    })
                elif "max-age" in value:
                    import re
                    match = re.search(r"max-age=(\d+)", value)
                    if match:
                        max_age = int(match.group(1))
                        if max_age < 2592000:  # 30 days
                            issues.append({
                                "severity": "low",
                                "title": f"HSTS max-age is short ({max_age}s)",
                                "description": f"HSTS max-age is set to {max_age} seconds ({max_age // 86400} days). Consider at least 31536000 (1 year).",
                            })

            elif header_name == "content-security-policy":
                if "unsafe-inline" in value and "unsafe-eval" in value:
                    issues.append({
                        "severity": "medium",
                        "title": "CSP allows unsafe-inline and unsafe-eval",
                        "description": "The CSP allows both unsafe-inline and unsafe-eval, significantly weakening XSS protection.",
                    })

            elif header_name == "x-frame-options":
                val_upper = value.upper()
                if val_upper not in ("DENY", "SAMEORIGIN") and not val_upper.startswith("ALLOW-FROM"):
                    issues.append({
                        "severity": "low",
                        "title": f"Unusual X-Frame-Options value: {value}",
                        "description": "Expected DENY or SAMEORIGIN.",
                    })

    return issues


def _analyse_cookies(headers: Dict[str, str]) -> List[Dict[str, str]]:
    """Analyse Set-Cookie headers for security flags."""
    issues = []
    cookie_headers = []

    # Headers dict may have multiple set-cookie values joined
    raw = headers.get("set-cookie", "")
    if raw:
        # Split on common cookie boundaries
        cookie_headers = [c.strip() for c in raw.split(",") if "=" in c]

    for cookie in cookie_headers:
        name = cookie.split("=")[0].strip()
        lower = cookie.lower()

        if "secure" not in lower:
            issues.append({
                "severity": "medium",
                "title": f"Cookie '{name}' missing Secure flag",
                "description": f"The cookie '{name}' can be sent over unencrypted HTTP connections.",
            })

        if "httponly" not in lower:
            issues.append({
                "severity": "low",
                "title": f"Cookie '{name}' missing HttpOnly flag",
                "description": f"The cookie '{name}' is accessible to JavaScript, increasing XSS risk.",
            })

        if "samesite" not in lower:
            issues.append({
                "severity": "low",
                "title": f"Cookie '{name}' missing SameSite attribute",
                "description": f"The cookie '{name}' does not set SameSite, which may allow CSRF attacks.",
            })

    return issues


def _build_header_summary(headers: Dict[str, str]) -> Dict[str, Any]:
    """Build a summary of which security headers are present."""
    summary = {}
    for check in SECURITY_HEADERS:
        header_lower = check["header"].lower()
        present = header_lower in headers
        summary[check["alias"]] = {
            "present": present,
            "value": headers.get(header_lower, None),
        }
    return summary


def _calculate_grade(issues: List[Dict[str, str]]) -> str:
    """Calculate an A-F grade based on issues found."""
    severities = [i["severity"] for i in issues]
    if "critical" in severities:
        return "F"
    high_count = severities.count("high")
    medium_count = severities.count("medium")
    if high_count >= 3:
        return "D"
    if high_count >= 2:
        return "C"
    if high_count >= 1:
        return "C+"
    if medium_count >= 3:
        return "B-"
    if medium_count >= 1:
        return "B"
    return "A"