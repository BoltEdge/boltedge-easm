# app/tools/routes.py
"""
Quick-check tool API routes.

Public endpoints return trimmed results (no deep details).
Authenticated endpoints return full results.

Tools:
    - Certificate Lookup    (domain input)
    - Certificate Hash      (SHA-256 hash input)
    - DNS Lookup            (domain input)
    - Reverse DNS Lookup    (IP input)
    - Header Check          (domain input)
    - WHOIS Lookup          (domain input)
    - Connectivity Check    (host/port input)
    - Email Security        (domain input)
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from flask import Blueprint, request, jsonify

from app.auth.decorators import require_auth

logger = logging.getLogger(__name__)

tools_bp = Blueprint("tools", __name__, url_prefix="/tools")

DOMAIN_RE = re.compile(r"^(?:\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")


# ═══════════════════════════════════════════════════════════════
# SSRF PROTECTION — Private/Reserved IP Blocklist
# ═══════════════════════════════════════════════════════════════

# Networks that should never be reached by outbound tool requests
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),         # "This" network
    ipaddress.ip_network("10.0.0.0/8"),         # Private (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),      # Private (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),     # Private (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("fc00::/7"),           # Unique local
    ipaddress.ip_network("fe80::/10"),          # Link-local
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped (check the mapped addr separately)
]


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address falls within blocked/private ranges."""
    try:
        addr = ipaddress.ip_address(ip_str)
        for network in BLOCKED_NETWORKS:
            if addr in network:
                return True
        return False
    except ValueError:
        return False


def _resolve_and_check_ssrf(host: str) -> tuple:
    """
    Resolve a hostname and verify the IP is not private/reserved.
    Returns (resolved_ip, error_response). If safe, error is None.
    For direct IPs, checks without resolution.
    """
    ip_str = host

    # If it's a hostname, resolve it first
    if not IP_RE.match(host) and not (IPV6_RE.match(host) and ":" in host):
        try:
            results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if not results:
                return None, (jsonify(error=f"Could not resolve hostname '{host}'."), 400)
            ip_str = results[0][4][0]
        except (socket.gaierror, socket.herror, OSError):
            return None, (jsonify(error=f"Could not resolve hostname '{host}'."), 400)

    if _is_private_ip(ip_str):
        logger.warning(f"SSRF blocked: {host} resolved to private IP {ip_str}")
        return None, (jsonify(error="Target resolves to a private or reserved IP address. Requests to internal networks are not allowed."), 403)

    return ip_str, None


def _normalize_domain(d: str) -> str:
    d = (d or "").strip().lower()
    if d.startswith("http://") or d.startswith("https://"):
        d = d.split("://", 1)[1]
    d = d.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0]
    d = d.strip().strip(".")
    return d


def _validate_domain(raw: str) -> tuple:
    """Returns (domain, error_response). If valid, error is None."""
    domain = _normalize_domain(raw)
    if not domain:
        return None, (jsonify(error="Domain is required."), 400)
    if len(domain) > 253 or not DOMAIN_RE.match(domain):
        return None, (jsonify(error="Invalid domain format."), 400)
    return domain, None


def _validate_ip(raw: str) -> tuple:
    """Returns (ip, error_response). If valid, error is None."""
    ip = (raw or "").strip()
    if not ip:
        return None, (jsonify(error="IP address is required."), 400)
    if not IP_RE.match(ip) and not IPV6_RE.match(ip):
        return None, (jsonify(error="Invalid IP address format."), 400)
    if IP_RE.match(ip):
        octets = ip.split(".")
        if any(int(o) > 255 for o in octets):
            return None, (jsonify(error="Invalid IP address: octets must be 0-255."), 400)
    return ip, None


def _validate_hash(raw: str) -> tuple:
    """Returns (hash, error_response). If valid, error is None."""
    h = (raw or "").strip()
    if not h:
        return None, (jsonify(error="Certificate hash is required."), 400)
    clean = h.replace(":", "").replace(" ", "").lower()
    if len(clean) != 64 or not all(c in "0123456789abcdef" for c in clean):
        return None, (jsonify(error="Invalid SHA-256 hash. Must be 64 hex characters."), 400)
    return clean, None


ASN_RE = re.compile(r"^(?:AS|as)?(\d{1,10})$")

def _validate_whois_query(body: dict) -> tuple:
    """
    Validate WHOIS input — accepts domain, IP, or ASN.
    Accepts body keys: "query", "domain", "ip", or "asn".
    Returns (query_string, error_response).
    """
    raw = (body.get("query") or body.get("domain") or body.get("ip") or body.get("asn") or "").strip()
    if not raw:
        return None, (jsonify(error="Query is required (domain, IP, or ASN)."), 400)
    if len(raw) > 253:
        return None, (jsonify(error="Query too long."), 400)

    # IP?
    if IP_RE.match(raw):
        octets = raw.split(".")
        if any(int(o) > 255 for o in octets):
            return None, (jsonify(error="Invalid IP address: octets must be 0-255."), 400)
        return raw, None

    # IPv6?
    if IPV6_RE.match(raw) and ":" in raw:
        return raw, None

    # ASN?
    if ASN_RE.match(raw):
        return raw, None

    # Domain? — normalize
    domain = _normalize_domain(raw)
    if domain and DOMAIN_RE.match(domain):
        return domain, None

    return None, (jsonify(error="Invalid input. Provide a domain, IP address, or ASN (e.g. AS13335)."), 400)


def _validate_connectivity_input(body: dict) -> tuple:
    """
    Validate connectivity check input.
    Accepts:
      - {"host": "example.com", "port": 443}
      - {"host": "8.8.8.8:443"}
      - {"host": "example.com"} (no port → scan common ports)
    Returns (host, port_or_None, error_response).
    """
    raw_host = (body.get("host") or "").strip()
    raw_port = body.get("port")

    if not raw_host:
        return None, None, (jsonify(error="Host is required."), 400)

    # Parse host:port format
    host = raw_host
    port = None

    if raw_port is not None:
        try:
            port = int(raw_port)
        except (ValueError, TypeError):
            return None, None, (jsonify(error="Port must be a number."), 400)
    elif ":" in raw_host and not raw_host.startswith("["):
        # host:port format (not IPv6)
        parts = raw_host.rsplit(":", 1)
        if parts[1].isdigit():
            host = parts[0]
            port = int(parts[1])

    # Normalize host
    host = host.strip().lower()
    if host.startswith("http://") or host.startswith("https://"):
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].strip()

    if not host:
        return None, None, (jsonify(error="Host is required."), 400)
    if len(host) > 253:
        return None, None, (jsonify(error="Host too long."), 400)

    # Validate port range
    if port is not None:
        if port < 1 or port > 65535:
            return None, None, (jsonify(error="Port must be between 1 and 65535."), 400)

    return host, port, None


# ═══════════════════════════════════════════════════════════════
# CERTIFICATE LOOKUP (by domain)
# ═══════════════════════════════════════════════════════════════

@tools_bp.post("/cert-lookup")
@require_auth
def cert_lookup_auth():
    """Authenticated certificate lookup — full results."""
    body = request.get_json(silent=True) or {}
    domain, err = _validate_domain(body.get("domain", ""))
    if err:
        return err
    # SSRF protection
    _, ssrf_err = _resolve_and_check_ssrf(domain)
    if ssrf_err:
        return ssrf_err
    from app.tools.cert_lookup import run_cert_lookup
    return jsonify(run_cert_lookup(domain, full=True)), 200


@tools_bp.post("/public/cert-lookup")
def cert_lookup_public():
    """Public certificate lookup — trimmed results."""
    body = request.get_json(silent=True) or {}
    domain, err = _validate_domain(body.get("domain", ""))
    if err:
        return err
    # SSRF protection
    _, ssrf_err = _resolve_and_check_ssrf(domain)
    if ssrf_err:
        return ssrf_err
    from app.tools.cert_lookup import run_cert_lookup
    return jsonify(run_cert_lookup(domain, full=False)), 200


# ═══════════════════════════════════════════════════════════════
# CERTIFICATE HASH LOOKUP (by SHA-256 fingerprint)
# ═══════════════════════════════════════════════════════════════

@tools_bp.post("/cert-hash")
@require_auth
def cert_hash_auth():
    """Authenticated cert hash lookup — full results."""
    body = request.get_json(silent=True) or {}
    cert_hash, err = _validate_hash(body.get("hash", ""))
    if err:
        return err
    from app.tools.cert_lookup import run_cert_hash_lookup
    return jsonify(run_cert_hash_lookup(cert_hash, full=True)), 200


@tools_bp.post("/public/cert-hash")
def cert_hash_public():
    """Public cert hash lookup — trimmed results (max 10)."""
    body = request.get_json(silent=True) or {}
    cert_hash, err = _validate_hash(body.get("hash", ""))
    if err:
        return err
    from app.tools.cert_lookup import run_cert_hash_lookup
    return jsonify(run_cert_hash_lookup(cert_hash, full=False)), 200


# ═══════════════════════════════════════════════════════════════
# DNS LOOKUP
# ═══════════════════════════════════════════════════════════════

@tools_bp.post("/dns-lookup")
@require_auth
def dns_lookup_auth():
    """Authenticated DNS lookup — full results."""
    body = request.get_json(silent=True) or {}
    domain, err = _validate_domain(body.get("domain", ""))
    if err:
        return err
    from app.tools.dns_lookup import run_dns_lookup
    return jsonify(run_dns_lookup(domain, full=True)), 200


@tools_bp.post("/public/dns-lookup")
def dns_lookup_public():
    """Public DNS lookup — trimmed results."""
    body = request.get_json(silent=True) or {}
    domain, err = _validate_domain(body.get("domain", ""))
    if err:
        return err
    from app.tools.dns_lookup import run_dns_lookup
    return jsonify(run_dns_lookup(domain, full=False)), 200


# ═══════════════════════════════════════════════════════════════
# REVERSE DNS LOOKUP (by IP)
# ═══════════════════════════════════════════════════════════════

@tools_bp.post("/reverse-dns")
@require_auth
def reverse_dns_auth():
    """Authenticated reverse DNS — full results with forward confirmation."""
    body = request.get_json(silent=True) or {}
    ip, err = _validate_ip(body.get("ip", ""))
    if err:
        return err
    # SSRF protection: block reverse DNS on private IPs
    if _is_private_ip(ip):
        return jsonify(error="Reverse DNS lookups on private or reserved IP addresses are not allowed."), 403
    from app.tools.reverse_dns import run_reverse_dns
    return jsonify(run_reverse_dns(ip, full=True)), 200


@tools_bp.post("/public/reverse-dns")
def reverse_dns_public():
    """Public reverse DNS — basic PTR results."""
    body = request.get_json(silent=True) or {}
    ip, err = _validate_ip(body.get("ip", ""))
    if err:
        return err
    if _is_private_ip(ip):
        return jsonify(error="Reverse DNS lookups on private or reserved IP addresses are not allowed."), 403
    from app.tools.reverse_dns import run_reverse_dns
    return jsonify(run_reverse_dns(ip, full=False)), 200


# ═══════════════════════════════════════════════════════════════
# HEADER CHECK
# ═══════════════════════════════════════════════════════════════

@tools_bp.post("/header-check")
@require_auth
def header_check_auth():
    """Authenticated header check — full results."""
    body = request.get_json(silent=True) or {}
    domain, err = _validate_domain(body.get("domain", ""))
    if err:
        return err
    # SSRF protection: ensure domain doesn't resolve to private IP
    _, ssrf_err = _resolve_and_check_ssrf(domain)
    if ssrf_err:
        return ssrf_err
    from app.tools.header_check import run_header_check
    return jsonify(run_header_check(domain, full=True)), 200


@tools_bp.post("/public/header-check")
def header_check_public():
    """Public header check — trimmed results."""
    body = request.get_json(silent=True) or {}
    domain, err = _validate_domain(body.get("domain", ""))
    if err:
        return err
    # SSRF protection
    _, ssrf_err = _resolve_and_check_ssrf(domain)
    if ssrf_err:
        return ssrf_err
    from app.tools.header_check import run_header_check
    return jsonify(run_header_check(domain, full=False)), 200


# ═══════════════════════════════════════════════════════════════
# WHOIS LOOKUP
# ═══════════════════════════════════════════════════════════════

@tools_bp.post("/whois")
@require_auth
def whois_auth():
    """Authenticated WHOIS — accepts domain, IP, or ASN. Full results."""
    body = request.get_json(silent=True) or {}
    query, err = _validate_whois_query(body)
    if err:
        return err
    from app.tools.whois_lookup import run_whois_lookup
    return jsonify(run_whois_lookup(query, full=True)), 200


@tools_bp.post("/public/whois")
def whois_public():
    """Public WHOIS — accepts domain, IP, or ASN. Parsed results only."""
    body = request.get_json(silent=True) or {}
    query, err = _validate_whois_query(body)
    if err:
        return err
    from app.tools.whois_lookup import run_whois_lookup
    return jsonify(run_whois_lookup(query, full=False)), 200


# ═══════════════════════════════════════════════════════════════
# CONNECTIVITY CHECK (authenticated only — no public endpoint)
# ═══════════════════════════════════════════════════════════════

@tools_bp.post("/connectivity-check")
@require_auth
def connectivity_check_auth():
    """Authenticated connectivity check — TCP port reachability test."""
    body = request.get_json(silent=True) or {}
    host, port, err = _validate_connectivity_input(body)
    if err:
        return err
    # SSRF protection: block private/reserved IPs (checks after DNS resolution)
    _, ssrf_err = _resolve_and_check_ssrf(host)
    if ssrf_err:
        return ssrf_err
    from app.tools.connectivity_check import run_connectivity_check
    return jsonify(run_connectivity_check(host, port)), 200


# ═══════════════════════════════════════════════════════════════
# EMAIL SECURITY CHECK (SPF / DKIM / DMARC)
# ═══════════════════════════════════════════════════════════════

@tools_bp.post("/email-security")
@require_auth
def email_security_auth():
    """Authenticated email security check — full results."""
    body = request.get_json(silent=True) or {}
    domain, err = _validate_domain(body.get("domain", ""))
    if err:
        return err
    from app.tools.email_security import run_email_security_check
    return jsonify(run_email_security_check(domain, full=True)), 200


@tools_bp.post("/public/email-security")
def email_security_public():
    """Public email security check — summary only."""
    body = request.get_json(silent=True) or {}
    domain, err = _validate_domain(body.get("domain", ""))
    if err:
        return err
    from app.tools.email_security import run_email_security_check
    return jsonify(run_email_security_check(domain, full=False)), 200

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# SENSITIVE PATH SCANNER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@tools_bp.post("/sensitive-paths")
@require_auth
def sensitive_paths_auth():
    """Authenticated sensitive path scan - full results."""
    body = request.get_json(silent=True) or {}
    domain, err = _validate_domain(body.get("domain", ""))
    if err:
        return err
    _, ssrf_err = _resolve_and_check_ssrf(domain)
    if ssrf_err:
        return ssrf_err
    from app.tools.sensitive_paths import run_sensitive_path_scan
    return jsonify(run_sensitive_path_scan(domain, full=True)), 200


@tools_bp.post("/public/sensitive-paths")
def sensitive_paths_public():
    """Public sensitive path scan - summary only."""
    body = request.get_json(silent=True) or {}
    domain, err = _validate_domain(body.get("domain", ""))
    if err:
        return err
    _, ssrf_err = _resolve_and_check_ssrf(domain)
    if ssrf_err:
        return ssrf_err
    from app.tools.sensitive_paths import run_sensitive_path_scan
    return jsonify(run_sensitive_path_scan(domain, full=False)), 200


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# GITHUB LEAK SCANNER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@tools_bp.post("/github-leaks")
@require_auth
def github_leaks_auth():
    """Authenticated GitHub leak scan - full results."""
    body = request.get_json(silent=True) or {}
    domain, err = _validate_domain(body.get("domain", ""))
    if err:
        return err
    from app.tools.github_leaks import run_github_leak_scan
    return jsonify(run_github_leak_scan(domain, full=True)), 200


@tools_bp.post("/public/github-leaks")
def github_leaks_public():
    """Public GitHub leak scan - summary only."""
    body = request.get_json(silent=True) or {}
    domain, err = _validate_domain(body.get("domain", ""))
    if err:
        return err
    from app.tools.github_leaks import run_github_leak_scan
    return jsonify(run_github_leak_scan(domain, full=False)), 200
