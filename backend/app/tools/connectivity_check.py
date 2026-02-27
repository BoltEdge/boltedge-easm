# app/tools/connectivity_check.py
"""
Connectivity Check tool.

Performs TCP connection tests to a host:port. Measures latency,
grabs service banners, detects TLS, and optionally scans common ports.

Authenticated only — not exposed on public endpoints.
"""

from __future__ import annotations

import logging
import socket
import ssl
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

TIMEOUT = 6

# Common ports to probe when no port is specified
COMMON_PORTS = [
    (22, "SSH"),
    (80, "HTTP"),
    (443, "HTTPS"),
    (3389, "RDP"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (27017, "MongoDB"),
]

# Known TLS ports
TLS_PORTS = {443, 8443, 993, 995, 465, 636}

# Service signatures (first bytes of banner)
BANNER_SIGNATURES = [
    (b"SSH-", "SSH"),
    (b"220 ", "SMTP/FTP"),
    (b"* OK", "IMAP"),
    (b"+OK", "POP3"),
    (b"HTTP/", "HTTP"),
    (b"\x15\x03", "TLS Alert"),
    (b"\x16\x03", "TLS Handshake"),
]


def run_connectivity_check(host: str, port: Optional[int] = None, full: bool = True) -> Dict[str, Any]:
    """
    Run a connectivity check.

    Args:
        host: Target hostname or IP
        port: Target port (if None, scans common ports)
        full: Always True for this tool (auth only)

    Returns:
        Dict with connectivity results
    """
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "error": None,
    }

    # Resolve hostname to IP first
    resolved_ip = _resolve_host(host)
    if resolved_ip:
        result["resolvedIp"] = resolved_ip
    elif not _is_ip(host):
        result["error"] = f"Could not resolve hostname '{host}' to an IP address."
        return result

    if port is not None:
        # Single port check — detailed
        check = _check_port(host, port)
        result["result"] = check
        result["reachable"] = check["reachable"]
        result["issues"] = _analyse_single(check, host, port)
    else:
        # Multi-port scan
        checks = []
        open_ports = []
        closed_ports = []
        for p, service in COMMON_PORTS:
            check = _check_port(host, p, grab_banner=True)
            check["expectedService"] = service
            checks.append(check)
            if check["reachable"]:
                open_ports.append(check)
            else:
                closed_ports.append(check)

        result["ports"] = checks
        result["openPorts"] = len(open_ports)
        result["closedPorts"] = len(closed_ports)
        result["totalChecked"] = len(checks)
        result["issues"] = _analyse_multi(open_ports, closed_ports, host)

    return result


def _is_ip(host: str) -> bool:
    """Check if host looks like an IP address."""
    try:
        socket.inet_aton(host)
        return True
    except socket.error:
        pass
    # IPv6
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except (socket.error, OSError):
        pass
    return False


def _resolve_host(host: str) -> Optional[str]:
    """Resolve hostname to IP."""
    if _is_ip(host):
        return host
    try:
        results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if results:
            return results[0][4][0]
    except (socket.gaierror, socket.herror, OSError):
        pass
    return None


def _check_port(host: str, port: int, grab_banner: bool = True) -> Dict[str, Any]:
    """Check TCP connectivity to host:port."""
    check: Dict[str, Any] = {
        "port": port,
        "reachable": False,
        "latencyMs": None,
        "banner": None,
        "service": None,
        "tls": None,
        "error": None,
    }

    try:
        start = time.monotonic()
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        elapsed = (time.monotonic() - start) * 1000
        check["reachable"] = True
        check["latencyMs"] = round(elapsed, 1)

        # Grab banner
        if grab_banner:
            banner = _grab_banner(sock, port)
            if banner:
                check["banner"] = banner["text"]
                check["service"] = banner["service"]

        # TLS check on known TLS ports
        if port in TLS_PORTS or port == 443:
            tls_info = _check_tls(host, port)
            if tls_info:
                check["tls"] = tls_info

        sock.close()

    except socket.timeout:
        check["error"] = "Connection timed out"
    except ConnectionRefusedError:
        check["error"] = "Connection refused"
    except OSError as e:
        check["error"] = str(e)

    return check


def _grab_banner(sock: socket.socket, port: int) -> Optional[Dict[str, str]]:
    """Try to read initial bytes from the connection."""
    # Skip banner grab on known TLS ports (will get garbage)
    if port in TLS_PORTS:
        return None

    try:
        sock.settimeout(2)
        data = sock.recv(1024)
        if not data:
            return None

        text = data[:256].decode("utf-8", errors="replace").strip()
        service = None

        for sig, svc in BANNER_SIGNATURES:
            if data.startswith(sig):
                service = svc
                break

        return {"text": text[:200], "service": service}

    except (socket.timeout, OSError):
        return None


def _check_tls(host: str, port: int) -> Optional[Dict[str, Any]]:
    """Quick TLS handshake to get protocol version and cert CN."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return {
                    "version": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else None,
                }
    except Exception:
        return None


def _analyse_single(check: Dict[str, Any], host: str, port: int) -> List[Dict[str, str]]:
    """Analyse a single port check result."""
    issues = []

    if check["reachable"]:
        latency = check.get("latencyMs", 0)
        issues.append({
            "severity": "info",
            "title": f"Port {port} is reachable",
            "description": f"TCP connection to {host}:{port} succeeded in {latency}ms."
                + (f" Service detected: {check['service']}." if check.get("service") else ""),
        })

        if latency and latency > 500:
            issues.append({
                "severity": "medium",
                "title": f"High latency: {latency}ms",
                "description": "Connection succeeded but latency is high. This may indicate network issues or geographic distance.",
            })

        if check.get("tls"):
            tls = check["tls"]
            version = tls.get("version", "")
            if version in ("TLSv1", "TLSv1.1"):
                issues.append({
                    "severity": "high",
                    "title": f"Deprecated TLS version: {version}",
                    "description": "This port uses a deprecated TLS version. Upgrade to TLS 1.2 or 1.3.",
                })
            else:
                issues.append({
                    "severity": "info",
                    "title": f"TLS: {version}",
                    "description": f"Cipher: {tls.get('cipher', 'unknown')}",
                })

        # Security-sensitive ports
        sensitive = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}
        if port in sensitive:
            issues.append({
                "severity": "medium",
                "title": f"{sensitive[port]} port ({port}) is publicly reachable",
                "description": f"This port is typically sensitive and should not be exposed to the internet. Consider restricting access via firewall rules.",
            })

    else:
        error_detail = check.get("error", "Unknown error")
        if "refused" in error_detail.lower():
            issues.append({
                "severity": "info",
                "title": f"Port {port} — connection refused",
                "description": f"The host actively refused the connection. The port is closed or filtered.",
            })
        elif "timed out" in error_detail.lower():
            issues.append({
                "severity": "low",
                "title": f"Port {port} — connection timed out",
                "description": f"No response within {TIMEOUT}s. The port may be filtered by a firewall (no RST/ACK).",
            })
        else:
            issues.append({
                "severity": "low",
                "title": f"Port {port} — not reachable",
                "description": error_detail,
            })

    return issues


def _analyse_multi(open_ports: list, closed_ports: list, host: str) -> List[Dict[str, str]]:
    """Analyse multi-port scan results."""
    issues = []

    if open_ports:
        port_list = ", ".join(f"{p['port']}" + (f" ({p.get('expectedService', '')})" if p.get("expectedService") else "") for p in open_ports)
        issues.append({
            "severity": "info",
            "title": f"{len(open_ports)} open port(s) found",
            "description": f"Open: {port_list}",
        })

        # Flag sensitive open ports
        sensitive = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}
        for p in open_ports:
            if p["port"] in sensitive:
                issues.append({
                    "severity": "medium",
                    "title": f"{sensitive[p['port']]} ({p['port']}) is publicly reachable",
                    "description": "Sensitive service exposed to the internet. Restrict with firewall rules.",
                })
    else:
        issues.append({
            "severity": "info",
            "title": "No open ports found",
            "description": f"None of the {len(closed_ports)} common ports checked are reachable on {host}.",
        })

    return issues