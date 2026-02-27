# app/tools/reverse_dns.py
"""
Reverse DNS Lookup tool.

Takes an IP address and performs reverse DNS (PTR) lookups to find
associated hostnames. Also resolves those hostnames forward to verify
the mapping is bidirectional (forward-confirmed reverse DNS).
"""

from __future__ import annotations

import logging
import socket
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

TIMEOUT = 5


def run_reverse_dns(ip: str, full: bool = False) -> Dict[str, Any]:
    """
    Run a reverse DNS lookup for the given IP address.

    Args:
        ip:   Target IP address (e.g., "8.8.8.8")
        full: If True, include forward confirmation and extended details

    Returns:
        Dict with reverse DNS results
    """
    result: Dict[str, Any] = {
        "ip": ip,
        "hostnames": [],
        "ptrRecords": [],
        "issues": [],
        "error": None,
    }

    # Step 1: PTR lookup via dnspython (more reliable than socket)
    ptr_records = _query_ptr(ip)

    if ptr_records:
        result["ptrRecords"] = ptr_records
        result["hostnames"] = [r["hostname"] for r in ptr_records]
    else:
        # Fallback: socket reverse lookup
        try:
            hostname, aliases, _ = socket.gethostbyaddr(ip)
            all_names = [hostname] + list(aliases)
            result["hostnames"] = all_names
            result["ptrRecords"] = [{"hostname": h, "ttl": None} for h in all_names]
        except (socket.herror, socket.gaierror):
            result["issues"].append({
                "severity": "info",
                "title": "No PTR record found",
                "description": f"No reverse DNS (PTR) record exists for {ip}. This IP does not have a hostname associated with it.",
            })
            return result

    # Step 2: Forward confirmation (full mode)
    if full and result["hostnames"]:
        forward_results = []
        for hostname in result["hostnames"]:
            confirmed = _forward_confirm(hostname, ip)
            forward_results.append({
                "hostname": hostname,
                "forwardIps": confirmed["ips"],
                "confirmed": confirmed["match"],
            })
        result["forwardConfirmation"] = forward_results

        # Check for mismatches
        unconfirmed = [fr for fr in forward_results if not fr["confirmed"]]
        if unconfirmed:
            for uc in unconfirmed:
                result["issues"].append({
                    "severity": "medium",
                    "title": f"Forward-reverse mismatch: {uc['hostname']}",
                    "description": (
                        f"The PTR record for {ip} points to {uc['hostname']}, but "
                        f"resolving {uc['hostname']} forward returns {uc['forwardIps'] or 'no IPs'}. "
                        f"This mismatch may cause issues with email delivery and certain security checks."
                    ),
                })

    # Step 3: Additional analysis
    if result["hostnames"]:
        hostnames = result["hostnames"]

        # Check for generic/ISP hostnames
        generic_patterns = [
            "static", "dynamic", "dhcp", "pool", "residential",
            "cable", "dsl", "broadband", "dial",
        ]
        for hn in hostnames:
            hn_lower = hn.lower()
            if any(p in hn_lower for p in generic_patterns):
                result["issues"].append({
                    "severity": "low",
                    "title": f"Generic ISP hostname: {hn}",
                    "description": "This appears to be a generic ISP-assigned hostname rather than a custom PTR record.",
                })
                break

        # Check for meaningful hostnames that reveal infrastructure
        infra_patterns = {
            "mail": "Mail server",
            "smtp": "SMTP server",
            "mx": "Mail exchange",
            "ns": "Nameserver",
            "dns": "DNS server",
            "vpn": "VPN endpoint",
            "fw": "Firewall",
            "proxy": "Proxy server",
            "cdn": "CDN node",
            "lb": "Load balancer",
        }
        if full:
            for hn in hostnames:
                parts = hn.lower().replace(".", " ").replace("-", " ").split()
                for pattern, label in infra_patterns.items():
                    if pattern in parts:
                        result.setdefault("infrastructure", [])
                        result["infrastructure"].append({
                            "hostname": hn,
                            "type": label,
                            "indicator": pattern,
                        })
                        break

    if not result["issues"]:
        result["issues"].append({
            "severity": "info",
            "title": "Reverse DNS configured",
            "description": f"PTR record found for {ip}: {', '.join(result['hostnames'][:3])}",
        })

    return result


def _query_ptr(ip: str) -> List[Dict[str, Any]]:
    """Query PTR records using dnspython."""
    try:
        import dns.resolver
        import dns.reversename

        rev_name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = TIMEOUT
        resolver.lifetime = TIMEOUT * 2

        answers = resolver.resolve(rev_name, "PTR")
        records = []
        for rdata in answers:
            hostname = str(rdata).rstrip(".")
            records.append({
                "hostname": hostname,
                "ttl": answers.ttl,
            })
        return records

    except ImportError:
        logger.debug("dnspython not available for PTR query")
        return []
    except Exception:
        return []


def _forward_confirm(hostname: str, original_ip: str) -> Dict[str, Any]:
    """Resolve hostname forward and check if it maps back to the original IP."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = list(dict.fromkeys(addr[4][0] for addr in results))
        return {
            "ips": ips,
            "match": original_ip in ips,
        }
    except (socket.gaierror, socket.herror, OSError):
        return {"ips": [], "match": False}