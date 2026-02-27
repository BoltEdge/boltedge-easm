# app/tools/dns_lookup.py
"""
DNS Lookup tool.

Queries all major DNS record types for a given domain and returns
structured results with security analysis.

Record types queried: A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV
Security checks: SPF, DMARC, DKIM, DNSSEC, dangling CNAMEs
"""

from __future__ import annotations

import logging
import socket
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

TIMEOUT = 5


def run_dns_lookup(domain: str, full: bool = False) -> Dict[str, Any]:
    """
    Run a DNS lookup for the given domain.

    Args:
        domain: Target domain (e.g., "example.com")
        full:   If True, include security analysis and WHOIS-like info

    Returns:
        Dict with DNS records and analysis
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "records": {},
        "resolvedIps": [],
        "issues": [],
        "grade": None,
        "error": None,
    }

    try:
        import dns.resolver
        import dns.rdatatype
    except ImportError:
        result["error"] = "dnspython library not installed."
        return result

    resolver = dns.resolver.Resolver()
    resolver.timeout = TIMEOUT
    resolver.lifetime = TIMEOUT * 2

    # Query each record type
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
    if full:
        record_types.append("SRV")

    for rtype in record_types:
        records = _query_records(resolver, domain, rtype)
        if records:
            result["records"][rtype] = records

    # Extract resolved IPs
    a_records = result["records"].get("A", [])
    aaaa_records = result["records"].get("AAAA", [])
    result["resolvedIps"] = [r["value"] for r in a_records] + [r["value"] for r in aaaa_records]

    # Security analysis
    issues = _analyse_dns_security(domain, result["records"], resolver, full)
    result["issues"] = issues
    result["grade"] = _calculate_grade(issues)

    # Full mode: extra lookups
    if full:
        # Check for DKIM (common selectors)
        dkim_results = _check_dkim(resolver, domain)
        if dkim_results:
            result["dkim"] = dkim_results

        # Check for DNSSEC
        result["dnssec"] = _check_dnssec(resolver, domain)

        # Nameserver details
        ns_records = result["records"].get("NS", [])
        if ns_records:
            ns_ips = {}
            for ns in ns_records:
                ns_name = ns["value"].rstrip(".")
                ips = _resolve_hostname(ns_name)
                if ips:
                    ns_ips[ns_name] = ips
            result["nameserverIps"] = ns_ips

    return result


def _query_records(resolver, domain: str, rtype: str) -> List[Dict[str, Any]]:
    """Query DNS records of a specific type."""
    try:
        import dns.resolver
        answers = resolver.resolve(domain, rtype)
        records = []

        for rdata in answers:
            record: Dict[str, Any] = {"value": str(rdata), "ttl": answers.ttl}

            if rtype == "MX":
                record["priority"] = rdata.preference
                record["value"] = str(rdata.exchange).rstrip(".")
            elif rtype == "SOA":
                record["value"] = str(rdata.mname).rstrip(".")
                record["rname"] = str(rdata.rname).rstrip(".")
                record["serial"] = rdata.serial
                record["refresh"] = rdata.refresh
                record["retry"] = rdata.retry
                record["expire"] = rdata.expire
                record["minimum"] = rdata.minimum
            elif rtype == "CAA":
                record["flags"] = rdata.flags
                record["tag"] = rdata.tag.decode() if isinstance(rdata.tag, bytes) else str(rdata.tag)
                record["value"] = rdata.value.decode() if isinstance(rdata.value, bytes) else str(rdata.value)
            elif rtype in ("NS", "CNAME"):
                record["value"] = str(rdata).rstrip(".")
            elif rtype == "SRV":
                record["priority"] = rdata.priority
                record["weight"] = rdata.weight
                record["port"] = rdata.port
                record["target"] = str(rdata.target).rstrip(".")

            records.append(record)

        return records

    except Exception:
        return []


def _analyse_dns_security(
    domain: str,
    records: Dict[str, List],
    resolver,
    full: bool,
) -> List[Dict[str, str]]:
    """Analyse DNS records for security issues."""
    issues = []
    txt_records = records.get("TXT", [])
    txt_values = [r["value"].strip('"') for r in txt_records]

    # SPF check
    spf_records = [v for v in txt_values if v.startswith("v=spf1")]
    if not spf_records:
        issues.append({
            "severity": "high",
            "title": "No SPF record found",
            "description": "No SPF (Sender Policy Framework) record found. This allows anyone to send email pretending to be from this domain.",
        })
    elif len(spf_records) > 1:
        issues.append({
            "severity": "medium",
            "title": "Multiple SPF records found",
            "description": "Multiple SPF records can cause email delivery issues and weaken email authentication.",
        })
    else:
        spf = spf_records[0]
        if "+all" in spf:
            issues.append({
                "severity": "high",
                "title": "SPF uses +all (permissive)",
                "description": "The SPF record ends with +all, which allows any server to send email for this domain. Use ~all or -all instead.",
            })
        elif "~all" in spf:
            issues.append({
                "severity": "low",
                "title": "SPF uses ~all (softfail)",
                "description": "The SPF record uses softfail (~all). Consider using -all (hardfail) for stricter enforcement.",
            })

    # DMARC check
    dmarc_records = _query_records(resolver, f"_dmarc.{domain}", "TXT")
    dmarc_values = [r["value"].strip('"') for r in dmarc_records if "v=DMARC1" in r.get("value", "")]

    if not dmarc_values:
        issues.append({
            "severity": "high",
            "title": "No DMARC record found",
            "description": "No DMARC record found at _dmarc." + domain + ". DMARC protects against email spoofing and phishing.",
        })
    else:
        dmarc = dmarc_values[0]
        if "p=none" in dmarc:
            issues.append({
                "severity": "medium",
                "title": "DMARC policy set to none",
                "description": "DMARC is configured but the policy is set to 'none' (monitor only). Consider upgrading to 'quarantine' or 'reject'.",
            })

    # CAA check
    caa_records = records.get("CAA", [])
    if not caa_records:
        issues.append({
            "severity": "low",
            "title": "No CAA records found",
            "description": "No CAA (Certificate Authority Authorization) records found. CAA records restrict which CAs can issue certificates for this domain.",
        })

    # Dangling CNAME check
    cname_records = records.get("CNAME", [])
    for cname in cname_records:
        target = cname.get("value", "")
        if target and not _resolve_hostname(target):
            issues.append({
                "severity": "high",
                "title": f"Dangling CNAME: {target}",
                "description": f"The CNAME target '{target}' does not resolve. This may indicate a subdomain takeover risk.",
            })

    # No issues found
    if not issues:
        issues.append({
            "severity": "info",
            "title": "No issues found",
            "description": "DNS records appear properly configured with SPF, DMARC, and CAA in place.",
        })

    return issues


def _check_dkim(resolver, domain: str) -> Dict[str, Any]:
    """Check common DKIM selectors."""
    common_selectors = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1", "s2"]
    found = []

    for selector in common_selectors:
        records = _query_records(resolver, f"{selector}._domainkey.{domain}", "TXT")
        if records:
            val = records[0].get("value", "").strip('"')
            if "v=DKIM1" in val or "k=rsa" in val:
                found.append({
                    "selector": selector,
                    "record": f"{selector}._domainkey.{domain}",
                    "value": val[:200],
                })

    return {
        "found": len(found) > 0,
        "selectors": found,
    }


def _check_dnssec(resolver, domain: str) -> Dict[str, Any]:
    """Check if DNSSEC is enabled for the domain."""
    try:
        import dns.resolver
        import dns.rdatatype

        try:
            answers = resolver.resolve(domain, "DNSKEY")
            return {"enabled": True, "keyCount": len(list(answers))}
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return {"enabled": False}
        except Exception:
            return {"enabled": False}
    except ImportError:
        return {"enabled": False}


def _resolve_hostname(hostname: str) -> List[str]:
    """Resolve a hostname to IP addresses."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return list(dict.fromkeys(addr[4][0] for addr in results))
    except (socket.gaierror, socket.herror, OSError):
        return []


def _calculate_grade(issues: List[Dict[str, str]]) -> str:
    """Calculate an A-F grade based on issues found."""
    severities = [i["severity"] for i in issues]
    if "critical" in severities:
        return "F"
    high_count = severities.count("high")
    if high_count >= 3:
        return "D"
    if high_count >= 2:
        return "C"
    if high_count >= 1:
        return "C+"
    medium_count = severities.count("medium")
    if medium_count >= 2:
        return "B"
    if medium_count >= 1:
        return "B+"
    return "A"