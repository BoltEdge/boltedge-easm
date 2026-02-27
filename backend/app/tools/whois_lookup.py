# app/tools/whois_lookup.py
"""
WHOIS Lookup tool.

Supports three input types (auto-detected):
  - Domain:  standard domain WHOIS (registrar, dates, nameservers, status)
  - IP:      queries ARIN/RIPE/APNIC/LACNIC/AFRINIC for netblock ownership
  - ASN:     queries AS number ownership and routing info
"""

from __future__ import annotations

import logging
import re
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

TIMEOUT = 10

# ═══════════════════════════════════════════════════════════════
# DOMAIN WHOIS SERVERS
# ═══════════════════════════════════════════════════════════════

WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "ai": "whois.nic.ai",
    "me": "whois.nic.me",
    "xyz": "whois.nic.xyz",
    "tech": "whois.nic.tech",
    "cloud": "whois.nic.cloud",
    "security": "whois.nic.security",
    "uk": "whois.nic.uk",
    "au": "whois.auda.org.au",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "nl": "whois.sidn.nl",
    "ca": "whois.cira.ca",
    "us": "whois.nic.us",
    "eu": "whois.eu",
    "in": "whois.registry.in",
    "jp": "whois.jprs.jp",
    "br": "whois.registro.br",
}

IANA_WHOIS = "whois.iana.org"

# RIR WHOIS servers
RIR_SERVERS = {
    "arin": "whois.arin.net",
    "ripe": "whois.ripe.net",
    "apnic": "whois.apnic.net",
    "lacnic": "whois.lacnic.net",
    "afrinic": "whois.afrinic.net",
}

# ═══════════════════════════════════════════════════════════════
# INPUT TYPE DETECTION
# ═══════════════════════════════════════════════════════════════

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
IPV6_RE = re.compile(r"^[0-9a-fA-F:]{3,39}$")
ASN_RE = re.compile(r"^(?:AS|as)?(\d{1,10})$")
DOMAIN_RE = re.compile(r"^([a-z0-9-]+\.)+[a-z]{2,63}$", re.IGNORECASE)


def detect_query_type(query: str) -> str:
    """Detect whether input is domain, ip, or asn."""
    q = query.strip()
    if IP_RE.match(q):
        return "ip"
    if IPV6_RE.match(q) and ":" in q:
        return "ip"
    if ASN_RE.match(q):
        return "asn"
    return "domain"


# ═══════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def run_whois_lookup(query: str, full: bool = False) -> Dict[str, Any]:
    """
    Run a WHOIS lookup. Auto-detects input type.

    Args:
        query: Domain, IP address, or ASN (e.g. "example.com", "8.8.8.8", "AS13335")
        full:  If True, include raw WHOIS text and extended details
    """
    query = query.strip()
    query_type = detect_query_type(query)

    if query_type == "ip":
        return _whois_ip(query, full)
    elif query_type == "asn":
        return _whois_asn(query, full)
    else:
        return _whois_domain(query, full)


# ═══════════════════════════════════════════════════════════════
# DOMAIN WHOIS
# ═══════════════════════════════════════════════════════════════

def _whois_domain(domain: str, full: bool = False) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "query": domain, "queryType": "domain",
        "registration": None, "issues": [], "error": None,
    }

    domain = domain.lower().strip().rstrip(".")
    if not DOMAIN_RE.match(domain):
        result["error"] = "Invalid domain format."
        return result

    tld = domain.rsplit(".", 1)[-1]
    whois_server = WHOIS_SERVERS.get(tld)
    if not whois_server:
        whois_server = _lookup_iana_whois(tld)
    if not whois_server:
        result["error"] = f"No WHOIS server found for TLD '.{tld}'."
        return result

    raw_text = _query_whois(domain, whois_server)
    if not raw_text:
        result["error"] = f"WHOIS query to {whois_server} failed or returned empty."
        return result

    referral = _extract_referral(raw_text)
    if referral and referral != whois_server:
        referral_text = _query_whois(domain, referral)
        if referral_text:
            raw_text = referral_text

    parsed = _parse_domain_whois(raw_text)
    result["registration"] = parsed
    if full:
        result["rawWhois"] = raw_text[:5000]
        result["whoisServer"] = whois_server
    result["issues"] = _analyse_domain_whois(parsed, domain)
    return result


# ═══════════════════════════════════════════════════════════════
# IP WHOIS
# ═══════════════════════════════════════════════════════════════

def _whois_ip(ip: str, full: bool = False) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "query": ip, "queryType": "ip",
        "network": None, "issues": [], "error": None,
    }

    # Validate octets
    if IP_RE.match(ip):
        octets = ip.split(".")
        if any(int(o) > 255 for o in octets):
            result["error"] = "Invalid IP address: octets must be 0-255."
            return result

    # Start with ARIN — it handles referrals to other RIRs
    # Prefix with "n " for ARIN to get network-only output
    raw_text = _query_whois(f"n {ip}", RIR_SERVERS["arin"])

    if not raw_text:
        raw_text = _query_whois(ip, RIR_SERVERS["ripe"])

    if not raw_text:
        result["error"] = "WHOIS query failed for this IP address."
        return result

    # Follow RIR referral if ARIN points elsewhere
    referral_rir = _detect_rir_referral(raw_text)
    if referral_rir and referral_rir in RIR_SERVERS:
        referred_text = _query_whois(ip, RIR_SERVERS[referral_rir])
        if referred_text:
            raw_text = referred_text

    parsed = _parse_ip_whois(raw_text)
    result["network"] = parsed
    if full:
        result["rawWhois"] = raw_text[:5000]
    result["issues"] = _analyse_ip_whois(parsed)
    return result


def _detect_rir_referral(raw: str) -> Optional[str]:
    """Detect if ARIN response refers to another RIR."""
    referral_map = {
        "whois.ripe.net": "ripe",
        "whois.apnic.net": "apnic",
        "whois.lacnic.net": "lacnic",
        "whois.afrinic.net": "afrinic",
    }
    raw_lower = raw.lower()
    for server, rir in referral_map.items():
        if server in raw_lower:
            return rir
    for rir_name in ["RIPE", "APNIC", "LACNIC", "AFRINIC"]:
        if f"({rir_name})" in raw:
            return rir_name.lower()
    return None


def _parse_ip_whois(raw: str) -> Dict[str, Any]:
    """Parse IP WHOIS response into structured data."""
    data: Dict[str, Any] = {}

    field_map = [
        ("netName", ["NetName:", "netname:", "network-name:"]),
        ("netRange", ["NetRange:", "inetnum:", "inet6num:"]),
        ("cidr", ["CIDR:", "route:"]),
        ("orgName", ["OrgName:", "org-name:", "Organization:", "owner:"]),
        ("orgId", ["OrgId:", "org:", "aut-num:"]),
        ("country", ["Country:", "country:"]),
        ("regDate", ["RegDate:", "created:"]),
        ("updated", ["Updated:", "last-modified:", "changed:"]),
        ("abuseEmail", ["OrgAbuseEmail:", "abuse-mailbox:", "e-mail:"]),
        ("abusePhone", ["OrgAbusePhone:", "phone:"]),
        ("source", ["source:"]),
        ("status", ["NetType:", "status:"]),
        ("parentNet", ["Parent:", "parent:"]),
    ]

    for out_key, labels in field_map:
        for label in labels:
            pattern = re.escape(label) + r"\s*(.+)"
            match = re.search(pattern, raw, re.IGNORECASE)
            if match:
                val = match.group(1).strip()
                if val and val.lower() not in ("", "***"):
                    data[out_key] = val
                break

    # Description lines (common in RIPE responses)
    descr_lines = re.findall(r"descr:\s*(.+)", raw, re.IGNORECASE)
    if descr_lines:
        # Use first descr as orgName fallback
        if "orgName" not in data:
            data["orgName"] = descr_lines[0].strip()
        data["description"] = "; ".join(line.strip() for line in descr_lines[:5])

    # Collect all abuse contacts
    abuse_emails = re.findall(
        r"(?:OrgAbuseEmail|abuse-mailbox|e-mail):\s*(\S+@\S+)", raw, re.IGNORECASE
    )
    if abuse_emails:
        data["abuseContacts"] = list(dict.fromkeys(abuse_emails))[:5]

    return data


def _analyse_ip_whois(parsed: Dict[str, Any]) -> List[Dict[str, str]]:
    issues = []
    org = parsed.get("orgName")
    net = parsed.get("cidr") or parsed.get("netRange")

    if org:
        desc = f"Network: {net}" if net else "Network range not available."
        issues.append({"severity": "info", "title": f"IP owned by {org}", "description": desc})
    else:
        issues.append({"severity": "info", "title": "Limited WHOIS data",
            "description": "Could not determine the organization that owns this IP range."})

    if parsed.get("abuseEmail") or parsed.get("abuseContacts"):
        contact = parsed.get("abuseEmail") or parsed.get("abuseContacts", ["unknown"])[0]
        issues.append({"severity": "info", "title": "Abuse contact available",
            "description": f"Abuse reports can be sent to: {contact}"})

    return issues


# ═══════════════════════════════════════════════════════════════
# ASN WHOIS
# ═══════════════════════════════════════════════════════════════

def _whois_asn(asn_input: str, full: bool = False) -> Dict[str, Any]:
    match = ASN_RE.match(asn_input.strip())
    asn_number = match.group(1) if match else asn_input.upper().replace("AS", "")
    asn_str = f"AS{asn_number}"

    result: Dict[str, Any] = {
        "query": asn_str, "queryType": "asn",
        "asn": None, "issues": [], "error": None,
    }

    # Try ARIN first, then RIPE, then APNIC
    raw_text = _query_whois(f"a {asn_str}", RIR_SERVERS["arin"])

    if not raw_text or "No match found" in raw_text:
        raw_text = _query_whois(asn_str, RIR_SERVERS["ripe"])

    if not raw_text or "No match found" in raw_text:
        raw_text = _query_whois(asn_str, RIR_SERVERS["apnic"])

    if not raw_text:
        result["error"] = f"WHOIS query failed for {asn_str}."
        return result

    # Follow referral
    referral_rir = _detect_rir_referral(raw_text)
    if referral_rir and referral_rir in RIR_SERVERS:
        referred_text = _query_whois(asn_str, RIR_SERVERS[referral_rir])
        if referred_text:
            raw_text = referred_text

    parsed = _parse_asn_whois(raw_text, asn_str)
    result["asn"] = parsed
    if full:
        result["rawWhois"] = raw_text[:5000]
    result["issues"] = _analyse_asn_whois(parsed, asn_str)
    return result


def _parse_asn_whois(raw: str, asn_str: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {"number": asn_str}

    field_map = [
        ("name", ["ASName:", "as-name:"]),
        ("orgName", ["OrgName:", "org-name:", "owner:"]),
        ("orgId", ["OrgId:", "org:"]),
        ("country", ["Country:", "country:"]),
        ("regDate", ["RegDate:", "created:"]),
        ("updated", ["Updated:", "last-modified:", "changed:"]),
        ("abuseEmail", ["OrgAbuseEmail:", "abuse-mailbox:"]),
        ("source", ["source:"]),
        ("status", ["status:"]),
    ]

    for out_key, labels in field_map:
        for label in labels:
            pattern = re.escape(label) + r"\s*(.+)"
            match = re.search(pattern, raw, re.IGNORECASE)
            if match:
                val = match.group(1).strip()
                if val and val.lower() not in ("", "***"):
                    data[out_key] = val
                break

    # Description lines
    descr_lines = re.findall(r"descr:\s*(.+)", raw, re.IGNORECASE)
    if descr_lines:
        if "orgName" not in data:
            data["orgName"] = descr_lines[0].strip()
        data["description"] = "; ".join(line.strip() for line in descr_lines[:5])

    # Import/export policies (routing info)
    imports = re.findall(r"import:\s*(.+)", raw, re.IGNORECASE)
    exports = re.findall(r"export:\s*(.+)", raw, re.IGNORECASE)
    if imports:
        data["importPolicy"] = [line.strip() for line in imports[:10]]
    if exports:
        data["exportPolicy"] = [line.strip() for line in exports[:10]]

    # Abuse contacts
    abuse_emails = re.findall(
        r"(?:OrgAbuseEmail|abuse-mailbox):\s*(\S+@\S+)", raw, re.IGNORECASE
    )
    if abuse_emails:
        data["abuseContacts"] = list(dict.fromkeys(abuse_emails))[:5]

    return data


def _analyse_asn_whois(parsed: Dict[str, Any], asn_str: str) -> List[Dict[str, str]]:
    issues = []
    org = parsed.get("orgName") or parsed.get("name")

    if org:
        issues.append({"severity": "info", "title": f"{asn_str} operated by {org}",
            "description": f"Country: {parsed.get('country', 'Unknown')}"})
    else:
        issues.append({"severity": "info", "title": f"Limited data for {asn_str}",
            "description": "Could not determine the organization operating this ASN."})

    if parsed.get("abuseEmail") or parsed.get("abuseContacts"):
        contact = parsed.get("abuseEmail") or parsed.get("abuseContacts", ["unknown"])[0]
        issues.append({"severity": "info", "title": "Abuse contact available",
            "description": f"Abuse reports: {contact}"})

    return issues


# ═══════════════════════════════════════════════════════════════
# SHARED HELPERS
# ═══════════════════════════════════════════════════════════════

def _lookup_iana_whois(tld: str) -> Optional[str]:
    try:
        raw = _query_whois(tld, IANA_WHOIS)
        if raw:
            match = re.search(r"whois:\s*(\S+)", raw, re.IGNORECASE)
            if match:
                return match.group(1).strip()
    except Exception:
        pass
    return None


def _query_whois(query: str, server: str, port: int = 43) -> Optional[str]:
    try:
        with socket.create_connection((server, port), timeout=TIMEOUT) as sock:
            sock.sendall((query + "\r\n").encode("utf-8"))
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 65536:
                    break
            return response.decode("utf-8", errors="replace")
    except (socket.timeout, socket.gaierror, OSError) as e:
        logger.debug(f"WHOIS query failed for {query}@{server}: {e}")
        return None


def _extract_referral(raw: str) -> Optional[str]:
    patterns = [
        r"Registrar WHOIS Server:\s*(\S+)",
        r"Whois Server:\s*(\S+)",
        r"refer:\s*(\S+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, raw, re.IGNORECASE)
        if match:
            server = match.group(1).strip().rstrip(".")
            if server and "." in server:
                return server
    return None


def _parse_domain_whois(raw: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}

    field_map = [
        ("registrar", ["Registrar:", "Registrar Name:", "Sponsoring Registrar:"]),
        ("registrarUrl", ["Registrar URL:"]),
        ("creationDate", ["Creation Date:", "Created Date:", "Registration Date:", "Created:", "created:"]),
        ("expiryDate", ["Registry Expiry Date:", "Registrar Registration Expiration Date:", "Expiration Date:", "Expiry Date:", "Expires:", "paid-till:"]),
        ("updatedDate", ["Updated Date:", "Last Modified:", "Last Updated:", "changed:"]),
        ("registrantOrg", ["Registrant Organization:", "Registrant Organisation:", "org-name:", "Registrant:"]),
        ("registrantCountry", ["Registrant Country:", "Registrant Country Code:"]),
        ("registrantState", ["Registrant State/Province:"]),
        ("dnssec", ["DNSSEC:", "dnssec:"]),
    ]

    for out_key, labels in field_map:
        for label in labels:
            pattern = re.escape(label) + r"\s*(.+)"
            match = re.search(pattern, raw, re.IGNORECASE)
            if match:
                val = match.group(1).strip()
                if val and val.lower() not in ("redacted", "redacted for privacy", "data protected", "not disclosed"):
                    data[out_key] = val
                break

    ns_matches = re.findall(r"Name Server:\s*(\S+)", raw, re.IGNORECASE)
    if not ns_matches:
        ns_matches = re.findall(r"nserver:\s*(\S+)", raw, re.IGNORECASE)
    if ns_matches:
        data["nameservers"] = list(dict.fromkeys(ns.lower().rstrip(".") for ns in ns_matches))

    status_matches = re.findall(r"Domain Status:\s*(\S+)", raw, re.IGNORECASE)
    if not status_matches:
        status_matches = re.findall(r"Status:\s*(\S+)", raw, re.IGNORECASE)
    if status_matches:
        data["domainStatus"] = list(dict.fromkeys(status_matches))

    for date_key in ("creationDate", "expiryDate", "updatedDate"):
        if date_key in data:
            parsed = _parse_date(data[date_key])
            if parsed:
                data[date_key] = parsed.isoformat() + "Z"
                if date_key == "expiryDate":
                    data["daysUntilExpiry"] = (parsed - datetime.now(timezone.utc)).days
                elif date_key == "creationDate":
                    data["domainAgeDays"] = (datetime.now(timezone.utc) - parsed).days

    return data


def _parse_date(date_str: str) -> Optional[datetime]:
    formats = [
        "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y",
        "%d/%m/%Y", "%Y/%m/%d", "%Y.%m.%d", "%d.%m.%Y", "%b %d %Y",
    ]
    date_str = date_str.strip().split(" (")[0]
    for fmt in formats:
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _analyse_domain_whois(parsed: Dict[str, Any], domain: str) -> List[Dict[str, str]]:
    issues = []

    days = parsed.get("daysUntilExpiry")
    if days is not None:
        if days < 0:
            issues.append({"severity": "critical", "title": "Domain registration has expired",
                "description": f"The domain expired {abs(days)} days ago. It may be at risk of being re-registered."})
        elif days <= 14:
            issues.append({"severity": "high", "title": f"Domain expires in {days} day(s)",
                "description": "Renew immediately to prevent loss of the domain."})
        elif days <= 30:
            issues.append({"severity": "medium", "title": f"Domain expires in {days} days",
                "description": "The domain will expire within 30 days. Schedule a renewal."})
        elif days <= 90:
            issues.append({"severity": "low", "title": f"Domain expires in {days} days",
                "description": "Consider setting up auto-renewal."})

    age_days = parsed.get("domainAgeDays")
    if age_days is not None and age_days < 30:
        issues.append({"severity": "low", "title": f"Newly registered domain ({age_days} days old)",
            "description": "Recently registered domains are sometimes associated with phishing or fraud."})

    dnssec = (parsed.get("dnssec") or "").lower()
    if dnssec in ("unsigned", "no"):
        issues.append({"severity": "low", "title": "DNSSEC not enabled",
            "description": "DNSSEC protects against DNS spoofing and cache poisoning."})

    statuses = parsed.get("domainStatus", [])
    hold_statuses = [s for s in statuses if "hold" in s.lower()]
    if hold_statuses:
        issues.append({"severity": "high", "title": f"Domain has hold status: {', '.join(hold_statuses)}",
            "description": "This may prevent the domain from resolving or being transferred."})

    locked = any("clienttransferprohibited" in s.lower() for s in statuses)
    if not locked and statuses:
        issues.append({"severity": "low", "title": "Domain transfer lock not enabled",
            "description": "Enable registrar lock to prevent unauthorized transfers."})

    if not issues:
        issues.append({"severity": "info", "title": "No issues found",
            "description": "WHOIS records appear healthy."})

    return issues