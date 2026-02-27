# app/tools/cert_lookup.py
"""
Certificate Lookup tool.

Connects to the target domain on port 443, retrieves the SSL/TLS
certificate, and returns structured certificate information.

For authenticated (full) requests, also queries CT logs via crt.sh
for historical certificate issuances.
"""

from __future__ import annotations

import json
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

logger = logging.getLogger(__name__)

TIMEOUT = 8


def run_cert_lookup(domain: str, full: bool = False) -> Dict[str, Any]:
    """
    Run a certificate lookup for the given domain.

    Args:
        domain: Target domain (e.g., "example.com")
        full:   If True, include CT log history and extended details

    Returns:
        Dict with certificate information
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "certificate": None,
        "issues": [],
        "grade": None,
        "error": None,
    }

    # Step 1: Pull live certificate
    cert_data = _get_live_certificate(domain)
    if cert_data is None:
        result["error"] = f"Could not connect to {domain}:443 or no SSL/TLS certificate found."
        result["grade"] = "F"
        return result

    result["certificate"] = cert_data

    # Step 2: Analyse for issues
    issues = _analyse_certificate(cert_data, domain)
    result["issues"] = issues

    # Step 3: Calculate grade
    result["grade"] = _calculate_grade(issues)

    # Step 4: Full mode — CT log history
    if full:
        ct_certs = _query_ct_logs(domain)
        result["ctLogCertificates"] = ct_certs
        result["ctLogCount"] = len(ct_certs)

    return result


def run_cert_hash_lookup(cert_hash: str, full: bool = False) -> Dict[str, Any]:
    """
    Look up a certificate by its SHA-256 fingerprint via crt.sh.

    Args:
        cert_hash: SHA-256 fingerprint (hex, with or without colons)
        full:      If True, include all matching entries

    Returns:
        Dict with certificate information from CT logs
    """
    result: Dict[str, Any] = {
        "hash": cert_hash,
        "certificates": [],
        "error": None,
    }

    # Normalize hash: remove colons, spaces, lowercase
    clean_hash = cert_hash.replace(":", "").replace(" ", "").strip().lower()
    if len(clean_hash) != 64 or not all(c in "0123456789abcdef" for c in clean_hash):
        result["error"] = "Invalid SHA-256 hash. Must be 64 hex characters (with or without colons)."
        return result

    try:
        url = f"https://crt.sh/?q={clean_hash}&output=json"
        req = Request(url, headers={"User-Agent": "BoltEdge EASM"})
        response = urlopen(req, timeout=15)
        data = json.loads(response.read(524288).decode("utf-8", errors="replace"))

        if not isinstance(data, list) or not data:
            result["error"] = f"No certificates found for hash {clean_hash[:16]}..."
            return result

        seen = set()
        certs = []
        for entry in data:
            serial = entry.get("serial_number", "")
            if serial in seen:
                continue
            seen.add(serial)
            cert_entry = {
                "id": entry.get("id"),
                "issuerName": entry.get("issuer_name", ""),
                "commonName": entry.get("common_name", ""),
                "nameValue": entry.get("name_value", ""),
                "notBefore": entry.get("not_before"),
                "notAfter": entry.get("not_after"),
                "serialNumber": serial,
                "entryTimestamp": entry.get("entry_timestamp"),
            }

            # Check if expired
            if cert_entry["notAfter"]:
                try:
                    expiry = datetime.strptime(cert_entry["notAfter"], "%Y-%m-%dT%H:%M:%S")
                    cert_entry["isExpired"] = datetime.now(timezone.utc) > expiry.replace(tzinfo=timezone.utc)
                    cert_entry["daysUntilExpiry"] = (expiry.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
                except (ValueError, Exception):
                    pass

            certs.append(cert_entry)

        certs.sort(key=lambda c: c.get("notBefore") or "", reverse=True)

        if not full:
            certs = certs[:10]

        result["certificates"] = certs
        result["totalFound"] = len(certs)

        # Extract unique domains covered by this cert
        all_domains = set()
        for c in certs:
            name_val = c.get("nameValue", "")
            for line in name_val.split("\n"):
                line = line.strip()
                if line and not line.startswith("*"):
                    all_domains.add(line.lower())
                elif line.startswith("*."):
                    all_domains.add(line.lower())
        result["coveredDomains"] = sorted(all_domains)[:50]

    except Exception as e:
        logger.debug(f"Cert hash lookup failed: {e}")
        result["error"] = f"Failed to query certificate database: {str(e)}"

    return result


def _get_live_certificate(domain: str) -> Optional[Dict[str, Any]]:
    """Connect to domain:443 and retrieve certificate details."""
    try:
        ctx = ssl.create_default_context()
        # We want to inspect the cert even if it's invalid
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get the binary DER cert
                der_cert = ssock.getpeercert(binary_form=True)
                # Get parsed cert dict (only works with CERT_REQUIRED, so do a second pass)
                pem_info = ssock.getpeercert(binary_form=False)

                # Get protocol and cipher
                protocol = ssock.version()
                cipher = ssock.cipher()

        # Parse with ssl module's built-in parser
        # pem_info might be empty with CERT_NONE, so parse DER manually
        cert_info = _parse_der_cert(der_cert, domain)
        if cert_info is None:
            return None

        cert_info["tlsVersion"] = protocol
        cert_info["cipherSuite"] = cipher[0] if cipher else None
        cert_info["cipherBits"] = cipher[2] if cipher and len(cipher) > 2 else None

        # Check chain validity with a proper validation pass
        cert_info["chainValid"] = _check_chain_validity(domain)

        # Check hostname match
        cert_info["hostnameMatch"] = _check_hostname_match(domain, cert_info.get("sans", []), cert_info.get("subjectCn", ""))

        return cert_info

    except (socket.timeout, socket.gaierror) as e:
        logger.debug(f"Cert lookup connection failed for {domain}: {e}")
        return None
    except Exception as e:
        logger.debug(f"Cert lookup failed for {domain}: {e}")
        return None


def _parse_der_cert(der_bytes: bytes, domain: str) -> Optional[Dict[str, Any]]:
    """Parse a DER-encoded certificate into structured data."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        cert = x509.load_der_x509_certificate(der_bytes)
        now = datetime.now(timezone.utc)

        # Subject CN
        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        subject_cn = cn_attrs[0].value if cn_attrs else ""

        # Issuer
        issuer_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        issuer_org = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
        issuer = issuer_cn[0].value if issuer_cn else (issuer_org[0].value if issuer_org else "Unknown")

        # SANs
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        # Dates
        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
        days_until_expiry = (not_after - now).days

        # Fingerprint
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        fingerprint_formatted = ":".join(fingerprint[i:i+2].upper() for i in range(0, len(fingerprint), 2))

        # Serial
        serial_hex = format(cert.serial_number, "X")

        # Self-signed check
        is_self_signed = cert.issuer == cert.subject

        # Wildcard check
        is_wildcard = subject_cn.startswith("*.") or any(s.startswith("*.") for s in sans)

        # Expired check
        is_expired = now > not_after

        # Key size
        key_size = None
        try:
            key_size = cert.public_key().key_size
        except (AttributeError, Exception):
            pass

        # Signature algorithm
        sig_algo = cert.signature_algorithm_oid._name if cert.signature_algorithm_oid else None

        return {
            "subjectCn": subject_cn,
            "issuer": issuer,
            "sans": sans,
            "serialNumber": serial_hex,
            "notBefore": not_before.isoformat() + "Z",
            "notAfter": not_after.isoformat() + "Z",
            "daysUntilExpiry": days_until_expiry,
            "isExpired": is_expired,
            "isSelfSigned": is_self_signed,
            "isWildcard": is_wildcard,
            "keySize": key_size,
            "signatureAlgorithm": sig_algo,
            "fingerprintSha256": fingerprint_formatted,
        }

    except ImportError:
        logger.warning("cryptography library not installed — falling back to basic cert parsing")
        return _parse_cert_basic(der_bytes, domain)
    except Exception as e:
        logger.debug(f"Failed to parse DER cert: {e}")
        return None


def _parse_cert_basic(der_bytes: bytes, domain: str) -> Optional[Dict[str, Any]]:
    """Basic fallback cert parsing using ssl module only (no cryptography lib)."""
    try:
        import tempfile
        import os

        # Write DER to temp file, convert to PEM-like format for ssl
        pem = ssl.DER_cert_to_PEM_cert(der_bytes)

        # Use a validating context to get parsed cert
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_dict = ssock.getpeercert(binary_form=False)

        if not cert_dict:
            return {"subjectCn": "Unknown", "issuer": "Unknown", "sans": [], "error": "Could not parse certificate details"}

        # Extract fields from cert dict
        subject = dict(x[0] for x in cert_dict.get("subject", ()))
        issuer = dict(x[0] for x in cert_dict.get("issuer", ()))

        sans = []
        for san_type, san_val in cert_dict.get("subjectAltName", ()):
            if san_type == "DNS":
                sans.append(san_val)

        cn = subject.get("commonName", "")
        now = datetime.now(timezone.utc)
        not_after_str = cert_dict.get("notAfter", "")
        not_before_str = cert_dict.get("notBefore", "")

        not_after = None
        not_before = None
        try:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except (ValueError, Exception):
            pass

        days_until_expiry = (not_after - now).days if not_after else None

        return {
            "subjectCn": cn,
            "issuer": issuer.get("commonName") or issuer.get("organizationName", "Unknown"),
            "sans": sans,
            "serialNumber": cert_dict.get("serialNumber", ""),
            "notBefore": not_before.isoformat() + "Z" if not_before else None,
            "notAfter": not_after.isoformat() + "Z" if not_after else None,
            "daysUntilExpiry": days_until_expiry,
            "isExpired": days_until_expiry is not None and days_until_expiry < 0,
            "isSelfSigned": subject == issuer,
            "isWildcard": cn.startswith("*.") if cn else False,
        }
    except Exception as e:
        logger.debug(f"Basic cert parse failed: {e}")
        return None


def _check_chain_validity(domain: str) -> bool:
    """Check if the certificate chain is valid using default CA store."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                return True
    except ssl.SSLCertVerificationError:
        return False
    except Exception:
        return False


def _check_hostname_match(domain: str, sans: List[str], cn: str) -> bool:
    """Check if the domain matches the certificate's CN or SANs."""
    targets = [s.lower() for s in sans] if sans else [cn.lower()]
    domain_lower = domain.lower()

    for target in targets:
        if target == domain_lower:
            return True
        # Wildcard match: *.example.com matches sub.example.com
        if target.startswith("*."):
            wildcard_base = target[2:]
            if domain_lower.endswith("." + wildcard_base) or domain_lower == wildcard_base:
                return True
    return False


def _analyse_certificate(cert: Dict[str, Any], domain: str) -> List[Dict[str, str]]:
    """Analyse certificate for issues and return a list of findings."""
    issues = []

    # Expired
    if cert.get("isExpired"):
        issues.append({
            "severity": "critical",
            "title": "Certificate is expired",
            "description": f"The certificate expired on {cert.get('notAfter', 'unknown')}. Browsers will show security warnings to all visitors.",
        })

    # Expiring soon
    days = cert.get("daysUntilExpiry")
    if days is not None and not cert.get("isExpired"):
        if days <= 7:
            issues.append({
                "severity": "high",
                "title": f"Certificate expires in {days} day(s)",
                "description": "The certificate is about to expire. Renew immediately to avoid service disruption.",
            })
        elif days <= 30:
            issues.append({
                "severity": "medium",
                "title": f"Certificate expires in {days} days",
                "description": "The certificate will expire within 30 days. Schedule a renewal.",
            })

    # Self-signed
    if cert.get("isSelfSigned"):
        issues.append({
            "severity": "medium",
            "title": "Self-signed certificate",
            "description": "The certificate is self-signed and will not be trusted by browsers. Use a certificate from a trusted CA.",
        })

    # Chain invalid
    if cert.get("chainValid") is False:
        issues.append({
            "severity": "high",
            "title": "Invalid certificate chain",
            "description": "The certificate chain could not be validated against the system CA store. This may cause trust errors in browsers.",
        })

    # Hostname mismatch
    if cert.get("hostnameMatch") is False:
        issues.append({
            "severity": "high",
            "title": "Hostname mismatch",
            "description": f"The certificate's CN/SANs do not match the domain '{domain}'. Browsers will show a security warning.",
        })

    # Deprecated TLS
    tls = cert.get("tlsVersion", "")
    if tls in ("TLSv1", "TLSv1.1"):
        issues.append({
            "severity": "high",
            "title": f"Deprecated TLS version ({tls})",
            "description": f"The server negotiated {tls}, which is deprecated and insecure. Upgrade to TLS 1.2 or 1.3.",
        })

    # Weak key
    key_size = cert.get("keySize")
    if key_size and key_size < 2048:
        issues.append({
            "severity": "medium",
            "title": f"Weak key size ({key_size} bits)",
            "description": "RSA keys smaller than 2048 bits are considered weak. Use at least 2048-bit keys.",
        })

    # No issues
    if not issues:
        issues.append({
            "severity": "info",
            "title": "No issues found",
            "description": "The certificate appears valid and properly configured.",
        })

    return issues


def _calculate_grade(issues: List[Dict[str, str]]) -> str:
    """Calculate an A-F grade based on issues found."""
    severities = [i["severity"] for i in issues]
    if "critical" in severities:
        return "F"
    if severities.count("high") >= 2:
        return "D"
    if "high" in severities:
        return "C"
    if "medium" in severities:
        return "B"
    return "A"


def _query_ct_logs(domain: str) -> List[Dict[str, Any]]:
    """Query crt.sh for Certificate Transparency log entries."""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = Request(url, headers={"User-Agent": "BoltEdge EASM"})
        response = urlopen(req, timeout=10)
        data = json.loads(response.read(524288).decode("utf-8", errors="replace"))

        if not isinstance(data, list):
            return []

        # Deduplicate by serial number, take most recent 50
        seen = set()
        certs = []
        for entry in data:
            serial = entry.get("serial_number", "")
            if serial in seen:
                continue
            seen.add(serial)
            certs.append({
                "id": entry.get("id"),
                "issuerName": entry.get("issuer_name", ""),
                "commonName": entry.get("common_name", ""),
                "nameValue": entry.get("name_value", ""),
                "notBefore": entry.get("not_before"),
                "notAfter": entry.get("not_after"),
                "serialNumber": serial,
                "entryTimestamp": entry.get("entry_timestamp"),
            })

        # Sort by most recent first
        certs.sort(key=lambda c: c.get("notBefore") or "", reverse=True)
        return certs[:50]

    except Exception as e:
        logger.debug(f"CT log query failed for {domain}: {e}")
        return []