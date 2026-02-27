# app/tools/email_security.py
"""
Email Security Lookup tool.

Checks SPF, DKIM, and DMARC records for a domain and grades them.

Public mode:  summary only (grade + issues + record presence)
Full mode:    all details including raw records, parsed directives, selectors
"""

from __future__ import annotations

import dns.resolver
import logging
import re

logger = logging.getLogger(__name__)

# Common DKIM selectors to probe
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",  # Google / Microsoft
    "k1", "k2", "k3",                                # Mailchimp
    "s1", "s2",                                       # Generic
    "dkim", "mail", "email",                          # Common
    "mandrill", "mxvault", "everlytickey1", "cm",     # ESPs
    "smtp", "ses", "amazonses",                       # AWS SES
    "postmark", "pm",                                 # Postmark
    "mailjet", "turbo-smtp",                          # Others
    "protonmail", "protonmail2", "protonmail3",        # Proton
    "zendesk1", "zendesk2",                           # Zendesk
    "sendgrid", "smtpapi",                            # SendGrid
    "hubspot",                                        # HubSpot
]

RESOLVER_TIMEOUT = 5
RESOLVER_LIFETIME = 10


def _make_resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = RESOLVER_TIMEOUT
    r.lifetime = RESOLVER_LIFETIME
    r.nameservers = ["8.8.8.8", "1.1.1.1"]
    return r


def _query_txt(domain: str, resolver: dns.resolver.Resolver) -> list[str]:
    """Return all TXT record strings for a domain."""
    try:
        answers = resolver.resolve(domain, "TXT")
        results = []
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            results.append(txt)
        return results
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.resolver.Timeout,
            dns.exception.DNSException):
        return []


# ───────────────────────────────────────────────────────────────
# SPF Analysis
# ───────────────────────────────────────────────────────────────

def _check_spf(domain: str, resolver: dns.resolver.Resolver) -> dict:
    txt_records = _query_txt(domain, resolver)
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    result: dict = {
        "found": False,
        "record": None,
        "valid": False,
        "mechanisms": [],
        "allQualifier": None,
        "lookupCount": 0,
        "issues": [],
    }

    if not spf_records:
        result["issues"].append({
            "severity": "high",
            "title": "No SPF Record Found",
            "description": "This domain has no SPF record, allowing anyone to spoof emails from it.",
            "recommendation": "Add a TXT record starting with 'v=spf1' to define authorized mail senders.",
        })
        return result

    if len(spf_records) > 1:
        result["issues"].append({
            "severity": "high",
            "title": "Multiple SPF Records",
            "description": f"Found {len(spf_records)} SPF records. RFC 7208 requires exactly one.",
            "recommendation": "Merge all SPF records into a single TXT record.",
        })

    spf = spf_records[0]
    result["found"] = True
    result["record"] = spf
    result["valid"] = True

    # Parse mechanisms
    parts = spf.split()
    mechanisms = []
    lookup_count = 0
    all_qualifier = None

    for part in parts[1:]:  # skip v=spf1
        # Detect qualifier
        qualifier = "+"
        mechanism = part
        if part[0] in "+-~?":
            qualifier = part[0]
            mechanism = part[1:]

        if mechanism == "all":
            all_qualifier = qualifier
            mechanisms.append({"mechanism": "all", "qualifier": qualifier})
            continue

        mechanisms.append({"mechanism": mechanism, "qualifier": qualifier})

        # Count DNS lookups
        mech_type = mechanism.split(":")[0].split("/")[0].lower()
        if mech_type in ("include", "a", "mx", "ptr", "exists", "redirect"):
            lookup_count += 1

    result["mechanisms"] = mechanisms
    result["allQualifier"] = all_qualifier
    result["lookupCount"] = lookup_count

    # Issue checks
    if all_qualifier == "+":
        result["issues"].append({
            "severity": "critical",
            "title": "SPF Uses +all (Pass All)",
            "description": "The SPF record ends with '+all', which allows any server to send email for this domain.",
            "recommendation": "Change '+all' to '-all' (hard fail) or '~all' (soft fail).",
        })
    elif all_qualifier == "?":
        result["issues"].append({
            "severity": "high",
            "title": "SPF Uses ?all (Neutral)",
            "description": "The SPF record ends with '?all', providing no protection against spoofing.",
            "recommendation": "Change '?all' to '-all' (hard fail) or '~all' (soft fail).",
        })
    elif all_qualifier == "~":
        result["issues"].append({
            "severity": "low",
            "title": "SPF Uses ~all (Soft Fail)",
            "description": "Soft fail is acceptable but '-all' provides stronger protection.",
            "recommendation": "Consider changing to '-all' for strict enforcement once all senders are listed.",
        })
    elif all_qualifier is None:
        result["issues"].append({
            "severity": "medium",
            "title": "No 'all' Mechanism",
            "description": "SPF record does not end with an 'all' mechanism, defaulting to neutral.",
            "recommendation": "Add '-all' or '~all' at the end of the SPF record.",
        })

    if lookup_count > 10:
        result["issues"].append({
            "severity": "high",
            "title": f"Too Many DNS Lookups ({lookup_count})",
            "description": "SPF is limited to 10 DNS lookups. Exceeding this causes permanent errors.",
            "recommendation": "Flatten includes or use ip4/ip6 mechanisms to reduce lookups.",
        })
    elif lookup_count > 7:
        result["issues"].append({
            "severity": "medium",
            "title": f"High DNS Lookup Count ({lookup_count}/10)",
            "description": "Approaching the 10-lookup SPF limit.",
            "recommendation": "Consider flattening some 'include' mechanisms.",
        })

    if len(spf) > 450:
        result["issues"].append({
            "severity": "medium",
            "title": "SPF Record Very Long",
            "description": f"Record is {len(spf)} characters. DNS TXT records over 255 bytes require multiple strings.",
            "recommendation": "Consider flattening to reduce length, or verify your DNS provider handles long records.",
        })

    # Check for deprecated ptr mechanism
    if any("ptr" in m["mechanism"].lower() for m in mechanisms):
        result["issues"].append({
            "severity": "medium",
            "title": "Deprecated 'ptr' Mechanism",
            "description": "The 'ptr' mechanism is deprecated (RFC 7208) due to performance and reliability issues.",
            "recommendation": "Replace 'ptr' with 'a' or 'ip4'/'ip6' mechanisms.",
        })

    return result


# ───────────────────────────────────────────────────────────────
# DKIM Analysis
# ───────────────────────────────────────────────────────────────

def _check_dkim(domain: str, resolver: dns.resolver.Resolver) -> dict:
    result: dict = {
        "found": False,
        "selectors": [],
        "issues": [],
    }

    found_selectors = []
    for sel in DKIM_SELECTORS:
        dkim_domain = f"{sel}._domainkey.{domain}"
        records = _query_txt(dkim_domain, resolver)
        for rec in records:
            if "v=dkim1" in rec.lower() or "p=" in rec:
                parsed: dict = {"selector": sel, "record": rec, "valid": True, "keyType": "rsa", "issues": []}

                # Parse key type
                kt_match = re.search(r"k=(\w+)", rec)
                if kt_match:
                    parsed["keyType"] = kt_match.group(1)

                # Check for empty public key (revoked)
                p_match = re.search(r"p=([^;\s]*)", rec)
                if p_match and not p_match.group(1).strip():
                    parsed["valid"] = False
                    parsed["issues"].append("Empty public key (selector revoked)")

                # Check for testing mode
                if "t=y" in rec:
                    parsed["issues"].append("Testing mode enabled (t=y)")

                found_selectors.append(parsed)
                break  # one per selector

    result["selectors"] = found_selectors
    result["found"] = len(found_selectors) > 0

    if not found_selectors:
        result["issues"].append({
            "severity": "medium",
            "title": "No DKIM Selectors Found",
            "description": f"Checked {len(DKIM_SELECTORS)} common selectors but none had DKIM records.",
            "recommendation": "Configure DKIM signing with your email provider and publish the public key.",
        })

    return result


# ───────────────────────────────────────────────────────────────
# DMARC Analysis
# ───────────────────────────────────────────────────────────────

def _check_dmarc(domain: str, resolver: dns.resolver.Resolver) -> dict:
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = _query_txt(dmarc_domain, resolver)
    dmarc_records = [r for r in txt_records if r.lower().startswith("v=dmarc1")]

    result: dict = {
        "found": False,
        "record": None,
        "policy": None,
        "subdomainPolicy": None,
        "percentage": 100,
        "reportingUris": [],
        "forensicUris": [],
        "alignmentSpf": None,
        "alignmentDkim": None,
        "issues": [],
    }

    if not dmarc_records:
        result["issues"].append({
            "severity": "high",
            "title": "No DMARC Record Found",
            "description": "Without DMARC, receivers cannot verify email authenticity or report abuse.",
            "recommendation": "Add a TXT record at _dmarc.{domain} starting with 'v=DMARC1'.",
        })
        return result

    if len(dmarc_records) > 1:
        result["issues"].append({
            "severity": "high",
            "title": "Multiple DMARC Records",
            "description": f"Found {len(dmarc_records)} DMARC records. Only one is allowed.",
            "recommendation": "Remove duplicate DMARC records.",
        })

    dmarc = dmarc_records[0]
    result["found"] = True
    result["record"] = dmarc

    # Parse tags
    tags = {}
    for part in dmarc.split(";"):
        part = part.strip()
        if "=" in part:
            key, val = part.split("=", 1)
            tags[key.strip().lower()] = val.strip()

    result["policy"] = tags.get("p")
    result["subdomainPolicy"] = tags.get("sp")
    result["alignmentSpf"] = tags.get("aspf", "r")   # default relaxed
    result["alignmentDkim"] = tags.get("adkim", "r")  # default relaxed

    if "pct" in tags:
        try:
            result["percentage"] = int(tags["pct"])
        except ValueError:
            pass

    # Reporting URIs
    if "rua" in tags:
        result["reportingUris"] = [u.strip() for u in tags["rua"].split(",")]
    if "ruf" in tags:
        result["forensicUris"] = [u.strip() for u in tags["ruf"].split(",")]

    # Policy checks
    policy = (result["policy"] or "").lower()
    if policy == "none":
        result["issues"].append({
            "severity": "medium",
            "title": "DMARC Policy is 'none' (Monitor Only)",
            "description": "The policy only monitors but does not reject or quarantine spoofed emails.",
            "recommendation": "Move to 'p=quarantine' or 'p=reject' once you've reviewed reports.",
        })
    elif policy == "quarantine":
        result["issues"].append({
            "severity": "low",
            "title": "DMARC Policy is 'quarantine'",
            "description": "Suspicious emails are quarantined. Consider 'reject' for maximum protection.",
            "recommendation": "Once confident, upgrade to 'p=reject'.",
        })
    elif policy != "reject":
        result["issues"].append({
            "severity": "high",
            "title": f"Unknown DMARC Policy: '{result['policy']}'",
            "description": "The policy value is not recognized.",
            "recommendation": "Use 'none', 'quarantine', or 'reject'.",
        })

    if result["percentage"] < 100:
        result["issues"].append({
            "severity": "medium",
            "title": f"DMARC Applies to {result['percentage']}% of Emails",
            "description": "The pct tag limits enforcement. Some spoofed emails may still be delivered.",
            "recommendation": "Increase to pct=100 once you're satisfied with the policy.",
        })

    if not result["reportingUris"]:
        result["issues"].append({
            "severity": "medium",
            "title": "No Aggregate Reporting (rua)",
            "description": "Without rua, you won't receive aggregate DMARC reports from receivers.",
            "recommendation": "Add 'rua=mailto:dmarc-reports@yourdomain.com' to receive reports.",
        })

    return result


# ───────────────────────────────────────────────────────────────
# Grading
# ───────────────────────────────────────────────────────────────

def _compute_grade(spf: dict, dkim: dict, dmarc: dict) -> str:
    """Grade email security from A+ to F."""
    score = 100

    # SPF scoring
    if not spf["found"]:
        score -= 30
    else:
        if spf["allQualifier"] == "+":
            score -= 30
        elif spf["allQualifier"] == "?":
            score -= 20
        elif spf["allQualifier"] == "~":
            score -= 5
        if spf["lookupCount"] > 10:
            score -= 10

    # DKIM scoring
    if not dkim["found"]:
        score -= 20

    # DMARC scoring
    if not dmarc["found"]:
        score -= 30
    else:
        policy = (dmarc["policy"] or "").lower()
        if policy == "none":
            score -= 15
        elif policy == "quarantine":
            score -= 5
        if dmarc["percentage"] < 100:
            score -= 5
        if not dmarc["reportingUris"]:
            score -= 5

    if score >= 95:
        return "A+"
    elif score >= 85:
        return "A"
    elif score >= 75:
        return "B+"
    elif score >= 65:
        return "B"
    elif score >= 55:
        return "C"
    elif score >= 40:
        return "D"
    else:
        return "F"


# ───────────────────────────────────────────────────────────────
# Public API
# ───────────────────────────────────────────────────────────────

def run_email_security_check(domain: str, full: bool = True) -> dict:
    """
    Run SPF, DKIM, and DMARC checks for a domain.

    Args:
        domain: The domain to check.
        full: If True, return all details. If False, return summary only.
    """
    resolver = _make_resolver()

    spf = _check_spf(domain, resolver)
    dkim = _check_dkim(domain, resolver)
    dmarc = _check_dmarc(domain, resolver)

    grade = _compute_grade(spf, dkim, dmarc)

    # Collect all issues
    all_issues = []
    all_issues.extend(spf.get("issues", []))
    all_issues.extend(dkim.get("issues", []))
    all_issues.extend(dmarc.get("issues", []))

    # Sort: critical > high > medium > low > info
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_issues.sort(key=lambda i: sev_order.get(i.get("severity", "info"), 5))

    result: dict = {
        "domain": domain,
        "grade": grade,
        "issues": all_issues,
        "spf": {
            "found": spf["found"],
            "record": spf["record"],
            "valid": spf["valid"],
            "allQualifier": spf["allQualifier"],
            "lookupCount": spf["lookupCount"],
        },
        "dkim": {
            "found": dkim["found"],
            "selectorCount": len(dkim["selectors"]),
        },
        "dmarc": {
            "found": dmarc["found"],
            "policy": dmarc["policy"],
            "subdomainPolicy": dmarc["subdomainPolicy"],
            "percentage": dmarc["percentage"],
        },
    }

    if full:
        result["spf"]["mechanisms"] = spf["mechanisms"]
        result["dkim"]["selectors"] = dkim["selectors"]
        result["dmarc"]["record"] = dmarc["record"]
        result["dmarc"]["reportingUris"] = dmarc["reportingUris"]
        result["dmarc"]["forensicUris"] = dmarc["forensicUris"]
        result["dmarc"]["alignmentSpf"] = dmarc["alignmentSpf"]
        result["dmarc"]["alignmentDkim"] = dmarc["alignmentDkim"]

    return result