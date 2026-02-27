# =============================================================================
# File: app/assets/intelligence.py
# Description: Asset intelligence endpoints — aggregate technology, SSL, DNS,
#   and port/service data from findings for the asset detail page.
#
# Endpoints:
#   GET /assets/<id>/intelligence — all roles can view
#
# This extracts and reshapes data already stored in Finding.details_json
# by the analyzers (tech_detector, ssl_analyzer, dns_analyzer, port_risk).
# No new scanning is needed — this is a read-only aggregation layer.
# =============================================================================

from __future__ import annotations

import logging
from flask import Blueprint, jsonify
from sqlalchemy import desc

from app.extensions import db
from app.models import Finding, Asset
from app.auth.decorators import require_auth, current_organization_id

logger = logging.getLogger(__name__)

intelligence_bp = Blueprint("asset_intelligence", __name__, url_prefix="/assets")


def _sid(x) -> str:
    return str(x) if x is not None else ""


def _safe_dict(v) -> dict:
    return v if isinstance(v, dict) else {}


def _safe_list(v) -> list:
    return v if isinstance(v, list) else []


def _get_latest_findings(asset_id: int, org_id: int):
    """Get all findings for an asset, most recent first."""
    return (
        db.session.query(Finding)
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(
            Finding.asset_id == asset_id,
            Asset.organization_id == org_id,
        )
        .order_by(desc(Finding.id))
        .all()
    )


def _extract_technologies(findings: list) -> list:
    """
    Extract technology inventory from tech_detector findings.
    Groups by technology name and picks the most recent version info.
    """
    tech_map: dict = {}  # key: (name_lower, category) → tech dict

    for f in findings:
        # Tech detector findings have finding_type "technology_detected"
        # or category "technology" with severity "info"
        ft = (f.finding_type or "").lower()
        cat = (getattr(f, "category", "") or "").lower()

        if ft not in ("technology_detected", "outdated_software") and cat != "technology":
            continue

        details = _safe_dict(f.details_json)
        name = details.get("technology") or ""
        if not name:
            # Try to parse from title: "Technology detected: nginx 1.24.0"
            title = f.title or ""
            if title.startswith("Technology detected: "):
                name = title.replace("Technology detected: ", "").strip()
            elif "Outdated " in title:
                parts = title.split("Outdated ", 1)
                if len(parts) > 1:
                    name = parts[1].split(" on ")[0].strip()

        if not name:
            continue

        category = details.get("category") or "other"
        key = (name.lower(), category)

        version = details.get("version") or details.get("current_version")
        source = details.get("source") or f.source or "unknown"
        port = details.get("port")
        confidence = getattr(f, "confidence", None) or details.get("confidence") or "medium"

        # EOL info
        eol_message = details.get("eol_message")
        is_outdated = ft == "outdated_software" or bool(eol_message)

        if key not in tech_map:
            tech_map[key] = {
                "name": name,
                "version": version,
                "category": category,
                "source": source,
                "port": port,
                "confidence": confidence,
                "severity": f.severity or "info",
                "isOutdated": is_outdated,
                "eolMessage": eol_message,
                "firstSeen": f.first_seen_at.isoformat() if f.first_seen_at else None,
                "lastSeen": f.last_seen_at.isoformat() if f.last_seen_at else None,
            }
        else:
            existing = tech_map[key]
            # Update with newer info
            if version and not existing.get("version"):
                existing["version"] = version
            if is_outdated:
                existing["isOutdated"] = True
                existing["eolMessage"] = eol_message or existing.get("eolMessage")
                # Outdated findings have higher severity
                existing["severity"] = f.severity or existing["severity"]
            if f.last_seen_at:
                existing["lastSeen"] = f.last_seen_at.isoformat()

    # Sort: outdated first, then by category, then by name
    techs = list(tech_map.values())
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    techs.sort(key=lambda t: (
        0 if t["isOutdated"] else 1,
        severity_order.get(t["severity"], 5),
        t["category"],
        t["name"].lower(),
    ))

    return techs


def _extract_ssl_certificates(findings: list) -> list:
    """
    Extract SSL/TLS certificate data from ssl_analyzer findings.
    Returns one entry per port with cert details and any issues.
    """
    certs_by_port: dict = {}  # port → cert dict
    issues_by_port: dict = {}  # port → list of issues

    for f in findings:
        cat = (getattr(f, "category", "") or "").lower()
        ft = (f.finding_type or "").lower()

        if cat != "ssl" and not ft.startswith("ssl_"):
            continue

        details = _safe_dict(f.details_json)
        port = details.get("port") or 443

        # Cert info finding — has full subject/issuer/SANs
        if ft in ("ssl_info",) or "certificate on" in (f.title or "").lower():
            subject = _safe_dict(details.get("subject"))
            issuer = _safe_dict(details.get("issuer"))

            certs_by_port[port] = {
                "port": port,
                "ip": details.get("ip"),
                "subject": subject,
                "commonName": subject.get("CN", ""),
                "issuer": issuer,
                "issuerName": issuer.get("O") or issuer.get("CN") or "Unknown",
                "serialNumber": details.get("serial_number"),
                "notBefore": details.get("not_before"),
                "notAfter": details.get("not_after"),
                "isExpired": details.get("is_expired"),
                "daysUntilExpiry": details.get("days_until_expiry"),
                "isSelfSigned": details.get("is_self_signed"),
                "hostnameMatch": details.get("hostname_match"),
                "sans": _safe_list(details.get("sans")),
                "protocolVersion": details.get("protocol_version"),
                "cipher": details.get("cipher"),
                "lastSeen": f.last_seen_at.isoformat() if f.last_seen_at else None,
                "issues": [],
            }

        # Issue findings — attach to the cert
        if f.severity != "info":
            if port not in issues_by_port:
                issues_by_port[port] = []
            issues_by_port[port].append({
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "findingType": ft,
            })

    # Merge issues into certs
    for port, issues in issues_by_port.items():
        if port in certs_by_port:
            certs_by_port[port]["issues"] = issues
        else:
            # Issues exist but no info finding — create minimal entry
            certs_by_port[port] = {
                "port": port,
                "commonName": "Unknown",
                "issuerName": "Unknown",
                "issues": issues,
                "lastSeen": None,
            }

    # Protocol summary
    protocols = {}
    for f in findings:
        details = _safe_dict(f.details_json)
        if "protocols" in details:
            protocols.update(details["protocols"])

    result = list(certs_by_port.values())
    result.sort(key=lambda c: c.get("port", 0))

    return result


def _extract_dns_records(findings: list) -> dict:
    """
    Extract DNS configuration and email security data from dns_analyzer findings.
    Returns a structured dict with SPF, DMARC, DKIM status and issues.
    """
    dns_info: dict = {
        "spf": None,
        "dmarc": None,
        "dkim": {"found": False, "selectors": []},
        "nameservers": [],
        "hasIpv6": None,
        "zoneTransfer": None,
        "issues": [],
    }

    for f in findings:
        cat = (getattr(f, "category", "") or "").lower()
        ft = (f.finding_type or "").lower()

        if cat != "dns" and not ft.startswith("dns_"):
            continue

        details = _safe_dict(f.details_json)
        title_lower = (f.title or "").lower()

        # SPF
        if "spf" in ft or "spf" in title_lower:
            spf_data = _safe_dict(details.get("spf"))
            if spf_data:
                dns_info["spf"] = {
                    "raw": spf_data.get("raw", ""),
                    "allQualifier": spf_data.get("all_qualifier", ""),
                    "mechanisms": _safe_list(spf_data.get("mechanisms")),
                    "status": "missing" if "no spf" in title_lower else (
                        "fail" if f.severity in ("high", "critical") else
                        "warn" if f.severity == "medium" else "pass"
                    ),
                }
            elif "no spf" in title_lower:
                dns_info["spf"] = {"raw": "", "status": "missing"}

        # DMARC
        if "dmarc" in ft or "dmarc" in title_lower:
            dmarc_data = _safe_dict(details.get("dmarc"))
            if dmarc_data:
                dns_info["dmarc"] = {
                    "raw": dmarc_data.get("raw", ""),
                    "policy": dmarc_data.get("policy", "none"),
                    "rua": dmarc_data.get("rua"),
                    "status": "missing" if "no dmarc" in title_lower else (
                        "fail" if f.severity in ("high", "critical") else
                        "warn" if f.severity == "medium" else "pass"
                    ),
                }
            elif "no dmarc" in title_lower:
                dns_info["dmarc"] = {"raw": "", "policy": "none", "status": "missing"}

        # DKIM
        if "dkim" in ft or "dkim" in title_lower:
            if "no dkim" in title_lower:
                dns_info["dkim"] = {"found": False, "selectors": [], "status": "missing"}
            else:
                dns_info["dkim"]["found"] = True

        # Nameservers
        ns_list = _safe_list(details.get("nameservers"))
        if ns_list:
            dns_info["nameservers"] = ns_list

        # IPv6
        if "ipv6" in title_lower or "aaaa" in title_lower:
            dns_info["hasIpv6"] = "no ipv6" not in title_lower and "no aaaa" not in title_lower

        # Zone transfer
        if "zone transfer" in title_lower or "zone_transfer" in ft:
            zt = _safe_dict(details.get("zone_transfer"))
            dns_info["zoneTransfer"] = {
                "successful": zt.get("successful", "successful" in title_lower),
                "server": zt.get("server"),
                "recordsCount": zt.get("records_count"),
            }

        # Collect all issues
        if f.severity != "info":
            dns_info["issues"].append({
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "findingType": ft,
            })

    # Sort issues by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    dns_info["issues"].sort(key=lambda i: sev_order.get(i["severity"], 5))

    return dns_info


def _extract_ports(findings: list) -> list:
    """
    Extract port/service inventory from findings.
    Combines data from Shodan open_port findings and nmap results.
    """
    port_map: dict = {}  # key: (ip, port, transport) → port dict

    for f in findings:
        ft = (f.finding_type or "").lower()
        details = _safe_dict(f.details_json)

        # Open port findings from Shodan/nmap
        if ft in ("open_port", "port_risk", "exposed_service"):
            ip = details.get("ip") or ""
            port = details.get("port")
            transport = details.get("transport") or "tcp"

            if port is None:
                continue

            key = (ip, port, transport)

            if key not in port_map:
                port_map[key] = {
                    "ip": ip,
                    "port": port,
                    "transport": transport,
                    "product": details.get("product") or "",
                    "version": details.get("version") or "",
                    "service": details.get("service_label") or details.get("product") or "",
                    "severity": f.severity or "info",
                    "title": f.title,
                    "banner": details.get("banner"),
                    "cpe": details.get("cpe"),
                    "lastSeen": f.last_seen_at.isoformat() if f.last_seen_at else None,
                }
            else:
                existing = port_map[key]
                # Merge — keep higher severity, newer data
                if not existing["product"] and details.get("product"):
                    existing["product"] = details["product"]
                if not existing["version"] and details.get("version"):
                    existing["version"] = details["version"]

        # Technology findings also have port info
        if ft == "technology_detected" and details.get("port"):
            ip = ""
            port = details.get("port")
            transport = "tcp"
            key = (ip, port, transport)

            if key not in port_map:
                port_map[key] = {
                    "ip": ip,
                    "port": port,
                    "transport": transport,
                    "product": details.get("technology") or "",
                    "version": details.get("version") or "",
                    "service": details.get("technology") or "",
                    "severity": "info",
                    "title": f"Port {port}/{transport}",
                    "lastSeen": f.last_seen_at.isoformat() if f.last_seen_at else None,
                }

    ports = list(port_map.values())
    ports.sort(key=lambda p: (p["ip"], p["port"]))

    return ports


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@intelligence_bp.get("/<int:asset_id>/intelligence")
@require_auth
def get_asset_intelligence(asset_id: int):
    """
    Aggregate technology, SSL, DNS, and port intelligence for an asset.
    All data comes from existing findings — no new scanning needed.
    """
    org_id = current_organization_id()

    # Verify asset belongs to org
    asset = Asset.query.filter_by(id=asset_id, organization_id=org_id).first()
    if not asset:
        return jsonify(error="asset not found"), 404

    findings = _get_latest_findings(asset_id, org_id)

    technologies = _extract_technologies(findings)
    certificates = _extract_ssl_certificates(findings)
    dns = _extract_dns_records(findings)
    ports = _extract_ports(findings)

    # Category summary counts
    tech_categories: dict = {}
    for t in technologies:
        cat = t["category"]
        tech_categories[cat] = tech_categories.get(cat, 0) + 1

    return jsonify(
        assetId=str(asset_id),
        assetValue=asset.value,
        assetType=asset.asset_type,
        technologies=technologies,
        techCategories=tech_categories,
        techCount=len(technologies),
        outdatedCount=sum(1 for t in technologies if t.get("isOutdated")),
        certificates=certificates,
        dns=dns,
        ports=ports,
        portCount=len(ports),
    ), 200