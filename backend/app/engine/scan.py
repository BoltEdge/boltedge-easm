from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import shodan


# ---------------------------
# Data shapes
# ---------------------------

@dataclass
class ServiceObservation:
    ip: str
    port: int
    transport: str = "tcp"
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    ssl: Optional[Dict[str, Any]] = None
    http: Optional[Dict[str, Any]] = None
    hostnames: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    raw: Optional[Dict[str, Any]] = None


@dataclass
class Observations:
    asset_type: str
    asset_value: str
    scanned_at: datetime
    resolved_ips: List[str] = field(default_factory=list)
    ips_scanned: List[str] = field(default_factory=list)
    services: List[ServiceObservation] = field(default_factory=list)
    vulns: Dict[str, Any] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class FindingDraft:
    finding_type: str
    severity: str
    title: str
    description: str
    detected_at: datetime
    evidence: Dict[str, Any] = field(default_factory=dict)
    source: str = "shodan"


@dataclass
class UnifiedScanResult:
    summary: Dict[str, Any]
    risk: Dict[str, Any]
    findings: List[Dict[str, Any]]


# ---------------------------
# Shodan + DNS helpers
# ---------------------------

def _now_utc() -> datetime:
    return datetime.utcnow().replace(tzinfo=timezone.utc)


def _get_shodan_client() -> shodan.Shodan:
    key = os.getenv("SHODAN_API_KEY")
    if not key:
        raise RuntimeError("SHODAN_API_KEY not set.")
    return shodan.Shodan(key)


def shodan_host_lookup(ip: str) -> Dict[str, Any]:
    return _get_shodan_client().host(ip)


def resolve_domain_to_ips(domain: str) -> List[str]:
    d = (domain or "").strip().lower()
    if d.startswith("*."):
        d = d[2:]
    if not d:
        return []
    ips: List[str] = []
    try:
        for *_rest, sockaddr in socket.getaddrinfo(d, None):
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        return []
    return ips


# ---------------------------
# Transform to observations
# ---------------------------

def shodan_hosts_to_observations(
    *,
    asset_type: str,
    asset_value: str,
    scanned_at: datetime,
    resolved_ips: List[str],
    host_payloads: List[Dict[str, Any]],
    errors: List[Dict[str, Any]],
) -> Observations:
    obs = Observations(
        asset_type=asset_type,
        asset_value=asset_value,
        scanned_at=scanned_at,
        resolved_ips=resolved_ips,
        errors=errors,
    )

    for host in host_payloads:
        ip = host.get("ip_str") or host.get("ip")
        if ip and ip not in obs.ips_scanned:
            obs.ips_scanned.append(ip)

        vulns = host.get("vulns")
        if isinstance(vulns, dict):
            obs.vulns.update(vulns)

        for item in host.get("data") or []:
            try:
                port = int(item.get("port"))
            except Exception:
                continue

            obs.services.append(
                ServiceObservation(
                    ip=str(ip) if ip else "unknown",
                    port=port,
                    transport=item.get("transport") or "tcp",
                    product=item.get("product"),
                    version=item.get("version"),
                    banner=item.get("data"),
                    ssl=item.get("ssl"),
                    http=item.get("http"),
                    hostnames=item.get("hostnames") or [],
                    domains=item.get("domains") or [],
                    tags=item.get("tags") or [],
                    raw=item,
                )
            )

    return obs


# ---------------------------
# Detectors (minimal set)
# ---------------------------

RISKY_PORTS: Dict[int, Dict[str, str]] = {
    23: {"label": "Telnet", "severity": "high"},
    445: {"label": "SMB", "severity": "high"},
    3389: {"label": "RDP", "severity": "high"},
    5900: {"label": "VNC", "severity": "medium"},
    6379: {"label": "Redis", "severity": "high"},
    9200: {"label": "Elasticsearch", "severity": "high"},
    27017: {"label": "MongoDB", "severity": "high"},
}


def detect_service_exposure(obs: Observations) -> List[FindingDraft]:
    out: List[FindingDraft] = []
    now = obs.scanned_at

    for s in obs.services:
        sev = "low" if (s.product or s.banner) else "info"
        endpoint = f"{s.ip}:{s.port}/{s.transport}"
        prod = f"{(s.product or '').strip()} {(s.version or '').strip()}".strip()
        title = f"Open network service detected: {endpoint}" + (f" ({prod})" if prod else "")

        out.append(
            FindingDraft(
                finding_type="service_exposure",
                severity=sev,
                title=title,
                description=(s.banner or f"A public service was observed on {endpoint}.")[:900],
                detected_at=now,
                evidence={
                    "ip": s.ip,
                    "port": s.port,
                    "transport": s.transport,
                    "product": s.product,
                    "version": s.version,
                    "banner": (s.banner or "")[:900],
                    "ssl": s.ssl,
                    "http": s.http,
                    "raw": s.raw,
                },
            )
        )
    return out


def detect_risky_ports(obs: Observations) -> List[FindingDraft]:
    out: List[FindingDraft] = []
    now = obs.scanned_at

    for s in obs.services:
        rule = RISKY_PORTS.get(int(s.port))
        if not rule:
            continue
        out.append(
            FindingDraft(
                finding_type="risky_port",
                severity=rule["severity"],
                title=f"Risky port exposed: {rule['label']} ({s.port}/{s.transport})",
                description="A commonly targeted or high-impact service port appears exposed to the internet.",
                detected_at=now,
                evidence={"ip": s.ip, "port": s.port, "transport": s.transport, "service_label": rule["label"]},
            )
        )
    return out


def _severity_from_cvss(cvss: Optional[float]) -> str:
    if cvss is None:
        return "high"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def detect_vulns(obs: Observations) -> List[FindingDraft]:
    out: List[FindingDraft] = []
    now = obs.scanned_at

    for cve_id, blob in (obs.vulns or {}).items():
        cvss = None
        if isinstance(blob, dict):
            try:
                cvss = float(blob.get("cvss") or blob.get("cvss_score"))
            except Exception:
                cvss = None
        out.append(
            FindingDraft(
                finding_type="cve",
                severity=_severity_from_cvss(cvss),
                title=f"Known vulnerability observed: {cve_id}",
                description="Shodan reports a known vulnerability (CVE) associated with the target host/service.",
                detected_at=now,
                evidence={"cve": cve_id, "cvss": cvss, "shodan_vuln": blob},
            )
        )
    return out


DETECTORS = [detect_service_exposure, detect_risky_ports, detect_vulns]


def _summarize_risk(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = (f.get("severity") or "info").lower()
        if s not in counts:
            s = "info"
        counts[s] += 1

    order = ["critical", "high", "medium", "low", "info"]
    max_sev = "info"
    for o in order:
        if counts[o] > 0:
            max_sev = o
            break

    return {"counts": counts, "totalFindings": sum(counts.values()), "maxSeverity": max_sev}


def run_unified_scan(
    *,
    asset_type: str,
    value: str,
    shodan_host_lookup_fn: Callable[[str], Dict[str, Any]] = shodan_host_lookup,
    max_ips: int = 5,
) -> UnifiedScanResult:
    if asset_type not in {"ip", "domain"}:
        raise RuntimeError("type must be ip or domain")

    scanned_at = _now_utc()
    resolved_ips: List[str] = []
    ips_to_scan: List[str] = []

    if asset_type == "ip":
        ips_to_scan = [value]
    else:
        resolved_ips = resolve_domain_to_ips(value)
        if not resolved_ips:
            raise RuntimeError(f"domain resolution failed for {value}")
        ips_to_scan = resolved_ips[: max(1, int(max_ips))]

    host_payloads: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for ip in ips_to_scan:
        try:
            host_payloads.append(shodan_host_lookup_fn(ip))
        except Exception as e:
            errors.append({"ip": ip, "error": str(e)})

    obs = shodan_hosts_to_observations(
        asset_type=asset_type,
        asset_value=value,
        scanned_at=scanned_at,
        resolved_ips=resolved_ips,
        host_payloads=host_payloads,
        errors=errors,
    )

    drafts: List[FindingDraft] = []
    for det in DETECTORS:
        try:
            drafts.extend(det(obs) or [])
        except Exception as e:
            obs.errors.append({"detector": getattr(det, "__name__", "unknown"), "error": str(e)})

    findings = [
        {
            "source": d.source,
            "finding_type": d.finding_type,
            "severity": (d.severity or "info").lower(),
            "title": d.title,
            "description": d.description or "",
            "details_json": d.evidence,
            "detected_at": d.detected_at.isoformat() if d.detected_at else None,
        }
        for d in drafts
    ]

    summary = {
        "asset": {"type": asset_type, "value": value},
        "resolved_ips": resolved_ips,
        "ips_scanned": obs.ips_scanned,
        "errors": obs.errors,
        "scanned_at": scanned_at.isoformat(),
    }

    risk = _summarize_risk(findings)
    return UnifiedScanResult(summary=summary, risk=risk, findings=findings)
