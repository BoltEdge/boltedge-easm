# app/scanner/engines/shodan_engine.py
"""
Shodan data collection engine.

Refactored from the original app/engine.py into the BaseEngine contract.

What this engine does:
    1. Takes a domain or IP from ScanContext
    2. Resolves domain → IPs (if needed)
    3. Calls Shodan host lookup API for each resolved IP
    4. Normalizes the raw response into a clean data structure

What this engine does NOT do:
    - Classify severity (that's the analyzers' job)
    - Create findings (that's the analyzers' job)
    - Decide what's risky (that's the analyzers' job)

Output data structure (stored in EngineResult.data):
    {
        "resolved_ips": ["1.2.3.4"],
        "ips_scanned": ["1.2.3.4"],
        "services": [
            {
                "ip": "1.2.3.4",
                "port": 443,
                "transport": "tcp",
                "product": "nginx",
                "version": "1.21.0",
                "banner": "HTTP/1.1 200 OK...",
                "ssl": { ... },           # Shodan SSL data if present
                "http": { ... },           # Shodan HTTP data if present
                "hostnames": ["example.com"],
                "domains": ["example.com"],
                "tags": [],
            },
            ...
        ],
        "vulns": {
            "CVE-2021-44228": {"cvss": 10.0, ...},
            ...
        },
        "hostnames": ["example.com", "www.example.com"],
        "os": "Linux",
        "org": "Cloudflare, Inc.",
        "isp": "Cloudflare, Inc.",
        "raw_hosts": [ ... ]   # Full Shodan payloads for deep analysis
    }
"""

from __future__ import annotations

import logging
import os
import socket
from typing import Any, Dict, List

from app.scanner.base import BaseEngine, EngineResult, ScanContext

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers (carried over from app/engine.py)
# ---------------------------------------------------------------------------

def _get_shodan_client():
    """Create a Shodan API client. Raises RuntimeError if key not set."""
    try:
        import shodan
    except ImportError:
        raise RuntimeError("shodan package not installed. Run: pip install shodan")

    key = os.getenv("SHODAN_API_KEY")
    if not key:
        raise RuntimeError(
            "SHODAN_API_KEY environment variable not set. "
            "Get a key at https://account.shodan.io/"
        )
    return shodan.Shodan(key)


def _resolve_domain_to_ips(domain: str) -> List[str]:
    """
    Resolve a domain to its IP addresses using DNS.
    Returns empty list on failure (never raises).
    """
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
    except Exception as e:
        logger.warning(f"DNS resolution failed for {domain}: {e}")
        return []
    return ips


# ---------------------------------------------------------------------------
# Shodan Engine
# ---------------------------------------------------------------------------

class ShodanEngine(BaseEngine):
    """
    Collects host intelligence from the Shodan API.

    Shodan provides:
    - Open ports and running services (with product/version/banner)
    - Known CVEs associated with the host
    - SSL certificate data (if HTTPS is running)
    - HTTP response data
    - Historical scan data
    - Organization and ISP info

    Profile config options (passed via config dict):
        include_history:  bool — fetch historical Shodan data (default: False)
        include_cves:     bool — include CVE data (default: True)
        include_dns:      bool — include DNS/subdomain data (default: False)
        max_ips:          int  — max IPs to scan for domains (default: 3)
    """

    @property
    def name(self) -> str:
        return "shodan"

    @property
    def supported_asset_types(self) -> List[str]:
        return ["domain", "ip", "cloud"]

    def execute(self, ctx: ScanContext, config: Dict[str, Any]) -> EngineResult:
        """
        Query Shodan for host data.

        Steps:
            1. Determine IPs to scan (use resolved_ips from ctx, or resolve now)
            2. Call Shodan host lookup for each IP
            3. Normalize into clean data structure
        """
        result = EngineResult(engine_name=self.name)

        # --- Config ---
        max_ips = config.get("max_ips", 3)
        include_history = config.get("include_history", False)
        include_cves = config.get("include_cves", True)

        # --- Determine IPs to scan ---
        ips_to_scan: List[str] = []

        if ctx.asset_type == "ip":
            ips_to_scan = [ctx.asset_value]
        elif ctx.asset_type == "domain":
            # Use already-resolved IPs from context, or resolve now
            if ctx.resolved_ips:
                ips_to_scan = ctx.resolved_ips[:max_ips]
            else:
                resolved = _resolve_domain_to_ips(ctx.asset_value)
                if not resolved:
                    result.success = False
                    result.add_error(f"DNS resolution failed for {ctx.asset_value}")
                    return result
                ctx.resolved_ips = resolved
                ips_to_scan = resolved[:max_ips]

        
        elif ctx.asset_type == "cloud":
            # Cloud assets: use already-resolved IPs from orchestrator
            if ctx.resolved_ips:
                ips_to_scan = ctx.resolved_ips[:max_ips]
            else:
                result.success = False
                result.add_error(f"No resolved IPs for cloud asset {ctx.asset_value}")
                return result
        else:
            result.success = False
            result.add_error(f"Unsupported asset type: {ctx.asset_type}")
            return result

        # --- Query Shodan for each IP ---
        try:
            api = _get_shodan_client()
        except RuntimeError as e:
            result.success = False
            result.add_error(str(e))
            return result

        host_payloads: List[Dict[str, Any]] = []
        scan_errors: List[Dict[str, str]] = []

        for ip in ips_to_scan:
            try:
                host_data = api.host(ip, history=include_history)
                host_payloads.append(host_data)
            except Exception as e:
                error_msg = str(e)
                scan_errors.append({"ip": ip, "error": error_msg})
                result.add_error(f"Shodan lookup failed for {ip}: {error_msg}")
                logger.warning(f"Shodan lookup failed for {ip}: {error_msg}")

        # If ALL IPs failed, mark as unsuccessful
        if not host_payloads and scan_errors:
            result.success = False
            return result

        # --- Normalize into clean structure ---
        result.data = self._normalize_hosts(
            host_payloads=host_payloads,
            resolved_ips=ctx.resolved_ips,
            include_cves=include_cves,
        )
        result.data["errors"] = scan_errors

        # Metadata for tracking
        result.metadata = {
            "ips_queried": len(ips_to_scan),
            "ips_successful": len(host_payloads),
            "ips_failed": len(scan_errors),
            "include_history": include_history,
            "api_key_set": True,
        }

        return result

    def _normalize_hosts(
        self,
        host_payloads: List[Dict[str, Any]],
        resolved_ips: List[str],
        include_cves: bool,
    ) -> Dict[str, Any]:
        """
        Transform raw Shodan host payloads into a clean, normalized structure
        that analyzers can easily consume.
        """
        services: List[Dict[str, Any]] = []
        vulns: Dict[str, Any] = {}
        all_hostnames: List[str] = []
        ips_scanned: List[str] = []
        os_info = None
        org_info = None
        isp_info = None

        for host in host_payloads:
            ip = host.get("ip_str") or host.get("ip") or "unknown"
            if ip not in ips_scanned:
                ips_scanned.append(ip)

            # Top-level host info
            if not os_info and host.get("os"):
                os_info = host["os"]
            if not org_info and host.get("org"):
                org_info = host["org"]
            if not isp_info and host.get("isp"):
                isp_info = host["isp"]

            # Hostnames
            for h in (host.get("hostnames") or []):
                if h and h not in all_hostnames:
                    all_hostnames.append(h)

            # Vulns (CVEs)
            if include_cves:
                host_vulns = host.get("vulns") or {}
                if isinstance(host_vulns, dict):
                    vulns.update(host_vulns)
                elif isinstance(host_vulns, list):
                    # Sometimes Shodan returns vulns as a list of CVE strings
                    for cve_id in host_vulns:
                        if cve_id not in vulns:
                            vulns[cve_id] = {}

            # Services (from the "data" array)
            for item in (host.get("data") or []):
                try:
                    port = int(item.get("port"))
                except (TypeError, ValueError):
                    continue

                service = {
                    "ip": str(ip),
                    "port": port,
                    "transport": item.get("transport") or "tcp",
                    "product": item.get("product"),
                    "version": item.get("version"),
                    "banner": (item.get("data") or "")[:2000],  # Cap banner size
                    "ssl": item.get("ssl"),
                    "http": item.get("http"),
                    "hostnames": item.get("hostnames") or [],
                    "domains": item.get("domains") or [],
                    "tags": item.get("tags") or [],
                    "cpe": item.get("cpe") or [],
                    "timestamp": item.get("timestamp"),
                }
                services.append(service)

        return {
            "resolved_ips": resolved_ips,
            "ips_scanned": ips_scanned,
            "services": services,
            "vulns": vulns,
            "hostnames": all_hostnames,
            "os": os_info,
            "org": org_info,
            "isp": isp_info,
            "raw_hosts": host_payloads,  # Keep full payloads for deep analysis
        }