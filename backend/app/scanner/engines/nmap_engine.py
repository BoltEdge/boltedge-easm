# app/scanner/engines/nmap_engine.py
"""
Nmap port scanning engine.

Wraps python-nmap to perform real-time port scanning against targets.
Provides more accurate and current data than Shodan's cached results.

Requirements:
    - nmap binary installed on the server (apt install nmap / brew install nmap)
    - python-nmap pip package (pip install python-nmap)

What this engine collects:
    - Open ports with service identification
    - Service version detection (-sV)
    - OS fingerprinting (-O) when running as root
    - Script output for common checks
    - Port states (open, closed, filtered)

Output data structure (stored in EngineResult.data):
    {
        "services": [
            {
                "ip": "1.2.3.4",
                "port": 443,
                "transport": "tcp",
                "state": "open",
                "product": "nginx",
                "version": "1.21.0",
                "extrainfo": "Ubuntu",
                "cpe": "cpe:/a:nginx:nginx:1.21.0",
                "scripts": {}
            }
        ],
        "os_matches": [
            {"name": "Linux 5.4", "accuracy": 95}
        ],
        "scan_info": {
            "tcp": {"method": "syn", "services": "1-1000"}
        },
        "host_status": "up",
        "scanned_ips": ["1.2.3.4"]
    }

Profile config options (from ScanProfile):
    port_range:     str   — "top100", "top1000", "all", or custom "80,443,8080" (default: "top1000")
    scan_type:      str   — "quick", "standard", "deep" (default: "standard")
    version_detect: bool  — run service version detection -sV (default: True)
    os_detect:      bool  — run OS fingerprinting -O (default: False, needs root)
    timeout:        int   — host timeout in seconds (default: 120)
    timing:         int   — nmap timing template 0-5, T4 is default (default: 4)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from app.scanner.base import BaseEngine, EngineResult, ScanContext

logger = logging.getLogger(__name__)

# Check if python-nmap is available
_HAS_NMAP = False
try:
    import nmap
    _HAS_NMAP = True
except ImportError:
    logger.info("python-nmap not available — Nmap engine will be disabled")

# Port range presets
PORT_RANGES = {
    "top100": "--top-ports 100",
    "top1000": "--top-ports 1000",
    "top5000": "--top-ports 5000",
    "all": "-p-",
    "common_web": "-p 80,443,8080,8443,3000,8000,8888,9090",
    "common_all": "-p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1434,1521,2049,2375,2376,3306,3389,5432,5900,5984,6379,8080,8443,9200,9300,11211,27017",
}


class NmapEngine(BaseEngine):
    """
    Real-time port scanning using Nmap.

    Falls back gracefully if nmap binary or python-nmap package
    is not available — returns EngineResult with success=False
    and a descriptive error message.

    Profile config:
        port_range:     Port range preset or custom string
        scan_type:      "quick" | "standard" | "deep"
        version_detect: Enable -sV service detection
        os_detect:      Enable -O OS fingerprinting (needs root)
        timeout:        Per-host timeout in seconds
        timing:         Nmap timing template (0-5)
    """

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def supported_asset_types(self) -> List[str]:
        return ["domain", "ip"]

    def execute(self, ctx: ScanContext, config: Dict[str, Any]) -> EngineResult:
        result = EngineResult(engine_name=self.name)

        if not _HAS_NMAP:
            result.success = False
            result.add_error(
                "python-nmap not installed. Run: pip install python-nmap. "
                "Also ensure nmap binary is installed on the server."
            )
            return result

        # --- Config ---
        scan_type = config.get("scan_type", "standard")
        port_range = config.get("port_range", "top1000")
        version_detect = config.get("version_detect", True)
        os_detect = config.get("os_detect", False)
        timeout = config.get("timeout", 120)
        timing = config.get("timing", 4)

        # --- Determine targets ---
        targets: List[str] = []
        if ctx.asset_type == "ip":
            targets = [ctx.asset_value]
        elif ctx.asset_type == "domain":
            if ctx.resolved_ips:
                targets = ctx.resolved_ips[:3]
            else:
                # Let nmap resolve it
                targets = [ctx.asset_value]

        if not targets:
            result.success = False
            result.add_error("No targets to scan")
            return result

        # --- Build nmap arguments ---
        nmap_args = self._build_args(
            scan_type=scan_type,
            port_range=port_range,
            version_detect=version_detect,
            os_detect=os_detect,
            timeout=timeout,
            timing=timing,
        )

        # --- Run scan ---
        try:
            scanner = nmap.PortScanner()
        except nmap.PortScannerError as e:
            result.success = False
            result.add_error(f"Nmap binary not found: {e}. Install nmap on the server.")
            return result

        all_services: List[Dict[str, Any]] = []
        os_matches: List[Dict[str, Any]] = []
        scanned_ips: List[str] = []
        scan_errors: List[Dict[str, str]] = []

        for target in targets:
            try:
                logger.info(f"Nmap scanning {target} with args: {nmap_args}")
                scanner.scan(hosts=target, arguments=nmap_args)

                for host in scanner.all_hosts():
                    scanned_ips.append(host)

                    # Host status
                    host_state = scanner[host].state()

                    if host_state != "up":
                        scan_errors.append({"ip": host, "error": f"Host state: {host_state}"})
                        continue

                    # Services
                    for proto in scanner[host].all_protocols():
                        ports = scanner[host][proto].keys()
                        for port in sorted(ports):
                            port_info = scanner[host][proto][port]

                            service = {
                                "ip": host,
                                "port": int(port),
                                "transport": proto,
                                "state": port_info.get("state", "unknown"),
                                "product": port_info.get("product", "") or None,
                                "version": port_info.get("version", "") or None,
                                "extrainfo": port_info.get("extrainfo", "") or None,
                                "reason": port_info.get("reason", ""),
                                "name": port_info.get("name", ""),
                                "cpe": port_info.get("cpe", "") or None,
                                "scripts": port_info.get("script", {}),
                            }

                            # Only include open ports
                            if service["state"] == "open":
                                all_services.append(service)

                    # OS detection results
                    if os_detect and "osmatch" in scanner[host]:
                        for match in scanner[host]["osmatch"]:
                            os_matches.append({
                                "name": match.get("name", "Unknown"),
                                "accuracy": int(match.get("accuracy", 0)),
                            })

            except nmap.PortScannerError as e:
                error_msg = str(e)
                scan_errors.append({"ip": target, "error": error_msg})
                result.add_error(f"Nmap scan failed for {target}: {error_msg}")
                logger.warning(f"Nmap scan failed for {target}: {error_msg}")

            except Exception as e:
                error_msg = str(e)
                scan_errors.append({"ip": target, "error": error_msg})
                result.add_error(f"Nmap error for {target}: {error_msg}")
                logger.warning(f"Nmap error for {target}: {error_msg}")

        # If ALL targets failed
        if not all_services and not scanned_ips:
            result.success = False
            return result

        result.data = {
            "services": all_services,
            "os_matches": os_matches[:5],  # Top 5 OS guesses
            "scan_info": dict(scanner.scaninfo()) if hasattr(scanner, "scaninfo") else {},
            "scanned_ips": scanned_ips,
            "errors": scan_errors,
        }

        result.metadata = {
            "nmap_version": scanner.nmap_version() if hasattr(scanner, "nmap_version") else "unknown",
            "arguments": nmap_args,
            "targets_scanned": len(scanned_ips),
            "targets_failed": len(scan_errors),
            "ports_found": len(all_services),
            "scan_type": scan_type,
        }

        return result

    def _build_args(
        self,
        scan_type: str,
        port_range: str,
        version_detect: bool,
        os_detect: bool,
        timeout: int,
        timing: int,
    ) -> str:
        """Build nmap command-line arguments from config."""
        args: List[str] = []

        # Timing template
        timing = max(0, min(5, timing))
        args.append(f"-T{timing}")

        # Port range
        if port_range in PORT_RANGES:
            args.append(PORT_RANGES[port_range])
        elif port_range:
            # Custom port range: "80,443,8080" or "1-1000"
            args.append(f"-p {port_range}")
        else:
            args.append("--top-ports 1000")

        # Scan type adjustments
        if scan_type == "quick":
            # Fast scan — skip version detection, use SYN scan
            args.append("-sS")  # SYN scan (needs root, falls back to connect)
            args.append("--max-retries 1")

        elif scan_type == "standard":
            # Balanced scan
            if version_detect:
                args.append("-sV")
                args.append("--version-intensity 5")

        elif scan_type == "deep":
            # Thorough scan
            if version_detect:
                args.append("-sV")
                args.append("--version-intensity 9")
            # Run default scripts
            args.append("-sC")

        else:
            # Default to standard
            if version_detect:
                args.append("-sV")

        # OS detection (needs root/admin)
        if os_detect:
            args.append("-O")
            args.append("--osscan-limit")  # Only try if at least 1 open + 1 closed port

        # Host timeout
        args.append(f"--host-timeout {timeout}s")

        # Don't resolve DNS (we already have IPs)
        args.append("-n")

        return " ".join(args)