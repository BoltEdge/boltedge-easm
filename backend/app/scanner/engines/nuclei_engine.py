# app/scanner/engines/nuclei_engine.py
"""
Nuclei vulnerability scanning engine.

Wraps ProjectDiscovery's Nuclei binary to run template-based
vulnerability and misconfiguration checks against targets.

Requirements:
    - nuclei binary installed on the server
      (https://github.com/projectdiscovery/nuclei)
    - nuclei templates updated: nuclei -update-templates

What this engine collects:
    - Template-matched vulnerabilities and misconfigurations
    - Severity from Nuclei's own classification
    - Matched URLs and evidence
    - CVE IDs when available
    - Technology detection results

Output data structure (stored in EngineResult.data):
    {
        "findings": [
            {
                "template_id": "cve-2021-44228-log4j",
                "template_name": "Apache Log4j RCE",
                "severity": "critical",
                "type": "http",
                "host": "https://example.com",
                "matched_at": "https://example.com/api",
                "extracted_results": [],
                "curl_command": "curl ...",
                "matcher_name": "log4j",
                "description": "...",
                "reference": ["https://nvd.nist.gov/..."],
                "tags": ["cve", "rce", "log4j"],
                "classification": {
                    "cve_id": "CVE-2021-44228",
                    "cwe_id": "CWE-502",
                    "cvss_score": 10.0
                }
            }
        ],
        "stats": {
            "templates_run": 1500,
            "findings_count": 3,
            "duration_seconds": 45.2
        }
    }

Profile config options:
    severity_filter:    list  — which severities to scan for (default: all)
    template_tags:      list  — filter templates by tag (e.g., ["cve", "misconfig"])
    rate_limit:         int   — requests per second (default: 150)
    timeout:            int   — per-request timeout in seconds (default: 10)
    bulk_size:          int   — parallel templates (default: 25)
    max_duration:       int   — max total scan time in seconds (default: 300)
    template_exclude:   list  — template IDs to skip
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional

from app.scanner.base import BaseEngine, EngineResult, ScanContext

logger = logging.getLogger(__name__)


def _find_nuclei_binary() -> Optional[str]:
    """Find the nuclei binary on the system."""
    # Check if it's in PATH
    binary = shutil.which("nuclei")
    if binary:
        return binary

    # Check common locations
    common_paths = [
        "/usr/local/bin/nuclei",
        "/usr/bin/nuclei",
        os.path.expanduser("~/go/bin/nuclei"),
        os.path.expanduser("~/.local/bin/nuclei"),
    ]
    for path in common_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    return None


class NucleiEngine(BaseEngine):
    """
    Template-based vulnerability scanning using Nuclei.

    Nuclei runs thousands of community and custom templates against
    the target to detect known CVEs, misconfigurations, exposed panels,
    default credentials, and more.

    Falls back gracefully if nuclei binary is not found.

    Profile config:
        severity_filter:  List of severities to include
        template_tags:    Tags to filter templates
        rate_limit:       Requests per second
        timeout:          Per-request timeout
        max_duration:     Maximum scan duration
    """

    @property
    def name(self) -> str:
        return "nuclei"

    @property
    def supported_asset_types(self) -> List[str]:
        return ["domain", "ip"]

    def execute(self, ctx: ScanContext, config: Dict[str, Any]) -> EngineResult:
        result = EngineResult(engine_name=self.name)

        # Find nuclei binary
        nuclei_bin = _find_nuclei_binary()
        if not nuclei_bin:
            result.success = False
            result.add_error(
                "Nuclei binary not found. Install from: "
                "https://github.com/projectdiscovery/nuclei/releases "
                "or run: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            )
            return result

        # --- Config ---
        severity_filter = config.get("severity_filter", ["critical", "high", "medium", "low", "info"])
        template_tags = config.get("template_tags", [])
        rate_limit = config.get("rate_limit", 150)
        timeout_per_req = config.get("timeout", 10)
        bulk_size = config.get("bulk_size", 25)
        max_duration = config.get("max_duration", 300)
        template_exclude = config.get("template_exclude", [])

        # --- Build target URL ---
        target = ctx.asset_value
        if ctx.asset_type == "domain":
            target = f"https://{ctx.asset_value}"

        # --- Build nuclei command ---
        output_file = None
        try:
            # Create temp file for JSON output
            fd, output_file = tempfile.mkstemp(suffix=".json", prefix="nuclei_")
            os.close(fd)

            cmd = self._build_command(
                nuclei_bin=nuclei_bin,
                target=target,
                output_file=output_file,
                severity_filter=severity_filter,
                template_tags=template_tags,
                rate_limit=rate_limit,
                timeout_per_req=timeout_per_req,
                bulk_size=bulk_size,
                template_exclude=template_exclude,
            )

            logger.info(f"Running nuclei: {' '.join(cmd[:5])}...")

            # Run nuclei with timeout
            start_time = time.monotonic()
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max_duration,
                cwd=tempfile.gettempdir(),
            )
            scan_duration = round(time.monotonic() - start_time, 2)

            if proc.returncode not in (0, 1):
                # returncode 1 = findings found (normal)
                # returncode 0 = no findings
                stderr = (proc.stderr or "")[:500]
                if proc.returncode != 0:
                    result.add_error(f"Nuclei exited with code {proc.returncode}: {stderr}")

            # Parse JSON output
            findings = self._parse_output(output_file)

            result.data = {
                "findings": findings,
                "stats": {
                    "findings_count": len(findings),
                    "duration_seconds": scan_duration,
                },
            }

            result.metadata = {
                "nuclei_binary": nuclei_bin,
                "target": target,
                "severity_filter": severity_filter,
                "return_code": proc.returncode,
            }

        except subprocess.TimeoutExpired:
            result.add_error(f"Nuclei scan timed out after {max_duration}s")
            # Still try to parse partial results
            if output_file and os.path.exists(output_file):
                findings = self._parse_output(output_file)
                result.data = {
                    "findings": findings,
                    "stats": {"findings_count": len(findings), "timed_out": True},
                }
            else:
                result.data = {"findings": [], "stats": {"timed_out": True}}

        except Exception as e:
            result.success = False
            result.add_error(f"Nuclei execution failed: {type(e).__name__}: {str(e)}")

        finally:
            # Cleanup temp file
            if output_file and os.path.exists(output_file):
                try:
                    os.unlink(output_file)
                except Exception:
                    pass

        return result

    def _build_command(
        self,
        nuclei_bin: str,
        target: str,
        output_file: str,
        severity_filter: List[str],
        template_tags: List[str],
        rate_limit: int,
        timeout_per_req: int,
        bulk_size: int,
        template_exclude: List[str],
    ) -> List[str]:
        """Build the nuclei command-line arguments."""
        cmd = [
            nuclei_bin,
            "-target", target,
            "-jsonl",                       # JSON lines output
            "-output", output_file,
            "-rate-limit", str(rate_limit),
            "-timeout", str(timeout_per_req),
            "-bulk-size", str(bulk_size),
            "-silent",                      # Minimal console output
            "-no-color",                    # No ANSI colors
            "-no-interactsh",               # Don't use interactsh for OOB testing
        ]

        # Severity filter
        if severity_filter and set(severity_filter) != {"critical", "high", "medium", "low", "info"}:
            cmd.extend(["-severity", ",".join(severity_filter)])

        # Template tags
        if template_tags:
            cmd.extend(["-tags", ",".join(template_tags)])

        # Template exclusions
        for exclude in template_exclude:
            cmd.extend(["-exclude-id", exclude])

        return cmd

    def _parse_output(self, output_file: str) -> List[Dict[str, Any]]:
        """Parse nuclei JSON lines output into structured findings."""
        findings: List[Dict[str, Any]] = []

        if not os.path.exists(output_file):
            return findings

        try:
            with open(output_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        finding = self._normalize_finding(entry)
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.warning(f"Failed to parse nuclei output: {e}")

        return findings

    def _normalize_finding(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalize a single nuclei JSON output entry."""
        info = entry.get("info", {})
        if not info:
            return None

        # Extract classification
        classification = info.get("classification", {}) or {}
        cve_id = classification.get("cve-id")
        if isinstance(cve_id, list):
            cve_id = cve_id[0] if cve_id else None

        cwe_id = classification.get("cwe-id")
        if isinstance(cwe_id, list):
            cwe_id = cwe_id[0] if cwe_id else None

        cvss_score = classification.get("cvss-score")
        if isinstance(cvss_score, str):
            try:
                cvss_score = float(cvss_score)
            except ValueError:
                cvss_score = None

        return {
            "template_id": entry.get("template-id", "unknown"),
            "template_name": info.get("name", "Unknown"),
            "severity": (info.get("severity") or "info").lower(),
            "type": entry.get("type", "http"),
            "host": entry.get("host", ""),
            "matched_at": entry.get("matched-at", ""),
            "extracted_results": entry.get("extracted-results", []),
            "curl_command": entry.get("curl-command", ""),
            "matcher_name": entry.get("matcher-name", ""),
            "description": info.get("description", ""),
            "remediation": info.get("remediation", ""),
            "reference": info.get("reference", []),
            "tags": info.get("tags", []),
            "classification": {
                "cve_id": cve_id,
                "cwe_id": cwe_id,
                "cvss_score": cvss_score,
            },
        }