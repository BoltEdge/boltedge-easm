# app/scanner/analyzers/cve_enricher.py
"""
CVE Enricher Analyzer.

Reads raw vulnerability/CVE data from engines (currently Shodan) and
produces enriched findings with:
    - CVSS-based severity classification
    - Human-readable descriptions
    - Remediation guidance (patch/upgrade)
    - References to NVD and MITRE

Shodan provides CVE data in two forms:
    1. host["vulns"] — dict of CVE IDs (sometimes with CVSS data)
    2. Individual service banners with "vulns" field

This analyzer handles both and deduplicates by CVE ID per asset.

Severity mapping (CVSS v2/v3 → our severity):
    9.0 - 10.0  →  critical
    7.0 -  8.9  →  high
    4.0 -  6.9  →  medium
    0.1 -  3.9  →  low
    0.0 / None  →  high (assume worst when CVSS unknown)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.scanner.base import BaseAnalyzer, FindingDraft, ScanContext

logger = logging.getLogger(__name__)


def _cvss_to_severity(cvss: Optional[float]) -> str:
    """Map a CVSS score to our severity level."""
    if cvss is None:
        # Unknown CVSS — assume high to be safe
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


def _extract_cvss(blob: Any) -> Optional[float]:
    """
    Try to extract a CVSS score from a Shodan vuln blob.
    Shodan's format varies — sometimes it's a dict with "cvss",
    sometimes just a number, sometimes a list of references.
    """
    if blob is None:
        return None

    if isinstance(blob, (int, float)):
        return float(blob)

    if isinstance(blob, dict):
        # Try common field names
        for key in ("cvss", "cvss_score", "cvss3", "cvss_v3", "score"):
            val = blob.get(key)
            if val is not None:
                try:
                    return float(val)
                except (TypeError, ValueError):
                    continue
    return None


def _extract_summary(cve_id: str, blob: Any) -> str:
    """Try to extract a description/summary from the Shodan vuln blob."""
    if isinstance(blob, dict):
        for key in ("summary", "description", "desc"):
            val = blob.get(key)
            if val and isinstance(val, str):
                return val[:1000]

    return (
        f"A known vulnerability ({cve_id}) was detected on this host. "
        "This CVE is associated with services running on the target "
        "and may allow unauthorized access, data exposure, or denial of service."
    )


def _extract_affected_product(blob: Any) -> Optional[str]:
    """Try to extract affected product info from the Shodan vuln blob."""
    if not isinstance(blob, dict):
        return None

    for key in ("product", "affected", "component", "software"):
        val = blob.get(key)
        if val and isinstance(val, str):
            return val

    # Try CPE if available
    cpe = blob.get("cpe") or blob.get("cpe23")
    if cpe and isinstance(cpe, str):
        # CPE format: cpe:2.3:a:vendor:product:version:...
        parts = cpe.split(":")
        if len(parts) >= 5:
            return f"{parts[3]} {parts[4]}".replace("_", " ")

    return None


class CVEEnricher(BaseAnalyzer):
    """
    Enriches raw CVE data into actionable findings.

    For each CVE found by engines:
        1. Extract CVSS score → map to severity
        2. Build clear title with CVE ID and score
        3. Generate description with context
        4. Add remediation guidance
        5. Link to NVD/MITRE references
        6. Deduplicate on CVE ID (same CVE won't duplicate across scans)
    """

    @property
    def name(self) -> str:
        return "cve_enricher"

    @property
    def required_engines(self) -> List[str]:
        return ["shodan"]

    def analyze(self, ctx: ScanContext) -> List[FindingDraft]:
        drafts: List[FindingDraft] = []

        # Collect CVEs from all engines
        vulns = self._collect_vulns(ctx)

        # Track seen CVE IDs to avoid duplicates within a single scan
        seen_cves: set = set()

        for cve_id, blob in vulns.items():
            cve_id = cve_id.strip().upper()

            # Skip duplicates and non-CVE entries
            if cve_id in seen_cves:
                continue
            if not cve_id.startswith("CVE-"):
                continue
            seen_cves.add(cve_id)

            drafts.append(self._build_cve_finding(cve_id, blob))

        return drafts

    def _collect_vulns(self, ctx: ScanContext) -> Dict[str, Any]:
        """Gather vulnerability data from all engines."""
        vulns: Dict[str, Any] = {}

        # From Shodan
        shodan_data = ctx.get_engine_data("shodan")
        shodan_vulns = shodan_data.get("vulns", {})
        if isinstance(shodan_vulns, dict):
            vulns.update(shodan_vulns)
        elif isinstance(shodan_vulns, list):
            # Sometimes Shodan returns a list of CVE ID strings
            for cve_id in shodan_vulns:
                if isinstance(cve_id, str) and cve_id not in vulns:
                    vulns[cve_id] = {}

        # Future: from Nmap version detection
        # nmap_data = ctx.get_engine_data("nmap")
        # vulns.update(nmap_data.get("vulns", {}))

        return vulns

    def _build_cve_finding(self, cve_id: str, blob: Any) -> FindingDraft:
        """Build an enriched FindingDraft for a single CVE."""
        cvss = _extract_cvss(blob)
        severity = _cvss_to_severity(cvss)
        summary = _extract_summary(cve_id, blob)
        product = _extract_affected_product(blob)

        # Build title
        title = f"Known vulnerability: {cve_id}"
        if cvss is not None:
            title += f" (CVSS {cvss:.1f})"
        if product:
            title += f" — {product}"

        # Build description
        description = summary
        if cvss is not None and summary == _extract_summary(cve_id, None):
            # Default summary — add CVSS context
            description = (
                f"{cve_id} has a CVSS score of {cvss:.1f} ({severity}). "
                + description
            )

        # Build remediation
        remediation = f"Research {cve_id} and apply the vendor's patch or update. "
        if product:
            remediation += f"Check for updates to {product}. "
        remediation += (
            f"See https://nvd.nist.gov/vuln/detail/{cve_id} for full details "
            "and affected versions."
        )

        return FindingDraft(
            template_id=f"cve-{cve_id.lower()}",
            title=title,
            severity=severity,
            category="cve",
            description=description[:2000],
            remediation=remediation,
            finding_type="cve",
            cwe=self._extract_cwe(blob),
            references=[
                f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
            ],
            tags=["cve", severity, cve_id.lower()],
            engine="shodan",
            confidence="high" if cvss is not None else "medium",
            details={
                "cve_id": cve_id,
                "cvss": cvss,
                "severity": severity,
                "summary": summary[:500],
                "affected_product": product,
                "raw_shodan": blob if isinstance(blob, dict) else {},
            },
            dedupe_fields={
                "cve_id": cve_id,
            },
        )

    def _extract_cwe(self, blob: Any) -> Optional[str]:
        """Try to extract CWE reference from the vuln blob."""
        if not isinstance(blob, dict):
            return None

        cwe = blob.get("cwe") or blob.get("cwe_id")
        if cwe and isinstance(cwe, str):
            return cwe

        # Sometimes nested in references
        refs = blob.get("references") or []
        for ref in refs:
            if isinstance(ref, str) and "cwe" in ref.lower():
                # Extract CWE-XXX pattern
                import re
                match = re.search(r"CWE-\d+", ref, re.IGNORECASE)
                if match:
                    return match.group(0).upper()

        return None