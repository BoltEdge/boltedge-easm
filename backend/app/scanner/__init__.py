# app/scanner/__init__.py
"""
XternSec Detection Engine — M7

Usage:
    from app.scanner import ScanOrchestrator

    orchestrator = ScanOrchestrator()
    result = orchestrator.execute(job, profile)

Architecture:
    Orchestrator
    ├── Engines (collect raw data)
    │   ├── ShodanEngine    — host intelligence from Shodan API
    │   ├── NmapEngine      — (future) real-time port scanning
    │   ├── SSLEngine       — (future) certificate & TLS checks
    │   ├── HTTPEngine      — (future) HTTP probe & headers
    │   ├── DNSEngine       — (future) DNS record analysis
    │   └── WHOISEngine     — (future) domain registration data
    │
    └── Analyzers (interpret data → produce findings)
        ├── PortRiskAnalyzer — classify open ports by risk
        ├── SSLAnalyzer      — (future) SSL/TLS issues
        ├── HeaderAnalyzer   — (future) HTTP security headers
        ├── CVEEnricher      — (future) enrich CVE data
        ├── TechDetector     — (future) technology fingerprinting
        └── ExposureScorer   — (future) overall exposure score
"""

from app.scanner.orchestrator import ScanOrchestrator

__all__ = ["ScanOrchestrator"]