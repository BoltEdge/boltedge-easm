# app/scanner/analyzers/__init__.py
"""
Finding analyzers.
Each analyzer reads raw engine data and produces FindingDrafts
with proper severity classification and remediation guidance.
Analyzers do NOT collect data â€” they only interpret it.
"""
from app.scanner.analyzers.port_risk import PortRiskAnalyzer
from app.scanner.analyzers.cve_enricher import CVEEnricher
from app.scanner.analyzers.ssl_analyzer import SSLAnalyzer
from app.scanner.analyzers.header_analyzer import HeaderAnalyzer
from app.scanner.analyzers.dns_analyzer import DNSAnalyzer
from app.scanner.analyzers.tech_detector import TechDetector
from app.scanner.analyzers.nuclei_analyzer import NucleiAnalyzer
from app.scanner.analyzers.api_analyzer import APIAnalyzer
from app.scanner.analyzers.exposed_db_analyzer import ExposedDBAnalyzer
from app.scanner.analyzers.cloud_asset_analyzer import CloudAssetAnalyzer
from app.scanner.analyzers.subdomain_takeover_analyzer import SubdomainTakeoverAnalyzer
from app.scanner.analyzers.leak_analyzer import LeakAnalyzer
from app.scanner.analyzers.exposure_scorer import ExposureScorer

# Registry of all available analyzers.
# The orchestrator runs these in order after engines complete.
# ORDER MATTERS: exposure_scorer MUST be last â€” it reads all other findings.
ALL_ANALYZERS = {
    "port_risk": PortRiskAnalyzer,
    "cve_enricher": CVEEnricher,
    "ssl_analyzer": SSLAnalyzer,
    "header_analyzer": HeaderAnalyzer,
    "dns_analyzer": DNSAnalyzer,
    "tech_detector": TechDetector,
    "nuclei_analyzer": NucleiAnalyzer,
    "api_analyzer": APIAnalyzer,
    "exposed_db_analyzer": ExposedDBAnalyzer,
    "cloud_asset_analyzer": CloudAssetAnalyzer,
    "subdomain_takeover": SubdomainTakeoverAnalyzer,    "leak_analyzer": LeakAnalyzer,

    "exposure_scorer": ExposureScorer,     # Always last
}

__all__ = [
    "PortRiskAnalyzer", "CVEEnricher", "SSLAnalyzer",
    "HeaderAnalyzer", "DNSAnalyzer", "TechDetector",
    "NucleiAnalyzer", "APIAnalyzer", "ExposedDBAnalyzer",
    "CloudAssetAnalyzer", "SubdomainTakeoverAnalyzer",
    "LeakAnalyzer", "ExposureScorer", "ALL_ANALYZERS",
]