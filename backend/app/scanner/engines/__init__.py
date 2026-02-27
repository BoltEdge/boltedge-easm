# app/scanner/engines/__init__.py
"""
Data collection engines.
Each engine collects raw data from a single source.
Engines do NOT classify severity â€” they only gather facts.
"""
from app.scanner.engines.shodan_engine import ShodanEngine
from app.scanner.engines.ssl_engine import SSLEngine
from app.scanner.engines.http_engine import HTTPEngine
from app.scanner.engines.dns_engine import DNSEngine
from app.scanner.engines.nmap_engine import NmapEngine
from app.scanner.engines.nuclei_engine import NucleiEngine
from app.scanner.engines.db_probe_engine import DBProbeEngine
from app.scanner.engines.cloud_asset_engine import CloudAssetEngine
from app.scanner.engines.leak_engine import LeakEngine

# Registry of all available engines.
# The orchestrator uses this to know what's available.
ALL_ENGINES = {
    "shodan": ShodanEngine,
    "ssl": SSLEngine,
    "http": HTTPEngine,
    "dns": DNSEngine,
    "nmap": NmapEngine,
    "nuclei": NucleiEngine,
    "db_probe": DBProbeEngine,
    "cloud_asset": CloudAssetEngine,
    "leak": LeakEngine,
}

__all__ = [
    "ShodanEngine", "SSLEngine", "HTTPEngine", "DNSEngine",
    "NmapEngine", "NucleiEngine", "DBProbeEngine", "CloudAssetEngine",
    "LeakEngine",
    "ALL_ENGINES",
]