# FILE: app/discovery/modules/__init__.py
"""
Discovery module registry.
All modules are registered here. The orchestrator uses this to determine
which modules to run for a given job based on org plan and target type.

Module plan tiers:
  free:          CT Logs, DNS Enum, RapidDNS
  starter:       + WHOIS/ASN, HackerTarget, AlienVault OTX, Web Archive, ASN/Org, Shodan
  professional+: + ThreatCrowd, Cloud Enum

Target types supported:
  domain:   CT Logs, DNS Enum, RapidDNS, WHOIS/ASN, HackerTarget, AlienVault OTX, Web Archive, ThreatCrowd, Shodan, Cloud Enum
  ip:       DNS Enum, WHOIS/ASN, HackerTarget, AlienVault OTX, ThreatCrowd, Shodan
  asn:      ASN/Org
  org_name: ASN/Org
  cidr:     CIDR Enum
"""
from __future__ import annotations

from typing import List, Type

from ..base_module import BaseDiscoveryModule
from .ct_logs import CTLogModule
from .dns_enum import DNSEnumModule
from .rapiddns import RapidDNSModule
from .whois_asn import WHOISASNModule
from .hackertarget import HackerTargetModule
from .alienvault_otx import AlienVaultOTXModule
from .web_archive import WebArchiveModule
from .threatcrowd import ThreatCrowdModule
from .asn_org import ASNOrgModule
from .cidr_enum import CIDREnumModule
from .shodan_search import ShodanDiscoveryModule
from .cloud_enum import CloudEnumModule

# Order matters for display — modules run in parallel regardless.
REGISTRY: List[Type[BaseDiscoveryModule]] = [
    # Free tier
    CTLogModule,            # passive — certificate transparency logs
    DNSEnumModule,          # active  — DNS brute-force + resolution
    RapidDNSModule,         # passive — aggregated DNS data

    # Starter tier
    WHOISASNModule,         # passive — WHOIS, RDAP, ASN/netblock lookup
    HackerTargetModule,     # passive — hostsearch, reverse DNS
    AlienVaultOTXModule,    # passive — passive DNS + URL intelligence
    WebArchiveModule,       # passive — Wayback Machine historical data
    ASNOrgModule,           # passive — ASN & org name → netblocks, IPs, domains
    CIDREnumModule,         # active  — CIDR range → reverse DNS, host discovery
    ShodanDiscoveryModule,  # passive — Shodan API: subdomains, IPs, open ports, services

    # Professional tier
    ThreatCrowdModule,      # passive — OSINT aggregation
    CloudEnumModule,        # passive — cloud asset candidate names (storage, registries, serverless)
]


def get_all_modules() -> List[BaseDiscoveryModule]:
    return [cls() for cls in REGISTRY]


def get_modules_for_plan(plan: str) -> List[BaseDiscoveryModule]:
    return [m for m in get_all_modules() if m.is_allowed_for_plan(plan)]


def get_modules_for_target(plan: str, target_type: str) -> List[BaseDiscoveryModule]:
    """Get modules allowed by plan AND supporting the target type. Used by orchestrator."""
    return [
        m for m in get_all_modules()
        if m.is_allowed_for_plan(plan) and m.supports_target_type(target_type) and m.is_available()
    ]