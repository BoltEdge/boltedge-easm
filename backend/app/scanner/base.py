# app/scanner/base.py
"""
Base classes for the XternSec detection engine pipeline.

Architecture:
    ScanContext flows through:  Engines → Analyzers → FindingGenerator

BaseEngine:   Collects raw data from a source (Shodan, Nmap, SSL, HTTP, DNS, WHOIS).
              Engines NEVER classify severity — they only gather facts.

BaseAnalyzer: Interprets raw engine data and produces FindingDrafts with
              proper severity classification and remediation guidance.
              Analyzers NEVER collect data — they only interpret it.

This separation means:
  - You can swap Shodan for Censys without touching any security logic
  - You can tune severity rules without changing how data is collected
  - Each component can fail independently without crashing the whole scan
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_utc() -> datetime:
    """Timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Data structures — these flow through the entire pipeline
# ---------------------------------------------------------------------------

@dataclass
class EngineResult:
    """
    Standardized output from any engine run.

    Every engine (Shodan, Nmap, SSL, etc.) returns one of these.
    The orchestrator stores it in ScanContext.engine_results[engine_name].

    Fields:
        engine_name:      Which engine produced this (e.g., "shodan", "ssl")
        success:          Did the engine complete without fatal errors?
        data:             Raw collected data — structure varies per engine.
                          Example for Shodan: {"services": [...], "vulns": {...}}
                          Example for SSL:    {"certificates": [...], "protocols": [...]}
        errors:           Non-fatal error messages (e.g., "timeout on port 8443")
        duration_seconds: Wall-clock time the engine took
        metadata:         Extra info like API credits used, IPs scanned, etc.
    """
    engine_name: str
    success: bool = True
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_error(self, msg: str):
        self.errors.append(msg)


@dataclass
class FindingDraft:
    """
    A finding produced by an analyzer, ready to be persisted to the DB.

    This is the standard contract between analyzers and the finding generator.
    Every analyzer outputs a list of these. The orchestrator then deduplicates
    and persists them as Finding model rows.

    Fields:
        template_id:    Unique template key, e.g., "ssl-cert-expired", "port-rdp-exposed".
                        Used for deduplication and for linking to finding templates.
        title:          Human-readable title shown in the UI.
        severity:       One of: critical, high, medium, low, info.
        category:       Grouping: ssl, ports, headers, cve, dns, tech, exposure.
        description:    What was found — shown in the finding detail dialog.
        remediation:    How to fix it — shown as guidance to the user.
        finding_type:   Maps to Finding.finding_type in the DB. Defaults to template_id.
        cwe:            Optional CWE reference (e.g., "CWE-295").
        references:     URLs for more info.
        tags:           Freeform tags for filtering.
        details:        Evidence dict — stored as Finding.details_json.
        dedupe_fields:  Key fields for deduplication. The finding generator hashes these
                        together with org_id + asset_id + template_id to build dedupe_key.
        engine:         Which engine's data this finding came from.
        analyzer:       Which analyzer produced this finding.
        confidence:     How confident are we? high / medium / low.
        detected_at:    When the issue was observed.
    """
    # Required
    template_id: str
    title: str
    severity: str                       # critical, high, medium, low, info
    category: str                       # ssl, ports, headers, cve, dns, tech, exposure, cloud
    description: str

    # Enrichment (optional)
    remediation: Optional[str] = None
    finding_type: Optional[str] = None
    cwe: Optional[str] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # Evidence
    details: Dict[str, Any] = field(default_factory=dict)

    # Deduplication — the generator hashes these to build dedupe_key
    dedupe_fields: Dict[str, Any] = field(default_factory=dict)

    # Source tracking
    engine: str = ""
    analyzer: str = ""
    confidence: str = "high"            # high, medium, low

    # Timing
    detected_at: Optional[datetime] = None

    def __post_init__(self):
        if self.detected_at is None:
            self.detected_at = now_utc()
        if not self.finding_type:
            self.finding_type = self.template_id


@dataclass
class ScanContext:
    """
    The data bag that flows through the entire scan pipeline.

    Created by the orchestrator at the start of a scan. Engines write their
    results into engine_results. Analyzers read from engine_results and write
    their findings into finding_drafts. The finding generator reads
    finding_drafts and persists them to the DB.

    This is the ONLY way data moves between pipeline stages.
    """
    # Target (set once, never changed)
    asset_id: int
    asset_type: str                     # domain, ip, email
    asset_value: str                    # e.g., "example.com", "1.2.3.4"
    organization_id: int
    scan_job_id: int

    # Resolved during scan setup (before engines run)
    resolved_ips: List[str] = field(default_factory=list)

    # Engine outputs (populated as engines complete)
    engine_results: Dict[str, EngineResult] = field(default_factory=dict)

    # Analyzer outputs (populated as analyzers complete)
    finding_drafts: List[FindingDraft] = field(default_factory=list)

    # Discovery metadata (populated by orchestrator from discovery results).
    # Used by engines that need context from the discovery layer, e.g.
    # cloud_asset engine reads cloud_candidates generated by cloud_enum.
    discovery_metadata: Dict[str, Any] = field(default_factory=dict)

    # For change detection (loaded from last completed scan)
    previous_scan_data: Optional[Dict[str, Any]] = None

    # Timing
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    def get_engine_data(self, engine_name: str) -> Dict[str, Any]:
        """
        Get raw data from a specific engine.
        Returns empty dict if engine didn't run or failed.
        Safe to call without checking — never raises.
        """
        result = self.engine_results.get(engine_name)
        if result and result.success:
            return result.data
        return {}

    def has_engine_data(self, engine_name: str) -> bool:
        """Check if a specific engine ran successfully and has data."""
        result = self.engine_results.get(engine_name)
        return result is not None and result.success and bool(result.data)


# ---------------------------------------------------------------------------
# Abstract base classes
# ---------------------------------------------------------------------------

class BaseEngine(ABC):
    """
    Abstract base for data collection engines.

    To create a new engine:
        1. Subclass BaseEngine
        2. Set the `name` property (e.g., "shodan", "ssl", "http")
        3. Implement `execute(ctx, config) -> EngineResult`
        4. Optionally override `supported_asset_types` if not domain+ip

    The base class handles automatically:
        - Timing (duration_seconds is set automatically)
        - Error catching (exceptions become EngineResult with success=False)
        - Asset type validation (skips if asset type not supported)
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique engine identifier. Used as key in ScanContext.engine_results."""
        ...

    @property
    def supported_asset_types(self) -> List[str]:
        """Which asset types this engine can scan. Override to restrict."""
        return ["domain", "ip"]

    def can_scan(self, ctx: ScanContext) -> bool:
        """Check if this engine supports the target's asset type."""
        return ctx.asset_type in self.supported_asset_types

    def run(self, ctx: ScanContext, config: Dict[str, Any] | None = None) -> EngineResult:
        """
        Execute the engine with automatic timing and error handling.

        DO NOT OVERRIDE THIS METHOD. Override `execute()` instead.

        Returns EngineResult — always, even on failure.
        """
        if not self.can_scan(ctx):
            return EngineResult(
                engine_name=self.name,
                success=False,
                errors=[f"Engine '{self.name}' does not support asset type '{ctx.asset_type}'"],
            )

        config = config or {}
        result = EngineResult(engine_name=self.name)
        start = time.monotonic()

        try:
            result = self.execute(ctx, config)
            result.engine_name = self.name
        except Exception as e:
            logger.exception(f"Engine '{self.name}' failed for {ctx.asset_value}")
            result = EngineResult(
                engine_name=self.name,
                success=False,
                errors=[f"{type(e).__name__}: {str(e)}"],
            )
        finally:
            result.duration_seconds = round(time.monotonic() - start, 2)

        return result

    @abstractmethod
    def execute(self, ctx: ScanContext, config: Dict[str, Any]) -> EngineResult:
        """
        Perform the actual data collection. Override this in subclasses.

        Args:
            ctx:    ScanContext with target info. Read ctx.asset_value, ctx.asset_type,
                    ctx.resolved_ips as needed.
            config: Engine-specific config from the scan profile.
                    Example for Nmap: {"port_range": "top1000", "version_detect": True}

        Returns:
            EngineResult with raw data in result.data.
            The data structure is engine-specific — the matching analyzer knows how to read it.
        """
        ...


class BaseAnalyzer(ABC):
    """
    Abstract base for finding analyzers.

    To create a new analyzer:
        1. Subclass BaseAnalyzer
        2. Set the `name` property (e.g., "port_risk", "ssl_analyzer")
        3. Set `required_engines` to list which engines you need data from
        4. Implement `analyze(ctx) -> List[FindingDraft]`

    The base class handles automatically:
        - Checking if required engine data exists (skips gracefully if not)
        - Error catching (exceptions return empty list, never crash the scan)
        - Auto-tagging all FindingDrafts with the analyzer name
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique analyzer identifier."""
        ...

    @property
    def required_engines(self) -> List[str]:
        """
        Which engines must have data for this analyzer to run.
        Uses OR logic: analyzer runs if ANY of these have data.
        Return empty list if the analyzer can always run.
        """
        return []

    def can_run(self, ctx: ScanContext) -> bool:
        """Check if at least one required engine has data."""
        if not self.required_engines:
            return True
        return any(ctx.has_engine_data(e) for e in self.required_engines)

    def run(self, ctx: ScanContext) -> List[FindingDraft]:
        """
        Execute the analyzer with error handling.

        DO NOT OVERRIDE THIS METHOD. Override `analyze()` instead.

        Returns list of FindingDrafts, or empty list on error/skip.
        """
        if not self.can_run(ctx):
            logger.debug(
                f"Analyzer '{self.name}' skipped: no data from required engines "
                f"{self.required_engines}"
            )
            return []

        try:
            drafts = self.analyze(ctx)
            # Auto-tag all drafts with this analyzer's name
            for d in drafts:
                if not d.analyzer:
                    d.analyzer = self.name
            return drafts
        except Exception as e:
            logger.exception(f"Analyzer '{self.name}' failed for asset {ctx.asset_value}")
            return []

    @abstractmethod
    def analyze(self, ctx: ScanContext) -> List[FindingDraft]:
        """
        Perform analysis on engine data and return finding drafts.

        Read raw data via:  ctx.get_engine_data("engine_name")
        Return a list of FindingDraft objects with severity, remediation, etc.
        """
        ...