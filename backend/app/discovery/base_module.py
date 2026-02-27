"""
Base class for all discovery modules.

Every discovery source (CT logs, DNS, VirusTotal, etc.) implements this interface.
The orchestrator calls discover() on each module and aggregates the results.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List
from enum import Enum

logger = logging.getLogger(__name__)


class ModuleType(Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


PLAN_RANK = {
    "free": 0,
    "starter": 1,
    "professional": 2,
    "enterprise_silver": 3,
    "enterprise_gold": 4,
}


@dataclass
class DiscoveredItem:
    """
    Standard output from any discovery module.
    Every module returns a list of these. The orchestrator deduplicates
    and correlates them across modules before storing.
    """
    asset_type: str          # domain / subdomain / ip / ip_range / cloud / url
    value: str               # e.g. "api.example.com"
    source_module: str       # e.g. "ct_logs"
    metadata: dict = field(default_factory=dict)
    confidence: float = 1.0  # 0.0 to 1.0

    def normalized_value(self) -> str:
        """Normalize value for deduplication."""
        v = self.value.strip().lower()
        if v.endswith("."):
            v = v[:-1]
        if v.startswith("*."):
            v = v[2:]
        return v


class BaseDiscoveryModule(ABC):
    """
    Abstract base class for discovery modules.

    To add a new discovery source:
    1. Create a new file in app/discovery/modules/
    2. Subclass BaseDiscoveryModule
    3. Implement discover() and set class attributes
    4. Register in app/discovery/modules/__init__.py REGISTRY
    """

    name: str = "base"
    description: str = ""
    module_type: ModuleType = ModuleType.PASSIVE
    requires_api_key: bool = False
    min_plan: str = "free"
    supported_target_types: tuple = ("domain",)

    @abstractmethod
    def discover(self, target: str, target_type: str, config: dict = None) -> List[DiscoveredItem]:
        """Run discovery against the target and return found assets."""
        pass

    def is_available(self) -> bool:
        """Check if this module can run (API key configured, etc.)."""
        return True

    def supports_target_type(self, target_type: str) -> bool:
        return target_type in self.supported_target_types

    def is_allowed_for_plan(self, plan: str) -> bool:
        return PLAN_RANK.get(plan, 0) >= PLAN_RANK.get(self.min_plan, 0)

    def get_rate_limit_status(self) -> dict:
        return {"remaining": None, "limit": None, "resets_at": None}