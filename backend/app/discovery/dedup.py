"""
Deduplication and correlation engine for discovery results.

Takes raw DiscoveredItem lists from multiple modules and produces
a unified, deduplicated set of discovered assets with source attribution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set

from .base_module import DiscoveredItem


@dataclass
class MergedAsset:
    """A deduplicated asset with data merged from all modules that found it."""
    asset_type: str
    value: str                                          # normalized
    original_value: str                                 # first-seen casing
    sources: List[str] = field(default_factory=list)    # module names
    metadata: dict = field(default_factory=dict)        # merged metadata
    confidence: float = 1.0                             # highest from any module
    is_new: bool = True                                 # not in existing inventory
    related_assets: List[str] = field(default_factory=list)


class DeduplicationEngine:
    """
    Merges discovery results from multiple modules into a unified set.

    Strategy:
    1. Normalize values (lowercase, strip trailing dots, wildcards)
    2. Group by (asset_type, normalized_value)
    3. Merge metadata and track all source modules
    4. Cross-reference with existing inventory to flag new vs known
    """

    def __init__(self, existing_asset_values: Set[str] = None):
        self.existing = existing_asset_values or set()
        self._merged: Dict[str, MergedAsset] = {}

    def add_results(self, items: List[DiscoveredItem]):
        for item in items:
            self._merge_item(item)

    def _merge_item(self, item: DiscoveredItem):
        key = f"{item.asset_type}::{item.normalized_value()}"

        if key in self._merged:
            existing = self._merged[key]
            if item.source_module not in existing.sources:
                existing.sources.append(item.source_module)
            for k, v in (item.metadata or {}).items():
                if k not in existing.metadata:
                    existing.metadata[k] = v
                elif isinstance(existing.metadata[k], list) and isinstance(v, list):
                    for val in v:
                        if val not in existing.metadata[k]:
                            existing.metadata[k].append(val)
            existing.confidence = max(existing.confidence, item.confidence)
        else:
            normalized = item.normalized_value()
            self._merged[key] = MergedAsset(
                asset_type=item.asset_type,
                value=normalized,
                original_value=item.value,
                sources=[item.source_module],
                metadata=dict(item.metadata) if item.metadata else {},
                confidence=item.confidence,
                is_new=normalized not in self.existing,
            )

    def get_results(self) -> List[MergedAsset]:
        results = list(self._merged.values())
        type_order = {"domain": 0, "subdomain": 1, "ip": 2, "ip_range": 3, "cloud": 4, "url": 5}
        results.sort(key=lambda a: (type_order.get(a.asset_type, 99), a.value))
        return results

    def get_stats(self) -> dict:
        results = self.get_results()
        by_type: Dict[str, int] = {}
        for r in results:
            by_type[r.asset_type] = by_type.get(r.asset_type, 0) + 1
        new_count = sum(1 for r in results if r.is_new)
        return {
            "total": len(results),
            "new": new_count,
            "known": len(results) - new_count,
            "by_type": by_type,
            "sources_used": list(set(s for r in results for s in r.sources)),
        }

    def correlate(self):
        """Cross-reference assets to find relationships (subdomain → IP links)."""
        ip_to_subs: Dict[str, List[str]] = {}
        sub_to_ips: Dict[str, List[str]] = {}

        for asset in self._merged.values():
            if asset.asset_type in ("subdomain", "domain"):
                resolved_ips = asset.metadata.get("resolved_ips", [])
                for ip in resolved_ips:
                    ip_to_subs.setdefault(ip, []).append(asset.value)
                    sub_to_ips.setdefault(asset.value, []).append(ip)

        for asset in self._merged.values():
            if asset.asset_type == "ip":
                related = ip_to_subs.get(asset.value, [])
                asset.related_assets = list(set(asset.related_assets + related))
            elif asset.asset_type in ("subdomain", "domain"):
                related = sub_to_ips.get(asset.value, [])
                asset.related_assets = list(set(asset.related_assets + related))