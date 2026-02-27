# app/monitoring/tuning_engine.py
"""
Tuning engine — evaluates findings against an organization's TuningRules.

Used by the change-detection pipeline to decide whether a new/changed finding
should generate an alert, be suppressed, or have its severity adjusted.

Usage:
    from app.monitoring.tuning_engine import apply_tuning

    result = apply_tuning(finding, asset, org_id)
    # result.action  → "allow" | "suppress" | "downgrade" | "upgrade" | "snooze"
    # result.severity → adjusted severity (for downgrade/upgrade) or original
    # result.rule    → the matched TuningRule (or None)
    # result.reason  → rule.reason if matched

Matching priority (most specific wins):
    1. Exact asset + exact template + exact port
    2. Exact asset + exact template
    3. Group + template
    4. Asset pattern + template
    5. Org-wide template
    6. Org-wide category
    7. Wildcard

All enabled rules for the org are loaded once and evaluated in-memory.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from app.models import TuningRule, Asset, Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class TuningResult:
    action: str = "allow"               # allow, suppress, downgrade, upgrade, snooze
    severity: str = "info"              # final severity after adjustment
    rule: Optional[TuningRule] = None   # matched rule (None = no match → allow)
    reason: Optional[str] = None        # rule reason
    specificity: int = 0                # higher = more specific match


# ---------------------------------------------------------------------------
# Specificity scoring
# ---------------------------------------------------------------------------

def _specificity(rule: TuningRule) -> int:
    """
    Calculate how specific a rule is. Higher score = more specific = wins ties.

    Weights:
        asset_id exact   → 100
        group_id         → 50
        asset_pattern    → 30
        template_id exact→ 40
        template_id glob → 20
        category         → 10
        port             → 15
        service_name     → 12
        cwe              → 12
        severity_match   → 8
        title_contains   → 5
    """
    score = 0
    if rule.asset_id:
        score += 100
    if rule.group_id:
        score += 50
    if rule.asset_pattern:
        score += 30
    if rule.template_id:
        if "*" in (rule.template_id or ""):
            score += 20
        else:
            score += 40
    if rule.category:
        score += 10
    if rule.port:
        score += 15
    if rule.service_name:
        score += 12
    if rule.cwe:
        score += 12
    if rule.severity_match:
        score += 8
    if rule.title_contains:
        score += 5
    return score


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------

def _matches_template(rule_template: str | None, finding_template: str | None) -> bool:
    """Match template_id with wildcard support. None means 'any'."""
    if not rule_template:
        return True  # no constraint
    if not finding_template:
        return False  # rule requires a template but finding has none

    if rule_template == "*":
        return True

    # fnmatch handles glob patterns: "dns-*", "port-*-exposed", etc.
    return fnmatch.fnmatch(finding_template.lower(), rule_template.lower())


def _matches_asset_pattern(pattern: str | None, asset_value: str | None) -> bool:
    """Match asset value against a glob pattern like '*.staging.example.com'."""
    if not pattern:
        return True  # no constraint
    if not asset_value:
        return False
    return fnmatch.fnmatch(asset_value.lower(), pattern.lower())


def _extract_port_from_finding(finding: Finding) -> int | None:
    """Try to extract port number from finding details."""
    details = finding.details_json or {}
    # Common locations where port might be stored
    port = details.get("port")
    if port is not None:
        try:
            return int(port)
        except (ValueError, TypeError):
            pass
    return None


def _extract_service_from_finding(finding: Finding) -> str | None:
    """Try to extract service name from finding details."""
    details = finding.details_json or {}
    return details.get("service") or details.get("service_name") or details.get("product")


def _rule_matches_finding(
    rule: TuningRule,
    finding: Finding,
    asset: Asset,
) -> bool:
    """
    Check if ALL conditions on a rule match the finding+asset.
    Empty/None conditions are treated as 'any' (always match).
    ALL non-None conditions must match for the rule to apply.
    """

    # Template ID (with wildcard)
    if not _matches_template(rule.template_id, finding.template_id):
        return False

    # Category
    if rule.category:
        if (finding.category or "").lower() != rule.category.lower():
            return False

    # Severity
    if rule.severity_match:
        if (finding.severity or "").lower() != rule.severity_match.lower():
            return False

    # Asset ID (exact)
    if rule.asset_id:
        if asset.id != rule.asset_id:
            return False

    # Group ID
    if rule.group_id:
        if asset.group_id != rule.group_id:
            return False

    # Asset pattern (glob)
    if not _matches_asset_pattern(rule.asset_pattern, asset.value):
        return False

    # Port
    if rule.port is not None:
        finding_port = _extract_port_from_finding(finding)
        if finding_port is None or finding_port != rule.port:
            return False

    # Service name
    if rule.service_name:
        finding_service = _extract_service_from_finding(finding)
        if not finding_service or finding_service.lower() != rule.service_name.lower():
            return False

    # CWE
    if rule.cwe:
        if not finding.cwe or finding.cwe.lower() != rule.cwe.lower():
            return False

    # Title contains (case-insensitive substring)
    if rule.title_contains:
        if rule.title_contains.lower() not in (finding.title or "").lower():
            return False

    return True


# ---------------------------------------------------------------------------
# Snooze check
# ---------------------------------------------------------------------------

def _is_snoozed(rule: TuningRule) -> bool:
    """Check if a snooze rule is still active (not expired)."""
    if rule.action != "snooze":
        return False
    if not rule.snooze_until:
        return False
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return rule.snooze_until > now


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def apply_tuning(
    finding: Finding,
    asset: Asset,
    org_id: int,
    rules: list[TuningRule] | None = None,
) -> TuningResult:
    """
    Evaluate a finding against the org's tuning rules.

    Args:
        finding: The Finding to evaluate.
        asset: The Asset the finding belongs to.
        org_id: Organization ID.
        rules: Optional pre-loaded rules (for batch processing).
               If None, rules are loaded from the database.

    Returns:
        TuningResult with the action to take.
    """
    if rules is None:
        rules = TuningRule.query.filter_by(
            organization_id=org_id,
            enabled=True,
        ).all()

    if not rules:
        return TuningResult(action="allow", severity=finding.severity)

    best_match: TuningRule | None = None
    best_specificity = -1

    for rule in rules:
        if not rule.enabled:
            continue

        # Skip expired snooze rules
        if rule.action == "snooze" and not _is_snoozed(rule):
            continue

        if _rule_matches_finding(rule, finding, asset):
            spec = _specificity(rule)
            if spec > best_specificity:
                best_specificity = spec
                best_match = rule

    if not best_match:
        return TuningResult(action="allow", severity=finding.severity)

    # Apply the action
    result = TuningResult(
        action=best_match.action,
        severity=finding.severity,
        rule=best_match,
        reason=best_match.reason,
        specificity=best_specificity,
    )

    if best_match.action == "suppress":
        # Finding is suppressed — no alert should be generated
        pass

    elif best_match.action == "snooze":
        # Finding is snoozed until snooze_until — no alert until then
        pass

    elif best_match.action == "downgrade":
        if best_match.target_severity:
            result.severity = best_match.target_severity

    elif best_match.action == "upgrade":
        if best_match.target_severity:
            result.severity = best_match.target_severity

    return result


def apply_tuning_batch(
    findings_with_assets: list[tuple[Finding, Asset]],
    org_id: int,
) -> dict[int, TuningResult]:
    """
    Batch evaluate multiple findings against tuning rules.
    Loads rules once and applies to all findings.

    Args:
        findings_with_assets: List of (Finding, Asset) tuples.
        org_id: Organization ID.

    Returns:
        Dict mapping finding.id → TuningResult.
    """
    rules = TuningRule.query.filter_by(
        organization_id=org_id,
        enabled=True,
    ).all()

    results = {}
    for finding, asset in findings_with_assets:
        results[finding.id] = apply_tuning(finding, asset, org_id, rules=rules)

    return results


def get_effective_severity(
    finding: Finding,
    asset: Asset,
    org_id: int,
    rules: list[TuningRule] | None = None,
) -> str:
    """
    Convenience function: returns the effective severity after tuning.
    If suppressed or snoozed, returns the original severity (caller decides
    whether to skip the alert).
    """
    result = apply_tuning(finding, asset, org_id, rules=rules)
    return result.severity


def should_alert(
    finding: Finding,
    asset: Asset,
    org_id: int,
    rules: list[TuningRule] | None = None,
) -> tuple[bool, TuningResult]:
    """
    Convenience function: returns (should_generate_alert, tuning_result).

    An alert should NOT be generated if:
        - action is 'suppress'
        - action is 'snooze' (and snooze is still active)
    """
    result = apply_tuning(finding, asset, org_id, rules=rules)
    generate = result.action not in ("suppress", "snooze")
    return generate, result