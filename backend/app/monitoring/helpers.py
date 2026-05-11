# backend/app/monitoring/helpers.py
"""
Helpers for the monitoring change-detector.

should_alert_on_recurrence
    Returns the effective alert-on-recurrence policy for a monitor.
    Per-monitor override wins; falls back to the org default. Used by
    change_detector to decide whether to suppress new_finding alerts
    for findings whose first_seen_at predates the current scan.
"""

from __future__ import annotations

from app.models import Monitor, Organization


def should_alert_on_recurrence(monitor: Monitor, org: Organization) -> bool:
    """True if this monitor should fire alerts on recurring findings.

    Monitor-level override has priority. NULL override = inherit org default.
    """
    if monitor.alert_on_recurrence_override is not None:
        return bool(monitor.alert_on_recurrence_override)
    return bool(org.alert_on_recurrence)
