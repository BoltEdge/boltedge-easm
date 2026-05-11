# backend/app/findings/helpers.py
"""
Shared helpers for the findings module.

mark_resolved
    Centralised resolve-write path. Sets resolved/resolved_at/_by/_reason
    and stamps previously_resolved_at on the first resolution (never
    overwritten on subsequent resolves). Both PATCH /findings/<id> and
    POST /findings/bulk-status route through here so the provenance
    history is consistent.

derive_provenance
    Pure function returning one of: "new" | "seen_before" |
    "resolved_before". Priority: resolved_before > new > seen_before.
    Used by every endpoint that serialises a Finding for the UI.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.models import Finding


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def mark_resolved(f: Finding, user_id: int, reason: str | None) -> None:
    """Set the resolve fields and stamp previously_resolved_at if first time.

    Idempotent on previously_resolved_at — re-resolving a row never
    moves the timestamp. The resolved/resolved_at fields ARE updated
    every call so they reflect the most recent resolution.
    """
    now = _now_utc()
    if f.previously_resolved_at is None:
        f.previously_resolved_at = now
    f.resolved = True
    f.resolved_at = now
    f.resolved_by = user_id
    f.resolved_reason = (reason or "")[:500] or None


def derive_provenance(f: Finding) -> str:
    """Return the provenance tag for a finding.

    Priority order:
        1. resolved_before  — was ever resolved (regardless of current status)
        2. new              — first_seen_at == last_seen_at (single scan)
        3. seen_before      — first_seen_at < last_seen_at (multiple scans)
    """
    if f.previously_resolved_at is not None:
        return "resolved_before"
    if f.first_seen_at is not None and f.first_seen_at == f.last_seen_at:
        return "new"
    return "seen_before"
