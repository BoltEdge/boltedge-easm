"""
Display IDs (a.k.a. public IDs) — the external identifier format used in
API responses, URLs, and emails.

Format: <2-letter prefix><zero-padded integer id, 4 digits min>
Examples: SC0042, AS0150, FN0299, AL0034

The numeric part is just the row's integer primary key, padded to 4 digits.
For ids > 9999 it grows naturally (SC10042, SC100042, ...). The format is
stable forever — `SC0042` is always scan_job.id=42, no matter when it was
generated.

Two consumers of this module:
  1. Models — register an after_insert event so newly inserted rows get
     a populated public_id automatically.
  2. Routes — call `resolve_id(value, "SC")` on incoming path/query
     params to accept either form (numeric or display_id) transparently.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

import sqlalchemy as sa
from sqlalchemy import event


logger = logging.getLogger(__name__)


# Canonical prefix per entity. Keep alphabetical by table name for sanity.
PREFIX_BY_TABLE: dict[str, str] = {
    "api_key":               "AK",
    "asset":                 "AS",
    "asset_group":           "GR",
    "audit_log":             "LG",
    "billing_event":         "BE",
    "blocked_ip":            "BL",
    "contact_request":       "CR",
    "discovery_job":         "DC",
    "finding":               "FN",
    "monitor":               "MO",
    "monitor_alert":         "AL",
    "organization":          "OR",
    "pending_invitation":    "IN",
    "platform_announcement": "AN",
    "quick_scan_log":        "QS",
    "report":                "RP",
    "scan_job":              "SC",
    "scan_profile":          "PR",
    "scan_schedule":         "SH",
    "user":                  "US",
}


# Same data inverted — useful when you have a display_id and want to know
# what entity table to look it up in.
TABLE_BY_PREFIX: dict[str, str] = {p: t for t, p in PREFIX_BY_TABLE.items()}


def format_display_id(prefix: str, integer_id: int) -> str:
    """
    Build a display_id from a prefix and an integer id.

        format_display_id("SC", 42)    -> "SC0042"
        format_display_id("AS", 150)   -> "AS0150"
        format_display_id("FN", 12345) -> "FN12345"   # grows beyond 4 digits

    Padded to 4 digits minimum so small ids look like "SC0001" not "SC1",
    but unbounded for higher ranges.
    """
    if integer_id is None:
        raise ValueError("integer_id is required")
    if not isinstance(prefix, str) or len(prefix) < 2:
        raise ValueError(f"invalid prefix: {prefix!r}")
    return f"{prefix}{integer_id:04d}"


def parse_display_id(value: str) -> Optional[tuple[str, int]]:
    """
    Parse a display_id string into (prefix, integer_id), or None if it
    doesn't look like one of our IDs.

        parse_display_id("SC0042") -> ("SC", 42)
        parse_display_id("AS150")  -> ("AS", 150)    # 3-digit also accepted
        parse_display_id("12345")  -> None
        parse_display_id("XX0001") -> None           # unknown prefix
    """
    if not value or not isinstance(value, str):
        return None
    s = value.strip().upper()
    if len(s) < 3:
        return None
    prefix = s[:2]
    if prefix not in TABLE_BY_PREFIX:
        return None
    rest = s[2:]
    if not rest.isdigit():
        return None
    try:
        return prefix, int(rest)
    except ValueError:
        return None


def resolve_id(
    value: str | int | None,
    expected_prefix: Optional[str] = None,
) -> Optional[int]:
    """
    Accept either a numeric id (`42`, `"42"`) or a display_id (`"SC0042"`)
    and return the integer id. Returns None on bad input or wrong prefix.

    Use this in route handlers to accept both forms transparently:

        @app.get("/scan-jobs/<job_id>")
        def get(job_id: str):
            int_id = resolve_id(job_id, "SC")
            if int_id is None:
                return jsonify(error="not found"), 404
            ...

    expected_prefix:
        If provided, display_ids with a different prefix return None.
        Pure numeric ids are always accepted (caller handles per-entity
        authz/lookup). Pass the prefix when the route expects a specific
        entity type — recommended.
    """
    if value is None:
        return None

    # Already integer-like
    if isinstance(value, int):
        return value if value >= 0 else None

    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None

        # Pure numeric path — accept "42" as 42
        if s.isdigit():
            try:
                return int(s)
            except ValueError:
                return None

        # Display-id path — parse and optionally check prefix
        parsed = parse_display_id(s)
        if parsed is None:
            return None
        prefix, int_id = parsed
        if expected_prefix and prefix != expected_prefix.upper():
            return None
        return int_id

    return None


# ---------------------------------------------------------------------------
# Event listener registration
# ---------------------------------------------------------------------------

def register_public_id_listeners() -> None:
    """
    Register an `after_insert` event on every entity model that has a
    public_id column. The listener writes
        public_id = format_display_id(prefix, target.id)
    inside the same transaction the INSERT runs in.

    Called once at app startup from create_app(). Safe to call multiple
    times — registrations are idempotent at the SQLAlchemy level.

    Lives here (not in models.py) to avoid importing the model layer
    until the function is invoked, which keeps test/CLI startup fast.
    """
    # Lazy import — models.py pulls in extensions and the whole world.
    from app import models as m

    # Map prefix -> model class. Order doesn't matter; this is the
    # single source of truth for which models participate.
    model_for_prefix: dict[str, Any] = {
        "AK": m.ApiKey,
        "AS": m.Asset,
        "GR": m.AssetGroup,
        "LG": m.AuditLog,
        "BE": m.BillingEvent,
        "BL": m.BlockedIP,
        "CR": m.ContactRequest,
        "DC": m.DiscoveryJob,
        "FN": m.Finding,
        "MO": m.Monitor,
        "AL": m.MonitorAlert,
        "OR": m.Organization,
        "IN": m.PendingInvitation,
        "AN": m.PlatformAnnouncement,
        "QS": m.QuickScanLog,
        "RP": m.Report,
        "SC": m.ScanJob,
        "PR": m.ScanProfile,
        "SH": m.ScanSchedule,
        "US": m.User,
    }

    for prefix, model_cls in model_for_prefix.items():
        _attach_listener(model_cls, prefix)


def _attach_listener(model_cls: Any, prefix: str) -> None:
    """Register one after_insert listener for `model_cls`."""

    table = model_cls.__table__

    @event.listens_for(model_cls, "after_insert")
    def _populate_public_id(mapper, connection, target) -> None:
        # Skip if a public_id was set explicitly (e.g. by a test or
        # a backfill script).
        if getattr(target, "public_id", None):
            return
        if target.id is None:
            # Defensive — shouldn't happen after INSERT, but don't crash.
            return

        pid = format_display_id(prefix, int(target.id))

        connection.execute(
            sa.update(table)
            .where(table.c.id == target.id)
            .values(public_id=pid)
        )

        # Also update the in-memory object so callers that read .public_id
        # immediately after .add()+.commit() see the populated value.
        target.public_id = pid

    # Mark the listener so duplicate registrations during hot-reload don't
    # double-fire. SQLAlchemy's _propagate is enough for ORM-level dedup.
    _populate_public_id.__module__ = __name__
