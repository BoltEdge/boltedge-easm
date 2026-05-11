from datetime import datetime, timedelta

from app.findings.helpers import derive_provenance


class _FakeFinding:
    """Minimal stand-in for the Finding model — only fields the helper reads."""
    def __init__(self, first=None, last=None, prev_resolved=None):
        self.first_seen_at = first
        self.last_seen_at = last
        self.previously_resolved_at = prev_resolved


def test_resolved_before_wins_over_new():
    t = datetime(2026, 5, 1)
    f = _FakeFinding(first=t, last=t, prev_resolved=t - timedelta(days=10))
    assert derive_provenance(f) == "resolved_before"


def test_resolved_before_wins_over_seen_before():
    t = datetime(2026, 5, 1)
    f = _FakeFinding(first=t - timedelta(days=2), last=t, prev_resolved=t - timedelta(days=10))
    assert derive_provenance(f) == "resolved_before"


def test_new_when_first_equals_last():
    t = datetime(2026, 5, 1)
    f = _FakeFinding(first=t, last=t, prev_resolved=None)
    assert derive_provenance(f) == "new"


def test_seen_before_when_first_lt_last():
    t = datetime(2026, 5, 1)
    f = _FakeFinding(first=t - timedelta(days=2), last=t, prev_resolved=None)
    assert derive_provenance(f) == "seen_before"


def test_seen_before_when_first_is_null():
    f = _FakeFinding(first=None, last=None, prev_resolved=None)
    assert derive_provenance(f) == "seen_before"
