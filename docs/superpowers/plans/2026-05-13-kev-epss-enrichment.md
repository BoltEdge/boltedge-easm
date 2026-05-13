# KEV + EPSS Finding Enrichment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enrich every CVE-based finding with CISA KEV (actively exploited?) and FIRST.org EPSS (probability of exploitation) data — badge-only, no severity change, with one-time backfill for existing findings.

**Architecture:** One utility module `app/scanner/threat_intel.py` exposes `lookup_kev`, `lookup_epss`, `enrich_cve`, `refresh_kev_feed`. Called by `cve_enricher.py` during live scans and by `scripts/backfill_threat_intel.py` for historical findings. Two new cache tables (`kev_entry`, `epss_cache`) and three new indexed columns on `Finding` (`kev_listed`, `epss_score`, `epss_percentile`). APScheduler runs the daily KEV refresh at 02:00 UTC. Failures are silent — scans never break on threat-intel outages.

**Tech Stack:** Python 3 / Flask / SQLAlchemy / Flask-Migrate / APScheduler / `requests` / pytest. Frontend: Next.js / TypeScript / Tailwind.

**Spec:** `docs/superpowers/specs/2026-05-13-kev-epss-enrichment-design.md`

---

## File map

**Create:**
- `backend/app/scanner/threat_intel.py` — utility module
- `backend/migrations/versions/s7i8j9k0l1m2_kev_epss_threat_intel.py` — migration
- `backend/scripts/backfill_threat_intel.py` — one-time CLI backfill
- `backend/tests/test_threat_intel.py` — unit tests

**Modify:**
- `backend/app/models.py` — add `KevEntry` + `EpssCache` models; add 3 columns to `Finding`
- `backend/app/scanner/base.py` — add 3 optional fields to `FindingDraft`
- `backend/app/scanner/analyzers/cve_enricher.py` — call `enrich_cve()`, set new draft fields, add KEV tag
- `backend/app/scanner/orchestrator.py:803-876` — copy 3 new fields in both update + create branches
- `backend/app/scheduler.py` — register daily KEV refresh job
- `frontend/app/FindingDetailsDialog.tsx` — render KEV badge + EPSS line

---

## Task 1: DB migration + new models

**Files:**
- Create: `backend/migrations/versions/s7i8j9k0l1m2_kev_epss_threat_intel.py`
- Modify: `backend/app/models.py` (add `KevEntry`, `EpssCache`, 3 `Finding` columns)

- [ ] **Step 1: Add `KevEntry` and `EpssCache` models to `models.py`**

Append to `backend/app/models.py` (near the end of the file, after the last model class):

```python
class KevEntry(db.Model):
    """CISA Known Exploited Vulnerabilities — local cache of the feed."""
    __tablename__ = "kev_entry"

    cve_id = db.Column(db.String(20), primary_key=True)
    date_added = db.Column(db.Date, nullable=False)
    vendor = db.Column(db.String(255), nullable=True)
    product = db.Column(db.String(255), nullable=True)
    vulnerability_name = db.Column(db.String(500), nullable=True)
    known_ransomware = db.Column(db.Boolean, nullable=False, default=False)
    required_action = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.Date, nullable=True)
    short_description = db.Column(db.Text, nullable=True)
    fetched_at = db.Column(db.DateTime, nullable=False, default=now_utc)


class EpssCache(db.Model):
    """FIRST.org EPSS scores — per-CVE cache with 7-day TTL."""
    __tablename__ = "epss_cache"

    cve_id = db.Column(db.String(20), primary_key=True)
    score = db.Column(db.Float, nullable=False)
    percentile = db.Column(db.Float, nullable=False)
    model_version = db.Column(db.String(20), nullable=True)
    fetched_at = db.Column(db.DateTime, nullable=False, default=now_utc)
```

- [ ] **Step 2: Add 3 columns to the `Finding` model**

Inside the `Finding` class in `backend/app/models.py`, after the line `template_id = db.Column(...)` (around line 446), add:

```python
    # Threat-intel enrichment — populated by app.scanner.threat_intel
    kev_listed = db.Column(db.Boolean, nullable=False, default=False, index=True)
    epss_score = db.Column(db.Float, nullable=True, index=True)
    epss_percentile = db.Column(db.Float, nullable=True)
```

- [ ] **Step 3: Generate the migration**

```bash
cd backend
$env:SQLALCHEMY_DATABASE_URI = "postgresql://easm_user:localdevpassword@localhost:5432/easm"
$env:SECRET_KEY = "local-dev-secret-key"
$env:FLASK_APP = "manage.py"
python -m flask db migrate -m "kev_epss_threat_intel"
```

Rename the auto-generated file to `s7i8j9k0l1m2_kev_epss_threat_intel.py` for chain stability. Verify the file contains:
- `op.create_table("kev_entry", ...)`
- `op.create_table("epss_cache", ...)`
- Three `op.add_column("finding", ...)` calls
- Two `op.create_index(...)` calls for the indexed Finding columns
- `down_revision = 'r6h7i8j9k0l1'` (the blog_subscribers migration, current head)

If autogenerate gets the column type wrong or omits indexes, hand-edit. Final migration body should look like:

```python
"""kev_epss_threat_intel

Revision ID: s7i8j9k0l1m2
Revises: r6h7i8j9k0l1
Create Date: 2026-05-13
"""
from alembic import op
import sqlalchemy as sa


revision = "s7i8j9k0l1m2"
down_revision = "r6h7i8j9k0l1"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "kev_entry",
        sa.Column("cve_id", sa.String(20), primary_key=True),
        sa.Column("date_added", sa.Date(), nullable=False),
        sa.Column("vendor", sa.String(255), nullable=True),
        sa.Column("product", sa.String(255), nullable=True),
        sa.Column("vulnerability_name", sa.String(500), nullable=True),
        sa.Column("known_ransomware", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("required_action", sa.Text(), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("short_description", sa.Text(), nullable=True),
        sa.Column("fetched_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_kev_entry_fetched_at", "kev_entry", ["fetched_at"])

    op.create_table(
        "epss_cache",
        sa.Column("cve_id", sa.String(20), primary_key=True),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column("model_version", sa.String(20), nullable=True),
        sa.Column("fetched_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_epss_cache_fetched_at", "epss_cache", ["fetched_at"])

    op.add_column(
        "finding",
        sa.Column("kev_listed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_finding_kev_listed", "finding", ["kev_listed"])

    op.add_column("finding", sa.Column("epss_score", sa.Float(), nullable=True))
    op.create_index("ix_finding_epss_score", "finding", ["epss_score"])

    op.add_column("finding", sa.Column("epss_percentile", sa.Float(), nullable=True))


def downgrade():
    op.drop_index("ix_finding_epss_score", table_name="finding")
    op.drop_column("finding", "epss_percentile")
    op.drop_column("finding", "epss_score")
    op.drop_index("ix_finding_kev_listed", table_name="finding")
    op.drop_column("finding", "kev_listed")

    op.drop_index("ix_epss_cache_fetched_at", table_name="epss_cache")
    op.drop_table("epss_cache")
    op.drop_index("ix_kev_entry_fetched_at", table_name="kev_entry")
    op.drop_table("kev_entry")
```

- [ ] **Step 4: Apply the migration locally**

```bash
python -m flask db upgrade
```

Expected: no errors. Verify with:
```bash
psql -h localhost -U easm_user -d easm -c "\d kev_entry; \d epss_cache; \d finding" | grep -E "kev_listed|epss_score|epss_percentile|kev_entry|epss_cache"
```

- [ ] **Step 5: Commit**

```bash
git add backend/app/models.py backend/migrations/versions/s7i8j9k0l1m2_kev_epss_threat_intel.py
git commit -m "feat(scan): add kev_entry, epss_cache, and threat-intel columns on finding"
```

---

## Task 2: `threat_intel.lookup_kev()` — DB read

**Files:**
- Create: `backend/app/scanner/threat_intel.py`
- Create: `backend/tests/test_threat_intel.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_threat_intel.py`:

```python
"""Tests for app.scanner.threat_intel.

The module is the single source of truth for CVE-to-KEV / CVE-to-EPSS
lookups. Tests focus on:
  - lookup_kev returns dict when row exists, None when not, None on DB error
  - lookup_epss returns cached value when fresh, fetches when stale, None on API error
  - refresh_kev_feed upserts correctly, handles HTTP failure
  - enrich_cve aggregates both correctly
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.scanner import threat_intel


def _make_kev_row(cve_id="CVE-2024-1234", ransomware=False):
    """Build a stand-in KevEntry-shaped object for tests."""
    return MagicMock(
        cve_id=cve_id,
        date_added=datetime(2024, 5, 1).date(),
        vendor="Acme",
        product="WidgetServer",
        vulnerability_name="Acme WidgetServer RCE",
        known_ransomware=ransomware,
        required_action="Apply patch 1.2.3 or block port 8080",
        due_date=datetime(2024, 6, 1).date(),
        short_description="Remote code execution via crafted Widget header",
        fetched_at=datetime.now(timezone.utc),
    )


def test_lookup_kev_returns_dict_when_listed():
    with patch.object(threat_intel, "_query_kev") as mock_q:
        mock_q.return_value = _make_kev_row(cve_id="CVE-2024-1234")
        result = threat_intel.lookup_kev("CVE-2024-1234")
        assert result is not None
        assert result["cve_id"] == "CVE-2024-1234"
        assert result["vendor"] == "Acme"
        assert result["known_ransomware"] is False
        assert result["date_added"] == "2024-05-01"


def test_lookup_kev_returns_none_when_not_listed():
    with patch.object(threat_intel, "_query_kev") as mock_q:
        mock_q.return_value = None
        assert threat_intel.lookup_kev("CVE-2024-9999") is None


def test_lookup_kev_returns_none_on_db_error():
    with patch.object(threat_intel, "_query_kev") as mock_q:
        mock_q.side_effect = RuntimeError("DB down")
        assert threat_intel.lookup_kev("CVE-2024-1234") is None


def test_lookup_kev_normalises_cve_id_case():
    with patch.object(threat_intel, "_query_kev") as mock_q:
        mock_q.return_value = _make_kev_row(cve_id="CVE-2024-1234")
        threat_intel.lookup_kev("cve-2024-1234")
        # _query_kev should be called with the uppercased form
        mock_q.assert_called_with("CVE-2024-1234")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd backend
pytest tests/test_threat_intel.py::test_lookup_kev_returns_dict_when_listed -v
```

Expected: FAIL — `app.scanner.threat_intel` module does not exist yet.

- [ ] **Step 3: Write the minimal implementation**

Create `backend/app/scanner/threat_intel.py`:

```python
# app/scanner/threat_intel.py
"""
Threat-intel enrichment for CVE findings.

Exposes lookups against two free, authoritative feeds:
  - CISA KEV (Known Exploited Vulnerabilities) — "is this actively exploited?"
  - FIRST.org EPSS (Exploit Prediction Scoring System) — "how likely?"

Used by:
  - app.scanner.analyzers.cve_enricher (live scans)
  - scripts.backfill_threat_intel (one-shot historical enrichment)

All public functions are non-raising — failures (DB error, API timeout,
JSON parse error) return None / falsy so the caller can carry on without
threat-intel data. A scan never fails because the threat-intel layer
is unavailable.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from app.extensions import db
from app.models import KevEntry

logger = logging.getLogger(__name__)


def _query_kev(cve_id: str) -> Optional[KevEntry]:
    """Indirection point so tests can mock the DB hit without app context."""
    return KevEntry.query.filter_by(cve_id=cve_id).first()


def lookup_kev(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Return a serialisable dict of the KEV entry for cve_id, or None if
    not listed / on any error.

    Never raises. Logs at WARNING on DB error.
    """
    if not cve_id:
        return None
    cve_id = cve_id.strip().upper()
    try:
        row = _query_kev(cve_id)
    except Exception:
        logger.exception("threat_intel: kev lookup failed for %s", cve_id)
        return None

    if not row:
        return None

    return {
        "cve_id": row.cve_id,
        "date_added": row.date_added.isoformat() if row.date_added else None,
        "vendor": row.vendor,
        "product": row.product,
        "vulnerability_name": row.vulnerability_name,
        "known_ransomware": bool(row.known_ransomware),
        "required_action": row.required_action,
        "due_date": row.due_date.isoformat() if row.due_date else None,
        "short_description": row.short_description,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_threat_intel.py -v -k lookup_kev
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add backend/app/scanner/threat_intel.py backend/tests/test_threat_intel.py
git commit -m "feat(scan): threat_intel.lookup_kev — DB-backed KEV cache read"
```

---

## Task 3: `threat_intel.refresh_kev_feed()` — HTTP fetch + upsert

**Files:**
- Modify: `backend/app/scanner/threat_intel.py`
- Modify: `backend/tests/test_threat_intel.py`

- [ ] **Step 1: Write the failing test**

Append to `backend/tests/test_threat_intel.py`:

```python
KEV_FIXTURE = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.05.13",
    "dateReleased": "2026-05-13T00:00:00.000Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-1234",
            "vendorProject": "Acme",
            "product": "WidgetServer",
            "vulnerabilityName": "Acme WidgetServer RCE",
            "dateAdded": "2024-05-01",
            "shortDescription": "Remote code execution via crafted Widget header.",
            "requiredAction": "Apply patch 1.2.3.",
            "dueDate": "2024-06-01",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2023-9999",
            "vendorProject": "Foo",
            "product": "Bar",
            "vulnerabilityName": "Foo Bar SQLi",
            "dateAdded": "2023-08-15",
            "shortDescription": "SQL injection.",
            "requiredAction": "Upgrade to 9.1.",
            "dueDate": "2023-09-15",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}


def test_refresh_kev_feed_upserts_rows():
    fake_session = MagicMock()
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = KEV_FIXTURE

    with patch.object(threat_intel.requests, "get", return_value=fake_response) as mock_get, \
         patch.object(threat_intel, "_upsert_kev_rows") as mock_upsert:
        mock_upsert.return_value = 2
        n = threat_intel.refresh_kev_feed()

    assert n == 2
    mock_get.assert_called_once()
    mock_upsert.assert_called_once()
    rows = mock_upsert.call_args[0][0]
    assert len(rows) == 2
    assert rows[0]["cve_id"] == "CVE-2024-1234"
    assert rows[0]["known_ransomware"] is True
    assert rows[1]["known_ransomware"] is False


def test_refresh_kev_feed_returns_zero_on_http_failure():
    with patch.object(threat_intel.requests, "get") as mock_get:
        mock_get.side_effect = threat_intel.requests.RequestException("connection refused")
        n = threat_intel.refresh_kev_feed()
    assert n == 0


def test_refresh_kev_feed_returns_zero_on_malformed_json():
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {"unexpected": "shape"}

    with patch.object(threat_intel.requests, "get", return_value=fake_response):
        n = threat_intel.refresh_kev_feed()
    assert n == 0
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_threat_intel.py -v -k refresh_kev
```

Expected: FAIL — `refresh_kev_feed` not defined.

- [ ] **Step 3: Add `refresh_kev_feed` to `threat_intel.py`**

Insert at top of `backend/app/scanner/threat_intel.py` after the existing imports:

```python
import requests
```

Then append to the file:

```python
KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
KEV_FETCH_TIMEOUT = 10  # seconds


def _parse_date(value: Optional[str]):
    """CISA dates are ISO YYYY-MM-DD. Returns date or None."""
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


def _vuln_to_row(v: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Convert one CISA vulnerability dict into our row shape. Skips bad rows."""
    cve_id = (v.get("cveID") or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return None
    return {
        "cve_id": cve_id,
        "date_added": _parse_date(v.get("dateAdded")),
        "vendor": (v.get("vendorProject") or "")[:255] or None,
        "product": (v.get("product") or "")[:255] or None,
        "vulnerability_name": (v.get("vulnerabilityName") or "")[:500] or None,
        "known_ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
        "required_action": v.get("requiredAction") or None,
        "due_date": _parse_date(v.get("dueDate")),
        "short_description": v.get("shortDescription") or None,
    }


def _upsert_kev_rows(rows: list) -> int:
    """Insert-or-update each row into kev_entry. Returns count upserted."""
    now = datetime.now(timezone.utc)
    upserted = 0
    for r in rows:
        existing = KevEntry.query.filter_by(cve_id=r["cve_id"]).first()
        if existing:
            existing.date_added = r["date_added"]
            existing.vendor = r["vendor"]
            existing.product = r["product"]
            existing.vulnerability_name = r["vulnerability_name"]
            existing.known_ransomware = r["known_ransomware"]
            existing.required_action = r["required_action"]
            existing.due_date = r["due_date"]
            existing.short_description = r["short_description"]
            existing.fetched_at = now
        else:
            db.session.add(KevEntry(fetched_at=now, **r))
        upserted += 1
    db.session.commit()
    return upserted


def refresh_kev_feed() -> int:
    """
    Pull the full CISA KEV JSON and upsert every entry into kev_entry.

    Returns count of rows upserted. Returns 0 on any error — last-known
    DB rows continue to serve until the next successful refresh. Run
    daily via APScheduler.
    """
    try:
        resp = requests.get(KEV_FEED_URL, timeout=KEV_FETCH_TIMEOUT)
        resp.raise_for_status()
        payload = resp.json()
    except requests.RequestException:
        logger.exception("threat_intel: KEV fetch failed")
        return 0
    except ValueError:
        logger.exception("threat_intel: KEV response not valid JSON")
        return 0

    vulns = payload.get("vulnerabilities")
    if not isinstance(vulns, list):
        logger.error("threat_intel: KEV payload missing 'vulnerabilities' list")
        return 0

    rows = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        row = _vuln_to_row(v)
        if row:
            rows.append(row)

    if not rows:
        logger.warning("threat_intel: KEV payload yielded zero valid rows")
        return 0

    try:
        return _upsert_kev_rows(rows)
    except Exception:
        logger.exception("threat_intel: KEV upsert failed")
        db.session.rollback()
        return 0
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_threat_intel.py -v -k refresh_kev
```

Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add backend/app/scanner/threat_intel.py backend/tests/test_threat_intel.py
git commit -m "feat(scan): threat_intel.refresh_kev_feed — daily upsert from CISA"
```

---

## Task 4: `threat_intel.lookup_epss()` — cached fetch from FIRST.org

**Files:**
- Modify: `backend/app/scanner/threat_intel.py`
- Modify: `backend/tests/test_threat_intel.py`

- [ ] **Step 1: Write the failing test**

Append to `backend/tests/test_threat_intel.py`:

```python
def _make_epss_row(cve_id="CVE-2024-1234", days_old=0, score=0.5, percentile=0.85):
    return MagicMock(
        cve_id=cve_id,
        score=score,
        percentile=percentile,
        model_version="2024.05.01",
        fetched_at=datetime.now(timezone.utc) - timedelta(days=days_old),
    )


def test_lookup_epss_returns_cached_when_fresh():
    with patch.object(threat_intel, "_query_epss") as mock_q:
        mock_q.return_value = _make_epss_row(days_old=3)
        result = threat_intel.lookup_epss("CVE-2024-1234")
    assert result is not None
    assert result["score"] == 0.5
    assert result["percentile"] == 0.85


def test_lookup_epss_fetches_when_stale():
    fresh_api = {
        "status": "OK",
        "data": [{
            "cve": "CVE-2024-1234",
            "epss": "0.77000",
            "percentile": "0.95000",
            "date": "2026-05-13",
            "model_version": "v2025.03.14",
        }],
    }
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = fresh_api

    with patch.object(threat_intel, "_query_epss") as mock_q, \
         patch.object(threat_intel.requests, "get", return_value=fake_response), \
         patch.object(threat_intel, "_upsert_epss") as mock_upsert:
        mock_q.return_value = _make_epss_row(days_old=20)  # 20d > 7d TTL → stale
        result = threat_intel.lookup_epss("CVE-2024-1234")

    assert result is not None
    assert result["score"] == pytest.approx(0.77)
    assert result["percentile"] == pytest.approx(0.95)
    mock_upsert.assert_called_once()


def test_lookup_epss_fetches_when_missing():
    fresh_api = {
        "status": "OK",
        "data": [{
            "cve": "CVE-2024-1234",
            "epss": "0.10",
            "percentile": "0.40",
            "date": "2026-05-13",
            "model_version": "v2025.03.14",
        }],
    }
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = fresh_api

    with patch.object(threat_intel, "_query_epss", return_value=None), \
         patch.object(threat_intel.requests, "get", return_value=fake_response), \
         patch.object(threat_intel, "_upsert_epss"):
        result = threat_intel.lookup_epss("CVE-2024-1234")

    assert result is not None
    assert result["score"] == pytest.approx(0.10)


def test_lookup_epss_returns_none_on_api_failure_when_no_cache():
    with patch.object(threat_intel, "_query_epss", return_value=None), \
         patch.object(threat_intel.requests, "get") as mock_get:
        mock_get.side_effect = threat_intel.requests.RequestException("timeout")
        assert threat_intel.lookup_epss("CVE-2024-1234") is None


def test_lookup_epss_returns_stale_cache_on_api_failure():
    """If the API is down and we have a stale cache, prefer stale to None."""
    with patch.object(threat_intel, "_query_epss") as mock_q, \
         patch.object(threat_intel.requests, "get") as mock_get:
        mock_q.return_value = _make_epss_row(days_old=20)
        mock_get.side_effect = threat_intel.requests.RequestException("down")
        result = threat_intel.lookup_epss("CVE-2024-1234")
    assert result is not None
    assert result["score"] == 0.5
    assert result.get("stale") is True
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_threat_intel.py -v -k lookup_epss
```

Expected: FAIL — `lookup_epss` not defined.

- [ ] **Step 3: Add `lookup_epss` and helpers to `threat_intel.py`**

Append to `backend/app/scanner/threat_intel.py`:

```python
from app.models import EpssCache  # add at top with the other model import
```

Then append at the end of the file:

```python
EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_FETCH_TIMEOUT = 5  # seconds
EPSS_CACHE_TTL_DAYS = 7


def _query_epss(cve_id: str) -> Optional[EpssCache]:
    """Indirection point for tests."""
    return EpssCache.query.filter_by(cve_id=cve_id).first()


def _upsert_epss(*, cve_id: str, score: float, percentile: float, model_version: Optional[str]) -> None:
    now = datetime.now(timezone.utc)
    existing = EpssCache.query.filter_by(cve_id=cve_id).first()
    if existing:
        existing.score = score
        existing.percentile = percentile
        existing.model_version = model_version
        existing.fetched_at = now
    else:
        db.session.add(EpssCache(
            cve_id=cve_id,
            score=score,
            percentile=percentile,
            model_version=model_version,
            fetched_at=now,
        ))
    db.session.commit()


def _epss_row_to_dict(row: EpssCache, *, stale: bool = False) -> Dict[str, Any]:
    return {
        "score": row.score,
        "percentile": row.percentile,
        "model_version": row.model_version,
        "fetched_at": row.fetched_at.isoformat() if row.fetched_at else None,
        "stale": stale,
    }


def _fetch_epss_api(cve_id: str) -> Optional[Dict[str, Any]]:
    """One-shot API call. Returns parsed score dict or None on any error."""
    try:
        resp = requests.get(
            EPSS_API_URL,
            params={"cve": cve_id},
            timeout=EPSS_FETCH_TIMEOUT,
        )
        resp.raise_for_status()
        payload = resp.json()
    except requests.RequestException:
        logger.warning("threat_intel: EPSS fetch failed for %s", cve_id)
        return None
    except ValueError:
        logger.warning("threat_intel: EPSS response not JSON for %s", cve_id)
        return None

    data = payload.get("data")
    if not isinstance(data, list) or not data:
        return None
    item = data[0]
    try:
        return {
            "score": float(item["epss"]),
            "percentile": float(item["percentile"]),
            "model_version": item.get("model_version"),
        }
    except (KeyError, ValueError, TypeError):
        return None


def lookup_epss(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Return EPSS data for cve_id. Reads cache first; if cache is missing
    or older than EPSS_CACHE_TTL_DAYS, refreshes from the FIRST.org API
    and upserts. Returns the stale row with stale=True if the API is down
    and we have any cached value at all, otherwise None.

    Never raises.
    """
    if not cve_id:
        return None
    cve_id = cve_id.strip().upper()

    try:
        cached = _query_epss(cve_id)
    except Exception:
        logger.exception("threat_intel: EPSS lookup db error for %s", cve_id)
        cached = None

    cutoff = datetime.now(timezone.utc) - __import__("datetime").timedelta(days=EPSS_CACHE_TTL_DAYS)
    fresh_cache = cached and cached.fetched_at and cached.fetched_at.replace(tzinfo=timezone.utc) > cutoff
    if fresh_cache:
        return _epss_row_to_dict(cached)

    # Cache stale or missing — try the API.
    fetched = _fetch_epss_api(cve_id)
    if fetched is not None:
        try:
            _upsert_epss(cve_id=cve_id, **fetched)
            return {
                "score": fetched["score"],
                "percentile": fetched["percentile"],
                "model_version": fetched.get("model_version"),
                "fetched_at": datetime.now(timezone.utc).isoformat(),
                "stale": False,
            }
        except Exception:
            logger.exception("threat_intel: EPSS upsert failed for %s", cve_id)
            # Fall through to returning whatever cache we had

    if cached is not None:
        return _epss_row_to_dict(cached, stale=True)
    return None
```

Replace the inline `__import__("datetime")` trick with a proper `timedelta` import at the top:

```python
from datetime import datetime, timedelta, timezone
```

…and replace `__import__("datetime").timedelta(days=EPSS_CACHE_TTL_DAYS)` with `timedelta(days=EPSS_CACHE_TTL_DAYS)`. The plan shows the ugly form first to make the dependency explicit — replace it.

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_threat_intel.py -v -k lookup_epss
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add backend/app/scanner/threat_intel.py backend/tests/test_threat_intel.py
git commit -m "feat(scan): threat_intel.lookup_epss — 7-day cache, stale-on-fail fallback"
```

---

## Task 5: `threat_intel.enrich_cve()` — convenience wrapper

**Files:**
- Modify: `backend/app/scanner/threat_intel.py`
- Modify: `backend/tests/test_threat_intel.py`

- [ ] **Step 1: Write the failing test**

Append to `backend/tests/test_threat_intel.py`:

```python
def test_enrich_cve_combines_both():
    with patch.object(threat_intel, "lookup_kev") as mock_kev, \
         patch.object(threat_intel, "lookup_epss") as mock_epss:
        mock_kev.return_value = {"cve_id": "CVE-2024-1234", "vendor": "Acme"}
        mock_epss.return_value = {"score": 0.5, "percentile": 0.85}
        result = threat_intel.enrich_cve("CVE-2024-1234")
    assert result == {
        "kev": {"cve_id": "CVE-2024-1234", "vendor": "Acme"},
        "epss": {"score": 0.5, "percentile": 0.85},
    }


def test_enrich_cve_handles_both_missing():
    with patch.object(threat_intel, "lookup_kev", return_value=None), \
         patch.object(threat_intel, "lookup_epss", return_value=None):
        result = threat_intel.enrich_cve("CVE-2024-9999")
    assert result == {"kev": None, "epss": None}


def test_enrich_cve_empty_input():
    assert threat_intel.enrich_cve("") == {"kev": None, "epss": None}
    assert threat_intel.enrich_cve(None) == {"kev": None, "epss": None}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_threat_intel.py -v -k enrich_cve
```

Expected: FAIL — `enrich_cve` not defined.

- [ ] **Step 3: Add `enrich_cve` to `threat_intel.py`**

Append to `backend/app/scanner/threat_intel.py`:

```python
def enrich_cve(cve_id: Optional[str]) -> Dict[str, Any]:
    """
    Convenience wrapper: return {kev: <dict|None>, epss: <dict|None>}.
    Used by cve_enricher and the backfill script.
    Never raises.
    """
    if not cve_id:
        return {"kev": None, "epss": None}
    return {
        "kev": lookup_kev(cve_id),
        "epss": lookup_epss(cve_id),
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_threat_intel.py -v
```

Expected: all tests pass (~15 total).

- [ ] **Step 5: Commit**

```bash
git add backend/app/scanner/threat_intel.py backend/tests/test_threat_intel.py
git commit -m "feat(scan): threat_intel.enrich_cve — combined lookup wrapper"
```

---

## Task 6: Add 3 fields to `FindingDraft`

**Files:**
- Modify: `backend/app/scanner/base.py`

- [ ] **Step 1: Add the three optional fields to the `FindingDraft` dataclass**

In `backend/app/scanner/base.py`, inside the `FindingDraft` dataclass, after the `confidence: str = "high"` line (around line 127), add:

```python
    # Threat-intel enrichment (populated by cve_enricher via threat_intel module)
    kev_listed: bool = False
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
```

- [ ] **Step 2: Verify the dataclass still imports cleanly**

```bash
cd backend
python -c "from app.scanner.base import FindingDraft; d = FindingDraft(template_id='t', title='x', severity='info', category='cve', description='y'); print(d.kev_listed, d.epss_score, d.epss_percentile)"
```

Expected: `False None None`

- [ ] **Step 3: Commit**

```bash
git add backend/app/scanner/base.py
git commit -m "feat(scan): add kev_listed, epss_score, epss_percentile to FindingDraft"
```

---

## Task 7: Wire `cve_enricher` to call `enrich_cve`

**Files:**
- Modify: `backend/app/scanner/analyzers/cve_enricher.py`
- Create: `backend/tests/test_cve_enricher_threat_intel.py`

- [ ] **Step 1: Write the failing test**

Create `backend/tests/test_cve_enricher_threat_intel.py`:

```python
"""Tests that cve_enricher populates threat-intel fields on FindingDrafts."""
from unittest.mock import patch

from app.scanner.analyzers.cve_enricher import CVEEnricher
from app.scanner.base import ScanContext, EngineResult


def _ctx_with_cve(cve_id="CVE-2024-1234"):
    ctx = ScanContext(
        asset_id=1, asset_type="domain", asset_value="example.com",
        organization_id=1, scan_job_id=1,
    )
    ctx.engine_results["shodan"] = EngineResult(
        engine_name="shodan",
        success=True,
        data={"vulns": {cve_id: {"cvss": 7.5}}},
    )
    return ctx


def test_cve_enricher_sets_kev_listed_when_kev_returns_data():
    ctx = _ctx_with_cve("CVE-2024-1234")
    enrichment = {
        "kev": {
            "cve_id": "CVE-2024-1234",
            "date_added": "2024-05-01",
            "known_ransomware": True,
        },
        "epss": {"score": 0.77, "percentile": 0.95},
    }
    with patch("app.scanner.analyzers.cve_enricher.enrich_cve", return_value=enrichment):
        drafts = CVEEnricher().analyze(ctx)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.kev_listed is True
    assert d.epss_score == 0.77
    assert d.epss_percentile == 0.95
    assert "kev" in d.tags
    assert d.details["kev"]["known_ransomware"] is True
    assert d.details["epss"]["score"] == 0.77


def test_cve_enricher_no_kev_no_epss_leaves_fields_blank():
    ctx = _ctx_with_cve("CVE-2024-9999")
    with patch("app.scanner.analyzers.cve_enricher.enrich_cve",
               return_value={"kev": None, "epss": None}):
        drafts = CVEEnricher().analyze(ctx)
    d = drafts[0]
    assert d.kev_listed is False
    assert d.epss_score is None
    assert d.epss_percentile is None
    assert "kev" not in d.tags
    assert "kev" not in d.details
    assert "epss" not in d.details


def test_cve_enricher_only_epss_present():
    ctx = _ctx_with_cve("CVE-2024-7777")
    with patch("app.scanner.analyzers.cve_enricher.enrich_cve",
               return_value={"kev": None, "epss": {"score": 0.92, "percentile": 0.99}}):
        drafts = CVEEnricher().analyze(ctx)
    d = drafts[0]
    assert d.kev_listed is False
    assert d.epss_score == 0.92
    assert "epss-high" in d.tags  # percentile >= 0.9 threshold
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_cve_enricher_threat_intel.py -v
```

Expected: FAIL — `enrich_cve` not imported in `cve_enricher.py`, fields not populated.

- [ ] **Step 3: Modify `cve_enricher.py` to call `enrich_cve` and set fields**

In `backend/app/scanner/analyzers/cve_enricher.py`:

a) Add the import at the top, after the existing `from app.scanner.base import ...` line:

```python
from app.scanner.threat_intel import enrich_cve
```

b) Replace the `_build_cve_finding` method's `return FindingDraft(...)` call with logic that fetches enrichment and populates the new fields. Find the existing method (around line 177) and modify it to look like:

```python
    def _build_cve_finding(self, cve_id: str, blob: Any) -> FindingDraft:
        """Build an enriched FindingDraft for a single CVE."""
        cvss = _extract_cvss(blob)
        severity = _cvss_to_severity(cvss)
        summary = _extract_summary(cve_id, blob)
        product = _extract_affected_product(blob)

        # Threat-intel enrichment (KEV + EPSS). Never raises.
        ti = enrich_cve(cve_id)
        kev = ti.get("kev")
        epss = ti.get("epss")

        # Build title
        title = f"Known vulnerability: {cve_id}"
        if cvss is not None:
            title += f" (CVSS {cvss:.1f})"
        if product:
            title += f" — {product}"

        # Build description
        description = summary
        if cvss is not None and summary == _extract_summary(cve_id, None):
            description = (
                f"{cve_id} has a CVSS score of {cvss:.1f} ({severity}). "
                + description
            )

        # Build remediation
        remediation = f"Research {cve_id} and apply the vendor's patch or update. "
        if product:
            remediation += f"Check for updates to {product}. "
        remediation += (
            f"See https://nvd.nist.gov/vuln/detail/{cve_id} for full details "
            "and affected versions."
        )

        # Tags
        tags = ["cve", severity, cve_id.lower()]
        if kev:
            tags.append("kev")
        if epss and epss.get("percentile") is not None and epss["percentile"] >= 0.9:
            tags.append("epss-high")

        # Details — include threat-intel blobs alongside Shodan raw
        details: Dict[str, Any] = {
            "cve_id": cve_id,
            "cvss": cvss,
            "severity": severity,
            "summary": summary[:500],
            "affected_product": product,
            "raw_shodan": blob if isinstance(blob, dict) else {},
        }
        if kev:
            details["kev"] = kev
        if epss:
            details["epss"] = epss

        return FindingDraft(
            template_id=f"cve-{cve_id.lower()}",
            title=title,
            severity=severity,
            category="cve",
            description=description[:2000],
            remediation=remediation,
            finding_type="cve",
            cwe=self._extract_cwe(blob),
            references=[
                f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
            ],
            tags=tags,
            engine="shodan",
            confidence="high" if cvss is not None else "medium",
            details=details,
            dedupe_fields={"cve_id": cve_id},
            kev_listed=bool(kev),
            epss_score=epss.get("score") if epss else None,
            epss_percentile=epss.get("percentile") if epss else None,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_cve_enricher_threat_intel.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Re-run the existing cve_enricher tests (if any) to confirm no regression**

```bash
pytest tests/ -k cve -v
```

Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add backend/app/scanner/analyzers/cve_enricher.py backend/tests/test_cve_enricher_threat_intel.py
git commit -m "feat(scan): cve_enricher populates kev + epss fields on findings"
```

---

## Task 8: Orchestrator persists the 3 new columns

**Files:**
- Modify: `backend/app/scanner/orchestrator.py` (both update and create branches around lines 803-876)

- [ ] **Step 1: Add the three `hasattr` blocks to the "update existing" branch**

In `backend/app/scanner/orchestrator.py`, find the update-branch block (around line 803-834). After the `if hasattr(Finding, "analyzer")` block (around line 830), add:

```python
                if hasattr(Finding, "kev_listed"):
                    prev.kev_listed = bool(draft.kev_listed)
                if hasattr(Finding, "epss_score") and draft.epss_score is not None:
                    prev.epss_score = draft.epss_score
                if hasattr(Finding, "epss_percentile") and draft.epss_percentile is not None:
                    prev.epss_percentile = draft.epss_percentile
```

- [ ] **Step 2: Add the same three blocks to the "new finding" branch**

In the same file, find the new-finding branch (around line 836-876). After the `if hasattr(Finding, "template_id")` block (around line 871), add:

```python
            if hasattr(Finding, "kev_listed"):
                finding.kev_listed = bool(draft.kev_listed)
            if hasattr(Finding, "epss_score"):
                finding.epss_score = draft.epss_score
            if hasattr(Finding, "epss_percentile"):
                finding.epss_percentile = draft.epss_percentile
```

- [ ] **Step 3: Verify by running the full cve test suite**

```bash
cd backend
pytest tests/ -k "cve or threat_intel" -v
```

Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add backend/app/scanner/orchestrator.py
git commit -m "feat(scan): orchestrator persists kev_listed, epss_score, epss_percentile"
```

---

## Task 9: Daily KEV refresh scheduler job

**Files:**
- Modify: `backend/app/scheduler.py`

- [ ] **Step 1: Find the `init_scheduler` function in `scheduler.py`**

Open `backend/app/scheduler.py`. Locate the `init_scheduler(app)` function near the end of the file. Note the existing `add_job(...)` calls for Monday/Tuesday/Wednesday agent briefs as the pattern.

- [ ] **Step 2: Add a `_run_refresh_kev_feed` function above `init_scheduler`**

Insert in `backend/app/scheduler.py` above the `init_scheduler` function (near the other `_run_*` helpers, around line 382):

```python
def _run_refresh_kev_feed(app):
    """Daily APScheduler job: refresh CISA KEV cache. Never raises."""
    with app.app_context():
        from app.scanner.threat_intel import refresh_kev_feed
        try:
            count = refresh_kev_feed()
            logger.info("refresh_kev_feed: upserted %d entries", count)
        except Exception:
            logger.exception("refresh_kev_feed crashed")
```

- [ ] **Step 3: Register the job inside `init_scheduler`**

Inside `init_scheduler(app)`, after the existing weekly-brief job registrations (search for `_run_monday_weekly_summary`), add:

```python
    _scheduler.add_job(
        _run_refresh_kev_feed,
        trigger=CronTrigger(hour=2, minute=0),
        args=[app],
        id="refresh_kev_feed",
        replace_existing=True,
        max_instances=1,
    )
    logger.info("Registered daily KEV refresh job (02:00 UTC)")
```

- [ ] **Step 4: Smoke-test the scheduler boots without errors**

```bash
cd backend
$env:SQLALCHEMY_DATABASE_URI = "postgresql://easm_user:localdevpassword@localhost:5432/easm"
$env:SECRET_KEY = "local-dev-secret-key"
python -c "from app import create_app; app = create_app(); print('OK')"
```

Expected: prints `OK`. The scheduler-registered logs will show the new job.

- [ ] **Step 5: Commit**

```bash
git add backend/app/scheduler.py
git commit -m "feat(scan): daily APScheduler job to refresh CISA KEV cache at 02:00 UTC"
```

---

## Task 10: Backfill script

**Files:**
- Create: `backend/scripts/backfill_threat_intel.py`

- [ ] **Step 1: Create the script**

Create `backend/scripts/backfill_threat_intel.py`:

```python
"""
One-time backfill: enrich every unresolved CVE Finding with KEV + EPSS data.

Run once per environment after deploying the threat-intel migration:

    docker compose exec easm-backend python -m scripts.backfill_threat_intel

Idempotent — re-running just refreshes any stale data.
"""
from __future__ import annotations

import logging
import sys
import time

from app import create_app
from app.extensions import db
from app.models import Finding
from app.scanner.threat_intel import enrich_cve, refresh_kev_feed


logger = logging.getLogger("backfill_threat_intel")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


def _cve_id_for(finding: Finding) -> str | None:
    """Best-effort: pull the CVE ID from details_json or template_id."""
    details = finding.details_json or {}
    cve = details.get("cve_id")
    if cve:
        return cve.strip().upper()
    # Fall back to template_id pattern "cve-cve-yyyy-nnnn"
    tid = (finding.template_id or "").lower()
    if tid.startswith("cve-cve-"):
        return tid[4:].upper()
    return None


def backfill() -> int:
    """Returns count of findings updated."""
    logger.info("Refreshing KEV cache before iterating findings...")
    n = refresh_kev_feed()
    logger.info("KEV refreshed: %d entries", n)

    q = (
        Finding.query
        .filter(Finding.finding_type == "cve")
        .filter(Finding.resolved.is_(False))
        .filter(Finding.ignored.is_(False))
        .order_by(Finding.id)
    )
    total = q.count()
    logger.info("Found %d unresolved CVE findings to backfill", total)
    if total == 0:
        return 0

    updated = 0
    skipped = 0
    batch_size = 100
    start_time = time.time()

    for finding in q.yield_per(batch_size):
        cve_id = _cve_id_for(finding)
        if not cve_id:
            skipped += 1
            continue

        enrichment = enrich_cve(cve_id)
        kev = enrichment.get("kev")
        epss = enrichment.get("epss")

        finding.kev_listed = bool(kev)
        finding.epss_score = epss.get("score") if epss else None
        finding.epss_percentile = epss.get("percentile") if epss else None

        details = dict(finding.details_json or {})
        if kev:
            details["kev"] = kev
        else:
            details.pop("kev", None)
        if epss:
            details["epss"] = epss
        else:
            details.pop("epss", None)
        finding.details_json = details

        # Tags update (preserve other tags)
        tags = list(finding.tags_json or [])
        if kev and "kev" not in tags:
            tags.append("kev")
        if (epss and epss.get("percentile") is not None
                and epss["percentile"] >= 0.9 and "epss-high" not in tags):
            tags.append("epss-high")
        finding.tags_json = tags

        updated += 1
        if updated % batch_size == 0:
            db.session.commit()
            elapsed = time.time() - start_time
            logger.info(
                "Progress: %d/%d updated (%.1fs, %.2f/s); skipped %d",
                updated, total, elapsed, updated / max(elapsed, 0.001), skipped,
            )

    db.session.commit()
    elapsed = time.time() - start_time
    logger.info(
        "Backfill complete: %d updated, %d skipped (no CVE id), %.1fs total",
        updated, skipped, elapsed,
    )
    return updated


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        try:
            backfill()
        except Exception:
            logger.exception("Backfill crashed")
            sys.exit(1)
```

- [ ] **Step 2: Run a dry-run smoke test against an empty DB section**

```bash
cd backend
$env:SQLALCHEMY_DATABASE_URI = "postgresql://easm_user:localdevpassword@localhost:5432/easm"
$env:SECRET_KEY = "local-dev-secret-key"
python -m scripts.backfill_threat_intel
```

Expected: log lines for "Refreshing KEV cache", "Found N unresolved CVE findings", "Backfill complete". No tracebacks. If you have zero unresolved CVE findings locally, that's fine — the empty-result path is what we want to verify.

- [ ] **Step 3: Commit**

```bash
git add backend/scripts/backfill_threat_intel.py
git commit -m "feat(scan): backfill_threat_intel script — one-time historical enrichment"
```

---

## Task 11: Frontend — KEV badge + EPSS line in finding details

**Files:**
- Modify: `frontend/app/FindingDetailsDialog.tsx`

- [ ] **Step 1: Locate the finding details panel's metadata section**

Open `frontend/app/FindingDetailsDialog.tsx`. Search for where the existing CWE / CVSS / severity metadata is rendered. The pattern is typically a series of `<div>` rows or a definition list near the top of the dialog body.

- [ ] **Step 2: Extend the `Finding` TypeScript type at the top of the file**

Find the existing `Finding` type / interface declaration in the file (or its import). Add three new optional fields:

```typescript
  kev_listed?: boolean;
  epss_score?: number | null;
  epss_percentile?: number | null;
  // The full KEV blob lives under details_json.kev (when listed)
  // The full EPSS blob lives under details_json.epss
```

If the type is imported from elsewhere, extend that source instead. If the dialog reads `details_json.kev` and `details_json.epss` directly, no type change is needed beyond optional access.

- [ ] **Step 3: Add the KEV badge block**

Inside the dialog body, near the existing CVSS / severity rendering, add:

```tsx
{finding.kev_listed && finding.details_json?.kev && (
  <div className="mt-3 rounded-lg border border-red-500/30 bg-red-500/[0.05] px-3 py-2">
    <div className="flex items-center gap-2">
      <span className="inline-flex items-center gap-1 rounded-md bg-red-500/15 px-2 py-0.5 text-[11px] font-semibold text-red-300 uppercase tracking-wide">
        Actively Exploited
      </span>
      <span className="text-xs text-white/55">
        CISA KEV · added {finding.details_json.kev.date_added}
      </span>
    </div>
    {finding.details_json.kev.vulnerability_name && (
      <div className="mt-1 text-sm text-white/80">
        {finding.details_json.kev.vulnerability_name}
      </div>
    )}
    {finding.details_json.kev.known_ransomware && (
      <div className="mt-1 text-xs text-red-300">
        ⚠ Known ransomware campaign use
      </div>
    )}
    {finding.details_json.kev.due_date && (
      <div className="mt-1 text-xs text-white/55">
        US federal due date: {finding.details_json.kev.due_date}
      </div>
    )}
    <a
      href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
      target="_blank"
      rel="noopener noreferrer"
      className="mt-1 inline-block text-[11px] text-teal-400 hover:text-teal-300"
    >
      View on CISA KEV catalog →
    </a>
  </div>
)}
```

- [ ] **Step 4: Add the EPSS line**

Below the CVSS row (or below the KEV block), add:

```tsx
{finding.epss_score != null && (
  <div className="mt-2 text-xs text-white/55">
    <span className="font-medium text-white/80">EPSS:</span>{" "}
    {(finding.epss_score * 100).toFixed(1)}% probability of exploitation in next 30 days
    {finding.epss_percentile != null && (
      <span className="text-white/40">
        {" "}(top {((1 - finding.epss_percentile) * 100).toFixed(1)}% of all CVEs)
      </span>
    )}{" "}
    <a
      href="https://www.first.org/epss/"
      target="_blank"
      rel="noopener noreferrer"
      className="text-teal-400 hover:text-teal-300"
    >
      what is this?
    </a>
  </div>
)}
```

- [ ] **Step 5: Verify visually**

Start the frontend dev server (if not already):
```bash
cd frontend
npm run dev
```

Trigger a scan against a domain known to have at least one KEV-listed CVE finding (or use the backfill script on existing data first). Open the finding in the UI; verify:
- KEV badge renders with the red "Actively Exploited" tag
- Date added shows
- Ransomware warning shows when applicable
- EPSS line shows score percentage and percentile
- Links open the right pages

For findings without KEV or EPSS data, neither block should render (no empty boxes).

- [ ] **Step 6: Commit**

```bash
git add frontend/app/FindingDetailsDialog.tsx
git commit -m "feat(ui): show KEV badge and EPSS line in finding details"
```

---

## Self-Review

**Spec coverage check** — every section of the spec has at least one task:

| Spec section | Task(s) |
|---|---|
| `threat_intel.py` module | 2, 3, 4, 5 |
| `kev_entry` table | 1 |
| `epss_cache` table | 1 |
| 3 new `Finding` columns | 1 |
| `cve_enricher` integration | 7 |
| `FindingDraft` field additions | 6 |
| Orchestrator persistence | 8 |
| APScheduler daily KEV refresh | 9 |
| Backfill script | 10 |
| UI — finding details panel | 11 |
| Severity unchanged (badge only) | 7 (tags + fields; no severity logic) |
| Silent failure invariant | 2, 3, 4 (every public function returns None on error) |

**Placeholder scan:** no TBDs / TODOs / vague directions. Every code block is complete. Test code is real assertions. Commands include expected output.

**Type consistency:** `enrich_cve` returns `{kev, epss}` consistently across Tasks 5, 7, and 10. `FindingDraft` fields named `kev_listed`, `epss_score`, `epss_percentile` consistently across Tasks 6, 7, 8, 10. Same names on the `Finding` model in Task 1. Migration column names match.

---

## Execution

**Plan complete and saved to `docs/superpowers/plans/2026-05-13-kev-epss-enrichment.md`.**

Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, two-stage review between tasks, fast iteration
2. **Inline Execution** — execute tasks in this session with checkpoints between

Which approach?
