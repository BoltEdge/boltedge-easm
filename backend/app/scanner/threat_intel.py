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
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import requests

from app.extensions import db
from app.models import EpssCache, KevEntry


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────
# KEV — CISA Known Exploited Vulnerabilities
# ─────────────────────────────────────────────────────────────────────

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
KEV_FETCH_TIMEOUT = 10  # seconds


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


# ─────────────────────────────────────────────────────────────────────
# EPSS — FIRST.org Exploit Prediction Scoring System
# ─────────────────────────────────────────────────────────────────────

EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_FETCH_TIMEOUT = 5  # seconds
EPSS_CACHE_TTL_DAYS = 7


def _query_epss(cve_id: str) -> Optional[EpssCache]:
    """Indirection point for tests."""
    return EpssCache.query.filter_by(cve_id=cve_id).first()


def _upsert_epss(
    *,
    cve_id: str,
    score: float,
    percentile: float,
    model_version: Optional[str],
) -> None:
    now = datetime.now(timezone.utc)
    existing = EpssCache.query.filter_by(cve_id=cve_id).first()
    if existing:
        existing.score = score
        existing.percentile = percentile
        existing.model_version = model_version
        existing.fetched_at = now
    else:
        db.session.add(
            EpssCache(
                cve_id=cve_id,
                score=score,
                percentile=percentile,
                model_version=model_version,
                fetched_at=now,
            )
        )
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

    cutoff = datetime.now(timezone.utc) - timedelta(days=EPSS_CACHE_TTL_DAYS)
    fresh_cache = bool(
        cached
        and cached.fetched_at
        and _ensure_aware(cached.fetched_at) > cutoff
    )
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


def _ensure_aware(dt: datetime) -> datetime:
    """SQLAlchemy may return naive UTC datetimes; normalise so comparison works."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ─────────────────────────────────────────────────────────────────────
# Combined wrapper — convenience for cve_enricher + backfill
# ─────────────────────────────────────────────────────────────────────


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
