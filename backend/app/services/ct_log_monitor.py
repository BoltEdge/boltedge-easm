# app/services/ct_log_monitor.py
"""
Certificate-transparency polling for Site Mimic Watch.

Every 15 minutes the scheduler invokes poll_brand_keywords() which:

  1. Enumerates unique brand keywords across all assets with
     lookalike_watch=True (each asset's domain → brand keyword via
     tldextract: nanoeasm.com → 'nanoeasm')
  2. For each unique keyword, queries crt.sh?q=<keyword>&output=json
  3. Filters the response to certs whose SAN list contains the
     keyword as a substring (rejects pure subdomain matches of
     unrelated brands)
  4. Inserts new (cert_id, hostname) pairs into ct_log_candidate.
     UNIQUE constraint on (cert_id, hostname) provides dedupe.

Per-keyword cap of 50 candidates per cycle prevents queue blow-out
when a short keyword matches thousands of legitimate certs.

All errors are silent: crt.sh outage, malformed JSON, DB write
failure — each causes that keyword to be skipped this cycle. Next
tick retries.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional

import requests


logger = logging.getLogger(__name__)


CRTSH_URL = "https://crt.sh/"
POLL_TIMEOUT = 10
PER_KEYWORD_CANDIDATE_CAP = 50
CANDIDATE_TTL_DAYS = 14


def extract_brand_keyword(domain: str) -> Optional[str]:
    """Derive a single brand keyword from a registrable domain.

    nanoeasm.com           -> 'nanoeasm'
    my-company.io          -> 'my-company'
    internal.acme.example  -> falls back to the rightmost label before
                              the public-suffix list TLD via tldextract

    Returns None when the input is empty or unparseable."""
    if not domain:
        return None
    d = domain.strip().lower()
    if d.startswith("*."):
        d = d[2:]
    try:
        import tldextract
    except ImportError:
        # Fallback: take the second-to-last label
        parts = d.split(".")
        if len(parts) >= 2:
            return parts[-2]
        return None
    ext = tldextract.extract(d)
    return (ext.domain or None)


def poll_brand_keywords(keywords: Iterable[str]) -> int:
    """Poll crt.sh for each unique keyword. Returns total candidates
    inserted across the whole cycle. Never raises."""
    keywords = sorted({k for k in keywords if k})
    if not keywords:
        return 0

    total_inserted = 0
    for keyword in keywords:
        try:
            inserted = _poll_one_keyword(keyword)
            total_inserted += inserted
        except Exception:
            logger.exception("ct_log_monitor: cycle failed for keyword=%s", keyword)
    return total_inserted


def _poll_one_keyword(keyword: str) -> int:
    rows = _fetch_crtsh(keyword)
    if not rows:
        return 0

    # Walk rows newest-first, dedupe (cert_id, hostname) into a batch,
    # cap at the per-keyword limit, insert into the queue.
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expires = now + timedelta(days=CANDIDATE_TTL_DAYS)

    batch: list[tuple[str, str, str, Optional[datetime]]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        if len(batch) >= PER_KEYWORD_CANDIDATE_CAP:
            break
        cert_id = str(row.get("id") or "").strip()[:40]
        if not cert_id:
            continue

        # crt.sh returns name_value as a newline-separated SAN list.
        sans = _split_sans(row.get("name_value", ""))
        cert_logged_at = _parse_crtsh_date(row.get("entry_timestamp"))

        for san in sans:
            host = _sanitize_hostname(san)
            if not host:
                continue
            if keyword not in host:
                # Keyword must appear as a substring of the hostname
                continue
            key = (cert_id, host)
            if key in seen:
                continue
            seen.add(key)
            batch.append((cert_id, host, keyword, cert_logged_at))
            if len(batch) >= PER_KEYWORD_CANDIDATE_CAP:
                break

    if not batch:
        return 0

    return _insert_candidates(batch, now=now, expires_at=expires)


def _fetch_crtsh(keyword: str) -> list[dict]:
    """Indirection so tests can mock the HTTP layer. Never raises."""
    try:
        resp = requests.get(
            CRTSH_URL,
            params={"q": keyword, "output": "json"},
            timeout=POLL_TIMEOUT,
            headers={"User-Agent": "Nano-EASM-CT-Monitor/1.0"},
        )
    except requests.RequestException:
        logger.warning("ct_log_monitor: network error for %s", keyword, exc_info=True)
        return []
    if resp.status_code != 200:
        logger.warning("ct_log_monitor: crt.sh returned %s for %s",
                       resp.status_code, keyword)
        return []
    try:
        payload = resp.json()
    except ValueError:
        logger.warning("ct_log_monitor: crt.sh response not JSON for %s", keyword)
        return []
    if not isinstance(payload, list):
        return []
    return payload


_HOSTNAME_RE = re.compile(r"^[a-z0-9*][a-z0-9.\-]{0,253}[a-z0-9]$")


def _sanitize_hostname(s: str) -> Optional[str]:
    if not s:
        return None
    host = s.strip().lower()
    # Wildcards aren't useful to probe; we want the concrete hostname
    if host.startswith("*."):
        host = host[2:]
    if not _HOSTNAME_RE.match(host):
        return None
    if len(host) > 255:
        return None
    return host


def _split_sans(name_value: str) -> List[str]:
    if not name_value:
        return []
    # crt.sh separates SANs by newline
    return [s for s in (name_value or "").split("\n") if s]


def _parse_crtsh_date(value) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    # Examples: "2026-05-14T03:14:15.123Z" or with offset
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _insert_candidates(
    batch: list[tuple[str, str, str, Optional[datetime]]],
    *,
    now: datetime,
    expires_at: datetime,
) -> int:
    """DB indirection — patched in tests. Returns count inserted."""
    try:
        from app.extensions import db
        from app.models import CtLogCandidate
    except Exception:
        return 0

    inserted = 0
    for cert_id, hostname, brand_keyword, cert_logged_at in batch:
        # ON CONFLICT-equivalent via try/insert/rollback. The unique
        # constraint (cert_id, hostname) means re-inserts of the same
        # pair fail cleanly and we treat as benign skip.
        try:
            db.session.add(CtLogCandidate(
                brand_keyword=brand_keyword[:64],
                hostname=hostname[:255],
                cert_id=cert_id,
                cert_logged_at=cert_logged_at,
                discovered_at=now,
                expires_at=expires_at,
            ))
            db.session.commit()
            inserted += 1
        except Exception:
            db.session.rollback()
            continue
    return inserted


def cleanup_expired_candidates() -> int:
    """Hourly cleanup: delete rows past their TTL. Returns count deleted."""
    try:
        from app.extensions import db
        from app.models import CtLogCandidate
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        deleted = (
            CtLogCandidate.query
            .filter(CtLogCandidate.expires_at < now)
            .delete(synchronize_session=False)
        )
        db.session.commit()
        return int(deleted or 0)
    except Exception:
        logger.exception("ct_log_monitor: cleanup failed")
        try:
            from app.extensions import db
            db.session.rollback()
        except Exception:
            pass
        return 0


def collect_brand_keywords() -> list[str]:
    """Read every watched-asset's brand keyword. Used by the scheduler
    job. Returns a deduped, sorted list. Never raises."""
    try:
        from app.models import Asset
    except Exception:
        return []
    try:
        rows = (
            Asset.query
            .filter(Asset.lookalike_watch.is_(True))
            .filter(Asset.asset_type == "domain")
            .with_entities(Asset.value)
            .all()
        )
    except Exception:
        return []
    keywords: set[str] = set()
    for (value,) in rows:
        kw = extract_brand_keyword(value)
        if kw and len(kw) >= 3:
            # Skip very short keywords ("io" etc.) — they'd match the
            # entire internet and blow up the queue.
            keywords.add(kw)
    return sorted(keywords)
