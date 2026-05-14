# app/services/pastebin_client.py
"""
Pastebin Scraping-API client.

Background-fetcher pattern. Public pastes are pulled in batches of 250
every 60 seconds via the operator-side scraping endpoint (which is the
only Pastebin API that exposes content keyword-searchable). New paste
keys are upserted into the local `paste_cache` table; the LeakEngine
queries that table at scan time to match customer domains.

Auth model: Pastebin gates the scraping API by IP whitelist, not by
token. The operator creates a Pastebin PRO account (one-off ~$30 USD),
logs in, pastes the EC2 box's public IP into the API allowlist, and
sets PASTEBIN_FETCHER_ENABLED=true on the backend. No secret is stored
in env — just a feature flag.

Failure modes (all silent, all returning 0 ingested):
  - PASTEBIN_FETCHER_ENABLED not set or != "true": fetcher skipped
  - IP not whitelisted: Pastebin returns text "YOUR IP: X.X.X.X DOES
    NOT HAVE ACCESS" instead of JSON; we detect and log
  - HTTP timeout, 5xx, malformed JSON: logged at WARNING; next tick
    retries
  - Per-paste body fetch fails: that paste is skipped, batch continues
  - Paste body > MAX_BODY_BYTES: truncated to first 64 KB
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

from app.extensions import db
from app.models import PasteCache


logger = logging.getLogger(__name__)


PASTEBIN_SCRAPE_URL = "https://scrape.pastebin.com/api_scraping.php"
PASTEBIN_BODY_URL = "https://scrape.pastebin.com/api_scrape_item.php"
DEFAULT_FETCH_LIMIT = 250          # Pastebin's documented max
MAX_BODY_BYTES = 65536             # 64 KB — bound row size
PASTE_TTL_DAYS = 7
FETCH_TIMEOUT = 10                 # seconds
BODY_FETCH_TIMEOUT = 8


def _fetcher_enabled() -> bool:
    return os.environ.get("PASTEBIN_FETCHER_ENABLED", "").strip().lower() == "true"


def _fetch_limit() -> int:
    """Allow operator-side override of the per-cycle paste count. Capped
    at Pastebin's documented maximum of 250."""
    raw = os.environ.get("PASTEBIN_FETCH_LIMIT", str(DEFAULT_FETCH_LIMIT))
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_FETCH_LIMIT
    return max(1, min(n, DEFAULT_FETCH_LIMIT))


def _is_ip_not_whitelisted(text: str) -> bool:
    """Pastebin's not-whitelisted response is a plain-text body that starts
    with `YOUR IP:` and contains `DOES NOT HAVE ACCESS`. Detect both
    fragments — the exact wording has shifted between Pastebin's API
    versions in the past."""
    if not text:
        return False
    upper = text.upper()
    return "DOES NOT HAVE ACCESS" in upper or "NOT REGISTERED" in upper


def _fetch_paste_list(limit: int) -> Optional[list]:
    """GET the recent-pastes index. Returns the JSON list of paste metadata
    dicts, or None on any failure / IP-blocked / malformed response."""
    try:
        resp = requests.get(
            PASTEBIN_SCRAPE_URL,
            params={"limit": limit},
            timeout=FETCH_TIMEOUT,
            headers={"User-Agent": "Nano-EASM-Pastebin-Fetcher/1.0"},
        )
    except requests.RequestException:
        logger.warning("pastebin_client: list fetch network error", exc_info=True)
        return None

    if resp.status_code != 200:
        logger.warning(
            "pastebin_client: list fetch returned %s", resp.status_code
        )
        return None

    body_text = resp.text or ""
    if _is_ip_not_whitelisted(body_text):
        logger.warning(
            "pastebin_client: server IP not whitelisted on Pastebin PRO. "
            "Add this server's IP to Pastebin → Settings → Scraping API. "
            "Response: %s",
            body_text[:200],
        )
        return None

    try:
        payload = resp.json()
    except ValueError:
        logger.warning(
            "pastebin_client: list response is not JSON: %s", body_text[:200]
        )
        return None

    if not isinstance(payload, list):
        logger.warning(
            "pastebin_client: list response not a JSON array, got %s",
            type(payload).__name__,
        )
        return None

    return payload


def _fetch_paste_body(paste_key: str) -> Optional[str]:
    """GET a single paste's body. Returns the text body (possibly truncated
    by the caller) or None on any failure."""
    try:
        resp = requests.get(
            PASTEBIN_BODY_URL,
            params={"i": paste_key},
            timeout=BODY_FETCH_TIMEOUT,
            headers={"User-Agent": "Nano-EASM-Pastebin-Fetcher/1.0"},
        )
    except requests.RequestException:
        return None

    if resp.status_code != 200:
        return None

    return resp.text


def _parse_int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _ts_to_datetime(epoch_s) -> datetime:
    """Pastebin sends `date` as a Unix epoch string. Coerce defensively;
    fall back to now-UTC if the field is missing or unparseable."""
    n = _parse_int(epoch_s)
    if n is None:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromtimestamp(n, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return datetime.now(timezone.utc)


def _query_existing_keys(keys: list[str]) -> set[str]:
    """DB indirection — tests patch this to avoid needing an app context."""
    rows = (
        PasteCache.query
        .with_entities(PasteCache.paste_key)
        .filter(PasteCache.paste_key.in_(keys))
        .all()
    )
    return {row.paste_key for row in rows}


def _save_paste(row: PasteCache) -> bool:
    """Add + commit a single paste row. Returns True on success.
    A unique-key collision (racing insert) is treated as a benign skip."""
    try:
        db.session.add(row)
        db.session.commit()
        return True
    except Exception:
        db.session.rollback()
        return False


def _query_pastes_by_domain(domain: str, max_matches: int) -> list:
    """DB indirection for match_pastes_for_domain — patch in tests."""
    pattern = f"%{domain}%"
    return (
        PasteCache.query
        .filter(PasteCache.body.ilike(pattern))
        .order_by(PasteCache.date_pasted.desc())
        .limit(max_matches)
        .all()
    )


def fetch_recent_pastes_and_upsert() -> int:
    """Pull the recent-pastes list, fetch the body for each previously-
    unseen paste_key, upsert into paste_cache. Returns the count of NEW
    pastes ingested this cycle. Never raises."""
    if not _fetcher_enabled():
        return 0

    listing = _fetch_paste_list(_fetch_limit())
    if not listing:
        return 0

    # Bulk-fetch known keys so we don't query the DB once per paste.
    keys = [
        str(item.get("key") or "").strip()[:20]
        for item in listing
        if isinstance(item, dict) and item.get("key")
    ]
    if not keys:
        return 0

    try:
        existing = _query_existing_keys(keys)
    except Exception:
        logger.exception("pastebin_client: existing-keys lookup failed")
        existing = set()

    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=PASTE_TTL_DAYS)
    inserted = 0

    for item in listing:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip()[:20]
        if not key or key in existing:
            continue

        body = _fetch_paste_body(key)
        if body is None:
            continue
        if len(body.encode("utf-8", errors="ignore")) > MAX_BODY_BYTES:
            body = body[:MAX_BODY_BYTES]  # char-truncate; close enough

        row = PasteCache(
            paste_key=key,
            paste_url=(str(item.get("scrape_url") or item.get("full_url") or
                           f"https://pastebin.com/{key}"))[:255],
            title=(str(item.get("title") or ""))[:255] or None,
            author=(str(item.get("user") or ""))[:100] or None,
            syntax=(str(item.get("syntax") or ""))[:40] or None,
            size_bytes=_parse_int(item.get("size")),
            body=body,
            date_pasted=_ts_to_datetime(item.get("date")),
            fetched_at=now,
            expires_at=expires,
        )
        if _save_paste(row):
            inserted += 1

    return inserted


def match_pastes_for_domain(
    domain: str, max_matches: int = 50,
) -> list[dict]:
    """Return up to max_matches pastes containing `domain` (ILIKE match).
    Most-recent first. Caller is the LeakEngine; returned dicts are the
    direct match payload for the LeakAnalyzer.
    Never raises — DB errors return [].
    """
    if not domain:
        return []
    try:
        rows = _query_pastes_by_domain(domain, max_matches)
    except Exception:
        logger.exception("pastebin_client: match query failed")
        return []

    out = []
    for r in rows:
        snippet = _extract_snippet(r.body or "", domain, window=160)
        out.append({
            "paste_key": r.paste_key,
            "paste_url": r.paste_url,
            "title": r.title,
            "author": r.author,
            "syntax": r.syntax,
            "size_bytes": r.size_bytes,
            "snippet": snippet,
            "date_pasted": r.date_pasted.isoformat() if r.date_pasted else None,
        })
    return out


def _extract_snippet(body: str, needle: str, window: int = 160) -> str:
    """Return ~window chars centred on the first case-insensitive match of
    needle in body. Falls back to the first window chars if not found."""
    if not body:
        return ""
    idx = body.lower().find(needle.lower())
    if idx < 0:
        return body[:window]
    start = max(0, idx - window // 2)
    end = min(len(body), idx + len(needle) + window // 2)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(body) else ""
    return f"{prefix}{body[start:end]}{suffix}"
