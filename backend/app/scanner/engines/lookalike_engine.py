# app/scanner/engines/lookalike_engine.py
"""
LookalikeEngine — detects typosquats, homoglyph variants, TLD swaps,
IDN/punycode confusables, and other lookalike domains for a watched
root domain.

Design (see docs/superpowers/specs/2026-05-14-lookalike-domain-detection-design.md):
  - Opt-in per Asset via Asset.lookalike_watch
  - Self-rate-limits at 6 days via Asset.last_lookalike_scan_at
  - Uses dnstwist to generate all 16 variant families
  - Verifies each candidate via three concurrent checks:
      1. DNS A-record lookup (dnspython)
      2. HTTP HEAD on port 80 + 443 (requests)
      3. CT log search via crt.sh
  - Drops candidates with no positive signal (unregistered noise)
  - Never raises — failures log and degrade gracefully

The matching analyzer is LookalikeAnalyzer which converts verified hits
into FindingDrafts with severity derived from the signal mix.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests

from app.extensions import db
from app.models import Asset
from app.scanner.base import BaseEngine, EngineResult, ScanContext


logger = logging.getLogger(__name__)


RATE_LIMIT_DAYS = 6
DNS_TIMEOUT = 3
HTTP_TIMEOUT = 5
CRTSH_TIMEOUT = 5
MAX_WORKERS = 20
CERT_RECENT_DAYS = 90

# Hard cap so a single run never balloons. dnstwist generates 4000+
# candidates for typical brand-length domains; verifying every single
# one would push us past crt.sh's rate limits and tie up the worker
# for over an hour. We take all non-homoglyph families (low volume,
# high signal) plus the first N homoglyph variants (high volume because
# every character has multiple Cyrillic / Greek / mathematical look-
# alikes; the most relevant ones come first in dnstwist's output).
MAX_HOMOGLYPH_VARIANTS = 250
MAX_CANDIDATES_PER_RUN = 1000

# DNSTwist family names we DO emit findings for. Excludes the noisiest
# families by default:
#   - "*original"     : the input domain itself; not a variant
#   - "bitsquatting"  : 1-bit flips; very high noise, very low real
#                       attack rate
#   - "hyphenation"   : inserts hyphens; mostly legit corp subdomains
#   - "plural"        : adds 's'; mostly benign coincidences
#   - "subdomain"     : variant.parent.com; different threat model
#                       (subdomain takeover, handled elsewhere)
#   - "various"       : catch-all without semantic meaning
# This list can be tuned later; default is conservative on noise.
INCLUDED_FAMILIES = {
    "addition",
    "homoglyph",
    "insertion",
    "omission",
    "repetition",
    "replacement",
    "transposition",
    "vowel-swap",
    "tld-swap",      # name varies across dnstwist versions
    "tldswap",
    "homophones",
}


class LookalikeEngine(BaseEngine):
    """Generate lookalike domain candidates and verify which ones exist."""

    @property
    def name(self) -> str:
        return "lookalike"

    @property
    def supported_asset_types(self) -> List[str]:
        return ["domain"]

    def execute(self, ctx: ScanContext, config: Dict[str, Any]) -> EngineResult:
        result = EngineResult(engine_name=self.name)

        asset = db.session.get(Asset, ctx.asset_id)
        if not asset:
            result.add_error("asset not found")
            result.success = False
            return result

        # Guard 1: customer must have explicitly opted this asset in.
        if not getattr(asset, "lookalike_watch", False):
            result.data = {
                "candidate_count": 0,
                "verified_hits": [],
                "rate_limited": False,
                "skipped_reason": "not_watched",
            }
            return result

        # Guard 2: 6-day self-rate-limit so manual triggers don't burn
        # external lookups. The scheduler also respects this window.
        last = getattr(asset, "last_lookalike_scan_at", None)
        cutoff = datetime.now(timezone.utc) - timedelta(days=RATE_LIMIT_DAYS)
        if last is not None:
            last_aware = last if last.tzinfo else last.replace(tzinfo=timezone.utc)
            if last_aware > cutoff:
                result.data = {
                    "candidate_count": 0,
                    "verified_hits": [],
                    "rate_limited": True,
                }
                logger.info(
                    "lookalike_engine: %s skipped (last scan %s, within %dd window)",
                    asset.value, last_aware.isoformat(), RATE_LIMIT_DAYS,
                )
                return result

        # Generate variants via dnstwist. The import is lazy so a missing
        # dependency in dev doesn't break unrelated scans.
        try:
            from dnstwist import Fuzzer
        except ImportError:
            logger.exception("lookalike_engine: dnstwist not installed")
            result.success = False
            result.add_error("dnstwist not installed")
            return result

        try:
            fuzz = Fuzzer(asset.value)
            fuzz.generate()
            all_variants = fuzz.domains
        except Exception:
            logger.exception("lookalike_engine: dnstwist generation failed for %s", asset.value)
            result.success = False
            result.add_error("variant generation failed")
            return result

        # Filter to included families, drop the original, drop dupes,
        # special-case the cap for homoglyph (high volume per the family's
        # nature; we keep only the first MAX_HOMOGLYPH_VARIANTS of them).
        seen: set[str] = set()
        candidates: List[tuple[str, str]] = []
        homoglyph_kept = 0
        for d in all_variants:
            domain = d.get("domain-name") or d.get("domain")
            family = d.get("fuzzer") or "unknown"
            if not domain or domain == asset.value:
                continue
            if family not in INCLUDED_FAMILIES:
                continue
            if domain in seen:
                continue
            if family == "homoglyph":
                if homoglyph_kept >= MAX_HOMOGLYPH_VARIANTS:
                    continue
                homoglyph_kept += 1
            seen.add(domain)
            candidates.append((domain, family))
            if len(candidates) >= MAX_CANDIDATES_PER_RUN:
                break

        logger.info(
            "lookalike_engine: %s generated %d candidates (from %d raw, %d homoglyph kept)",
            asset.value, len(candidates), len(all_variants), homoglyph_kept,
        )

        # Verify each candidate concurrently. Each check returns None on
        # failure so the aggregator can carry on with whatever signals
        # succeeded.
        verified: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {
                pool.submit(_verify_candidate, domain, family): (domain, family)
                for domain, family in candidates
            }
            for fut in as_completed(futures):
                try:
                    hit = fut.result()
                except Exception:
                    logger.exception(
                        "lookalike_engine: verifier crashed for %s",
                        futures[fut][0],
                    )
                    continue
                if hit:
                    verified.append(hit)

        # Persist the scan timestamp so the next 6 days short-circuit.
        try:
            asset.last_lookalike_scan_at = datetime.now(timezone.utc)
            db.session.commit()
        except Exception:
            logger.exception("lookalike_engine: failed to update last_lookalike_scan_at")
            db.session.rollback()

        result.data = {
            "candidate_count": len(candidates),
            "verified_hits": verified,
            "rate_limited": False,
            "parent_domain": asset.value,
        }
        result.metadata = {
            "max_workers": MAX_WORKERS,
            "rate_limit_days": RATE_LIMIT_DAYS,
        }
        return result


# ─────────────────────────────────────────────────────────────────────
# Per-candidate verification
# ─────────────────────────────────────────────────────────────────────


def _verify_candidate(domain: str, family: str) -> Optional[Dict[str, Any]]:
    """
    Probe one candidate domain. Returns a hit dict if any signal is
    positive; None if the candidate is unregistered / fully cold.
    Never raises.
    """
    dns_records = _resolve_dns(domain)
    http_80 = _http_head(f"http://{domain}/", HTTP_TIMEOUT)
    http_443 = _http_head(f"https://{domain}/", HTTP_TIMEOUT)
    cert_count, cert_first_seen = _ct_log_search(domain)

    has_dns = bool(dns_records)
    has_http = http_80 is not None or http_443 is not None
    has_cert = cert_count > 0

    if not (has_dns or has_http or has_cert):
        return None

    return {
        "variant_domain": domain,
        "variant_family": family,
        "dns_a_records": dns_records,
        "http_80_status": http_80,
        "http_443_status": http_443,
        "cert_seen_count": cert_count,
        "cert_first_seen": cert_first_seen,
    }


def _resolve_dns(domain: str) -> List[str]:
    """Return list of A-record IPs, or empty list on any failure."""
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(domain, "A")
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def _http_head(url: str, timeout: int) -> Optional[int]:
    """HEAD the URL. Returns status code on response, None on any error."""
    try:
        resp = requests.head(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "Nano-EASM-LookalikeProbe/1.0"},
        )
        return resp.status_code
    except requests.RequestException:
        return None


def _ct_log_search(domain: str) -> tuple[int, Optional[str]]:
    """
    Search crt.sh CT log mirror for the exact domain. Returns
    (cert_count, first_seen_iso). first_seen_iso is None when no certs.

    crt.sh returns a JSON array of entries; we count those issued in
    the last CERT_RECENT_DAYS and capture the earliest entry_timestamp.
    """
    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": domain, "output": "json"},
            timeout=CRTSH_TIMEOUT,
            headers={"User-Agent": "Nano-EASM-LookalikeProbe/1.0"},
        )
        if resp.status_code != 200:
            return (0, None)
        payload = resp.json()
    except (requests.RequestException, ValueError):
        return (0, None)

    if not isinstance(payload, list) or not payload:
        return (0, None)

    cutoff = datetime.now(timezone.utc) - timedelta(days=CERT_RECENT_DAYS)
    recent = 0
    earliest_iso: Optional[str] = None
    earliest_dt: Optional[datetime] = None
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        ts_raw = entry.get("entry_timestamp") or entry.get("not_before")
        if not isinstance(ts_raw, str):
            continue
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if ts > cutoff:
            recent += 1
        if earliest_dt is None or ts < earliest_dt:
            earliest_dt = ts
            earliest_iso = ts.isoformat()
    return (recent, earliest_iso)
