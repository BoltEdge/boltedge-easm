# app/services/page_signals.py
"""
Pure-function utilities for the Site Mimic Watch matcher.

Each function is I/O-free and trivially unit-testable. The engine
caller wires these into a pipeline:

  fetch_html(url) -> structural_hash + extract_key_strings
  fetch_image(favicon_url) -> favicon_perceptual_hash
  render_screenshot(url) -> visual_perceptual_hash

Hash distances are computed via hamming_distance for 64-bit
perceptual hashes (returned as 16-char hex strings) or via the
jaccard helper for key-string sets.
"""
from __future__ import annotations

import hashlib
import io
import re
from typing import Any, Dict, List, Optional, Sequence


# ─────────────────────────────────────────────────────────────────────
# DOM structural hash
# ─────────────────────────────────────────────────────────────────────


# A small ignore-list of structural noise that varies between renders
# without changing the "this is a clone" signal — script src URLs,
# inline event handlers, dynamic class names like Tailwind's hash
# suffixes. Including them in the hash makes the matcher brittle.
_NOISE_ATTRS = {"src", "href", "id", "data-*"}


def structural_hash(html: str) -> str:
    """Hash the DOM tag-tree to a stable 64-bit hex string.

    The hash captures the structural skeleton (tag names + nesting
    depth) but ignores attributes whose values are inherently
    per-render unique (URLs, IDs, inline scripts). Two pages that
    were generated from the same template produce identical hashes
    even when the rendered text differs.
    """
    if not html:
        return "0" * 16
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        # Fall back to a regex-based tag extraction — works well
        # enough for the common case.
        tags = re.findall(r"<\s*([a-zA-Z][a-zA-Z0-9-]*)\b", html)
        skeleton = ",".join(t.lower() for t in tags[:2000])
        return hashlib.sha256(skeleton.encode("utf-8")).hexdigest()[:16]

    soup = BeautifulSoup(html, "html.parser")
    parts: List[str] = []

    def walk(node, depth: int):
        if depth > 30:
            return
        name = getattr(node, "name", None)
        if not name:
            return
        # Class names sans dynamic / build-hash suffixes; sorted so
        # template-order shuffles don't break the hash.
        classes = node.get("class") or []
        stable_classes = sorted(
            c for c in classes
            if c and not _looks_dynamic(c)
        )
        parts.append(f"{depth}:{name.lower()}:{'.'.join(stable_classes)}")
        for child in getattr(node, "children", []):
            walk(child, depth + 1)

    walk(soup, 0)
    skeleton = "|".join(parts[:4000])
    return hashlib.sha256(skeleton.encode("utf-8")).hexdigest()[:16]


_DYNAMIC_CLASS_PATTERNS = (
    re.compile(r"^css-[a-z0-9]{4,}$"),       # emotion / styled-components
    re.compile(r"^_[a-zA-Z0-9_-]{6,}$"),     # CSS Modules
    re.compile(r"[A-Za-z0-9]{8,}$"),         # hash-suffixed class names
)


def _looks_dynamic(class_name: str) -> bool:
    """Heuristic: does this class name look like a build-time hash?"""
    return any(p.match(class_name) for p in _DYNAMIC_CLASS_PATTERNS)


# ─────────────────────────────────────────────────────────────────────
# Perceptual image hash
# ─────────────────────────────────────────────────────────────────────


def favicon_perceptual_hash(image_bytes: bytes) -> Optional[str]:
    """Return a 64-bit dhash of the favicon as a hex string.

    Falls back to None if the image is unreadable. The favicon signal
    is high-value precisely because most phishing kits reuse the
    original favicon — replacing it requires extra effort and breaks
    the visual identity the attacker is trying to copy."""
    return _dhash_image(image_bytes)


def visual_perceptual_hash(image_bytes: bytes) -> Optional[str]:
    """Same as favicon_perceptual_hash but for the full-page render.

    Implementation detail: 9-bit dhash (16x16 sample) — same as
    favicon, since we treat both as 64-bit fingerprints downstream.
    Could swap to phash later if false-positive rate is too high."""
    return _dhash_image(image_bytes)


def _dhash_image(image_bytes: bytes) -> Optional[str]:
    """Compute a 64-bit dhash. Returns hex string or None on failure."""
    if not image_bytes:
        return None
    try:
        from PIL import Image
        import imagehash
    except ImportError:
        return None
    try:
        img = Image.open(io.BytesIO(image_bytes))
        h = imagehash.dhash(img, hash_size=8)  # 8*8 = 64 bits
        return str(h)
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────
# Hash distance
# ─────────────────────────────────────────────────────────────────────


def hamming_distance(a: Optional[str], b: Optional[str]) -> int:
    """Hamming distance between two hex-encoded hashes.

    Returns 64 (= maximum distance for a 64-bit hash) when either
    operand is None or unparseable, so a missing signal contributes
    zero to the match score downstream."""
    if not a or not b:
        return 64
    try:
        ai = int(a, 16)
        bi = int(b, 16)
    except (ValueError, TypeError):
        return 64
    return bin(ai ^ bi).count("1")


def hash_similarity(a: Optional[str], b: Optional[str], bits: int = 64) -> float:
    """1.0 = identical, 0.0 = maximally different."""
    return 1.0 - (hamming_distance(a, b) / bits)


# ─────────────────────────────────────────────────────────────────────
# Key-string extraction
# ─────────────────────────────────────────────────────────────────────


def extract_key_strings(html: str, *, brand_keywords: Sequence[str] = ()) -> Dict[str, Any]:
    """Pull the high-signal text fragments from a page.

    Returns a dict with title, h1, brand_mentions (which brand
    keywords were observed in the body), and tokens (the set of
    distinctive tokens used for jaccard comparison)."""
    if not html:
        return {"title": "", "h1": [], "brand_mentions": [], "tokens": []}

    try:
        from bs4 import BeautifulSoup
    except ImportError:
        # Regex fallback — good enough
        title_m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
        title = (title_m.group(1) if title_m else "").strip()[:255]
        h1s = re.findall(r"<h1[^>]*>([^<]+)</h1>", html, re.I)
        h1s = [h.strip()[:255] for h in h1s if h.strip()][:5]
        body = re.sub(r"<[^>]+>", " ", html).lower()
    else:
        soup = BeautifulSoup(html, "html.parser")
        title = (soup.title.string if soup.title else "") or ""
        title = title.strip()[:255]
        h1s = [h.get_text(" ", strip=True)[:255]
               for h in soup.find_all("h1")[:5] if h.get_text(strip=True)]
        body = soup.get_text(" ", strip=True).lower()

    brand_mentions = [
        bk for bk in brand_keywords if bk and bk.lower() in body
    ]

    # Tokens for jaccard: lowercased words from title + h1s, plus
    # brand mentions if any. Bounded so the jaccard set stays small.
    bag = (title + " " + " ".join(h1s)).lower()
    raw_tokens = re.findall(r"[a-z][a-z0-9-]{2,}", bag)
    tokens = sorted(set(raw_tokens))[:50]

    return {
        "title": title,
        "h1": h1s,
        "brand_mentions": brand_mentions,
        "tokens": tokens,
    }


def jaccard_similarity(a: Sequence[str], b: Sequence[str]) -> float:
    """Standard jaccard. Returns 0.0 if both empty (no match signal)."""
    sa, sb = set(a or []), set(b or [])
    if not sa and not sb:
        return 0.0
    union = sa | sb
    return len(sa & sb) / len(union)


# ─────────────────────────────────────────────────────────────────────
# Composite score
# ─────────────────────────────────────────────────────────────────────


SIGNAL_WEIGHTS: Dict[str, float] = {
    "visual": 0.45,
    "favicon": 0.30,
    "structural": 0.15,
    "text": 0.10,
}


def composite_score(scores: Dict[str, float]) -> float:
    """Combine per-signal scores into a single 0-1 number.

    Implementation: max(weighted_average, max_single_signal).

    The max-single-signal override catches the case where the
    attacker mimics one dimension perfectly (e.g. pixel-perfect
    visual clone) but defeats the others (rewritten HTML, new
    favicon). A visual_score of 0.95 alone should still produce
    a high-severity finding even if the weighted average lands
    at 0.55."""
    if not scores:
        return 0.0
    weighted = sum(
        SIGNAL_WEIGHTS.get(k, 0.0) * float(scores.get(k, 0.0))
        for k in SIGNAL_WEIGHTS
    )
    max_single = max((float(v) for v in scores.values()), default=0.0)
    return max(weighted, max_single)


def severity_for_composite(composite: float) -> Optional[str]:
    """Return the severity bucket for a composite score, or None when
    the score is below the no-finding threshold (0.40)."""
    if composite >= 0.85:
        return "critical"
    if composite >= 0.70:
        return "high"
    if composite >= 0.55:
        return "medium"
    if composite >= 0.40:
        return "low"
    return None
