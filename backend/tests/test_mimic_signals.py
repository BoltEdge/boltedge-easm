"""Tests for app.services.page_signals.

Pure-function tests — no I/O, no app context, no DB. The point of
keeping the signal layer free of side effects is that we can exercise
the matcher math with confidence the engine glue won't surprise us.
"""
from app.services import page_signals as ps


# ─────────────────────────────────────────────────────────────────────
# structural_hash
# ─────────────────────────────────────────────────────────────────────


def test_structural_hash_deterministic_for_same_html():
    html = "<html><body><div class='wrap'><h1>Hi</h1></div></body></html>"
    assert ps.structural_hash(html) == ps.structural_hash(html)


def test_structural_hash_changes_for_different_structure():
    a = "<html><body><div><h1>Hi</h1></div></body></html>"
    b = "<html><body><div><h2>Hi</h2></div></body></html>"  # h1 -> h2
    assert ps.structural_hash(a) != ps.structural_hash(b)


def test_structural_hash_ignores_text_content():
    """Two pages with identical structure but different text should
    produce identical hashes — text is captured by key_strings, not
    by structure."""
    a = "<html><body><h1>Welcome to Acme</h1></body></html>"
    b = "<html><body><h1>Welcome to Phisher</h1></body></html>"
    assert ps.structural_hash(a) == ps.structural_hash(b)


def test_structural_hash_handles_empty():
    assert ps.structural_hash("") == "0" * 16
    # Also doesn't crash on malformed input
    h = ps.structural_hash("not html at all <<<>>>")
    assert isinstance(h, str)


# ─────────────────────────────────────────────────────────────────────
# Hash distance + similarity
# ─────────────────────────────────────────────────────────────────────


def test_hamming_distance_zero_for_identical():
    assert ps.hamming_distance("abcdef0123456789", "abcdef0123456789") == 0


def test_hamming_distance_max_for_inverse():
    assert ps.hamming_distance("0000000000000000", "ffffffffffffffff") == 64


def test_hamming_distance_none_inputs_return_max():
    assert ps.hamming_distance(None, "abc") == 64
    assert ps.hamming_distance("abc", None) == 64
    assert ps.hamming_distance(None, None) == 64


def test_hash_similarity_bounds():
    assert ps.hash_similarity("abcdef0123456789", "abcdef0123456789") == 1.0
    assert ps.hash_similarity("0000000000000000", "ffffffffffffffff") == 0.0


# ─────────────────────────────────────────────────────────────────────
# Key-string extraction + jaccard
# ─────────────────────────────────────────────────────────────────────


def test_extract_key_strings_basic():
    html = """
    <html>
      <head><title>Login — Acme Bank</title></head>
      <body><h1>Sign in to your account</h1></body>
    </html>
    """
    out = ps.extract_key_strings(html, brand_keywords=["acme"])
    assert "Login" in out["title"]
    assert any("Sign in" in h for h in out["h1"])
    assert "acme" in out["brand_mentions"]
    assert isinstance(out["tokens"], list)
    assert len(out["tokens"]) > 0


def test_extract_key_strings_empty_html():
    out = ps.extract_key_strings("", brand_keywords=["acme"])
    assert out["title"] == ""
    assert out["h1"] == []
    assert out["brand_mentions"] == []
    assert out["tokens"] == []


def test_jaccard_similarity_identical():
    assert ps.jaccard_similarity(["a", "b", "c"], ["a", "b", "c"]) == 1.0


def test_jaccard_similarity_disjoint():
    assert ps.jaccard_similarity(["a", "b"], ["c", "d"]) == 0.0


def test_jaccard_similarity_both_empty():
    assert ps.jaccard_similarity([], []) == 0.0


def test_jaccard_similarity_partial():
    score = ps.jaccard_similarity(["a", "b", "c"], ["b", "c", "d"])
    # 2 in common, 4 in union -> 0.5
    assert score == 0.5


# ─────────────────────────────────────────────────────────────────────
# Composite scoring
# ─────────────────────────────────────────────────────────────────────


def test_composite_max_single_signal_overrides_weighted_avg():
    """A perfect visual match with everything else at zero should still
    produce a high composite via the max-single-signal override."""
    scores = {"visual": 0.95, "favicon": 0.0, "structural": 0.0, "text": 0.0}
    c = ps.composite_score(scores)
    assert c >= 0.85


def test_composite_weighted_avg_when_no_strong_single():
    scores = {"visual": 0.5, "favicon": 0.5, "structural": 0.5, "text": 0.5}
    c = ps.composite_score(scores)
    # Either the weighted-avg arm or the max-single arm is fine here;
    # both should produce 0.5.
    assert abs(c - 0.5) < 1e-6


def test_composite_returns_zero_for_empty():
    assert ps.composite_score({}) == 0.0


def test_severity_buckets():
    assert ps.severity_for_composite(0.92) == "critical"
    assert ps.severity_for_composite(0.85) == "critical"
    assert ps.severity_for_composite(0.84) == "high"
    assert ps.severity_for_composite(0.70) == "high"
    assert ps.severity_for_composite(0.69) == "medium"
    assert ps.severity_for_composite(0.55) == "medium"
    assert ps.severity_for_composite(0.54) == "low"
    assert ps.severity_for_composite(0.40) == "low"
    assert ps.severity_for_composite(0.39) is None
    assert ps.severity_for_composite(0.0) is None


def test_perceptual_hash_returns_none_for_empty_bytes():
    assert ps.favicon_perceptual_hash(b"") is None
    assert ps.visual_perceptual_hash(b"") is None
