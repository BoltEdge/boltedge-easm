"""Tests for app.scanner.analyzers.lookalike_analyzer.

Covers:
  - severity heuristic across every signal-mix combination
  - FindingDraft shape (template_id, tags, category, dedupe)
  - empty / malformed engine output handled cleanly
"""
from app.scanner.analyzers.lookalike_analyzer import LookalikeAnalyzer
from app.scanner.base import EngineResult, ScanContext


def _ctx_with_hits(hits, parent="example.com"):
    ctx = ScanContext(
        asset_id=1,
        asset_type="domain",
        asset_value=parent,
        organization_id=1,
        scan_job_id=99,
    )
    ctx.engine_results["lookalike"] = EngineResult(
        engine_name="lookalike",
        success=True,
        data={"verified_hits": hits, "parent_domain": parent},
    )
    return ctx


def _hit(
    domain="exampe.com",
    family="omission",
    dns=None,
    http_80=None,
    http_443=None,
    cert_count=0,
    cert_first_seen=None,
):
    return {
        "variant_domain": domain,
        "variant_family": family,
        "dns_a_records": dns if dns is not None else [],
        "http_80_status": http_80,
        "http_443_status": http_443,
        "cert_seen_count": cert_count,
        "cert_first_seen": cert_first_seen,
    }


def test_severity_high_when_live_http_plus_recent_cert():
    drafts = LookalikeAnalyzer().analyze(_ctx_with_hits([
        _hit(http_443=200, dns=["1.2.3.4"], cert_count=2, cert_first_seen="2026-04-01T00:00:00+00:00"),
    ]))
    assert drafts[0].severity == "high"


def test_severity_medium_when_dns_resolves_plus_cert():
    drafts = LookalikeAnalyzer().analyze(_ctx_with_hits([
        _hit(dns=["1.2.3.4"], cert_count=1, cert_first_seen="2025-01-01T00:00:00+00:00"),
    ]))
    assert drafts[0].severity == "medium"


def test_severity_low_when_dns_only():
    drafts = LookalikeAnalyzer().analyze(_ctx_with_hits([
        _hit(dns=["1.2.3.4"]),
    ]))
    assert drafts[0].severity == "low"


def test_severity_low_when_cert_only_no_dns():
    drafts = LookalikeAnalyzer().analyze(_ctx_with_hits([
        _hit(cert_count=2, cert_first_seen="2026-04-01T00:00:00+00:00"),
    ]))
    assert drafts[0].severity == "low"


def test_no_finding_when_no_signals():
    """Belt-and-braces — engine should already drop these, but defend
    in depth."""
    drafts = LookalikeAnalyzer().analyze(_ctx_with_hits([
        _hit(),  # all signals empty
    ]))
    assert drafts == []


def test_finding_shape_complete():
    drafts = LookalikeAnalyzer().analyze(_ctx_with_hits([
        _hit(domain="exámple.com", family="homoglyph", dns=["1.2.3.4"]),
    ], parent="example.com"))
    d = drafts[0]
    assert d.template_id == "lookalike-exámple.com"
    assert d.title == "Lookalike domain: exámple.com"
    assert d.category == "lookalike"
    assert d.finding_type == "lookalike"
    assert d.engine == "lookalike"
    assert "lookalike" in d.tags
    assert "homoglyph" in d.tags
    assert d.confidence == "high"  # DNS resolves
    assert d.dedupe_fields == {"variant_domain": "exámple.com"}
    assert d.details["variant_domain"] == "exámple.com"
    assert d.details["parent_domain"] == "example.com"
    assert d.details["variant_family"] == "homoglyph"


def test_dedupe_stable_across_repeated_scans():
    """Same variant detected twice must produce drafts that dedupe to
    the same Finding row."""
    drafts_a = LookalikeAnalyzer().analyze(_ctx_with_hits([
        _hit(domain="exampe.com", dns=["1.2.3.4"]),
    ]))
    drafts_b = LookalikeAnalyzer().analyze(_ctx_with_hits([
        _hit(domain="exampe.com", dns=["1.2.3.4", "5.6.7.8"]),  # IPs changed
    ]))
    assert drafts_a[0].template_id == drafts_b[0].template_id
    assert drafts_a[0].dedupe_fields == drafts_b[0].dedupe_fields


def test_confidence_medium_when_no_dns_resolution():
    drafts = LookalikeAnalyzer().analyze(_ctx_with_hits([
        _hit(cert_count=1, cert_first_seen="2026-04-01T00:00:00+00:00"),
    ]))
    assert drafts[0].confidence == "medium"


def test_handles_empty_engine_data():
    ctx = ScanContext(
        asset_id=1, asset_type="domain", asset_value="example.com",
        organization_id=1, scan_job_id=99,
    )
    ctx.engine_results["lookalike"] = EngineResult(
        engine_name="lookalike", success=True, data={},
    )
    drafts = LookalikeAnalyzer().analyze(ctx)
    assert drafts == []


def test_skips_malformed_hit():
    drafts = LookalikeAnalyzer().analyze(_ctx_with_hits([
        "not a dict",
        _hit(dns=["1.2.3.4"]),
    ]))
    assert len(drafts) == 1
    assert drafts[0].dedupe_fields["variant_domain"] == "exampe.com"
