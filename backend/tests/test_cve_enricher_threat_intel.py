"""Tests that cve_enricher populates threat-intel fields on FindingDrafts.

The enricher itself is exercised end-to-end here — engine data is
synthesised in a ScanContext, enrich_cve is mocked to return predictable
KEV / EPSS payloads, and we assert the resulting FindingDraft is shaped
correctly.
"""
from unittest.mock import patch

from app.scanner.analyzers.cve_enricher import CVEEnricher
from app.scanner.base import EngineResult, ScanContext


def _ctx_with_cve(cve_id="CVE-2024-1234"):
    ctx = ScanContext(
        asset_id=1,
        asset_type="domain",
        asset_value="example.com",
        organization_id=1,
        scan_job_id=1,
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
    assert "epss-high" in d.tags  # percentile 0.95 >= 0.9
    assert d.details["kev"]["known_ransomware"] is True
    assert d.details["epss"]["score"] == 0.77


def test_cve_enricher_no_kev_no_epss_leaves_fields_blank():
    ctx = _ctx_with_cve("CVE-2024-9999")
    with patch(
        "app.scanner.analyzers.cve_enricher.enrich_cve",
        return_value={"kev": None, "epss": None},
    ):
        drafts = CVEEnricher().analyze(ctx)
    d = drafts[0]
    assert d.kev_listed is False
    assert d.epss_score is None
    assert d.epss_percentile is None
    assert "kev" not in d.tags
    assert "epss-high" not in d.tags
    assert "kev" not in d.details
    assert "epss" not in d.details


def test_cve_enricher_only_epss_present():
    ctx = _ctx_with_cve("CVE-2024-7777")
    with patch(
        "app.scanner.analyzers.cve_enricher.enrich_cve",
        return_value={"kev": None, "epss": {"score": 0.92, "percentile": 0.99}},
    ):
        drafts = CVEEnricher().analyze(ctx)
    d = drafts[0]
    assert d.kev_listed is False
    assert d.epss_score == 0.92
    assert "kev" not in d.tags
    assert "epss-high" in d.tags  # percentile 0.99 >= 0.9


def test_cve_enricher_epss_below_high_threshold_no_tag():
    """EPSS percentile under 0.9 should NOT add the 'epss-high' tag."""
    ctx = _ctx_with_cve("CVE-2024-6666")
    with patch(
        "app.scanner.analyzers.cve_enricher.enrich_cve",
        return_value={"kev": None, "epss": {"score": 0.20, "percentile": 0.60}},
    ):
        drafts = CVEEnricher().analyze(ctx)
    d = drafts[0]
    assert d.epss_score == 0.20
    assert "epss-high" not in d.tags
    assert d.details["epss"]["score"] == 0.20


def test_cve_enricher_severity_unchanged_by_kev():
    """KEV listing must not alter severity — badge-only contract."""
    ctx = _ctx_with_cve("CVE-2024-5555")
    # CVSS 7.5 → high. KEV listing must NOT bump to critical.
    with patch(
        "app.scanner.analyzers.cve_enricher.enrich_cve",
        return_value={
            "kev": {"cve_id": "CVE-2024-5555", "date_added": "2024-01-01"},
            "epss": None,
        },
    ):
        drafts = CVEEnricher().analyze(ctx)
    d = drafts[0]
    assert d.kev_listed is True
    assert d.severity == "high"  # NOT "critical"
