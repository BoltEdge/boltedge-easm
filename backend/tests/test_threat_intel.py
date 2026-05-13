"""Tests for app.scanner.threat_intel.

The module is the single source of truth for CVE-to-KEV / CVE-to-EPSS
lookups. Tests focus on:
  - lookup_kev returns dict when row exists, None when not, None on DB error
  - lookup_epss returns cached value when fresh, fetches when stale, None on API error
  - refresh_kev_feed upserts correctly, handles HTTP failure
  - enrich_cve aggregates both correctly

All tests mock the DB and HTTP layers so they run without an app context
or a live database.
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


# ─────────────────────────────────────────────────────────────────────
# lookup_kev
# ─────────────────────────────────────────────────────────────────────


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
        mock_q.assert_called_with("CVE-2024-1234")


def test_lookup_kev_handles_empty_input():
    assert threat_intel.lookup_kev("") is None
    assert threat_intel.lookup_kev(None) is None


# ─────────────────────────────────────────────────────────────────────
# refresh_kev_feed
# ─────────────────────────────────────────────────────────────────────


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


def test_refresh_kev_feed_skips_non_cve_entries():
    fixture = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-1111", "dateAdded": "2024-01-01"},
            {"cveID": "GARBAGE-1234", "dateAdded": "2024-01-01"},   # invalid prefix
            "not a dict",                                              # not a dict
            {"cveID": "", "dateAdded": "2024-01-01"},                  # empty id
        ]
    }
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = fixture

    captured_rows = []

    def fake_upsert(rows):
        captured_rows.extend(rows)
        return len(rows)

    with patch.object(threat_intel.requests, "get", return_value=fake_response), \
         patch.object(threat_intel, "_upsert_kev_rows", side_effect=fake_upsert):
        n = threat_intel.refresh_kev_feed()

    assert n == 1
    assert len(captured_rows) == 1
    assert captured_rows[0]["cve_id"] == "CVE-2024-1111"


# ─────────────────────────────────────────────────────────────────────
# lookup_epss
# ─────────────────────────────────────────────────────────────────────


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
    assert result["stale"] is False


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
    assert result["stale"] is True


def test_lookup_epss_handles_empty_input():
    assert threat_intel.lookup_epss("") is None
    assert threat_intel.lookup_epss(None) is None


# ─────────────────────────────────────────────────────────────────────
# enrich_cve
# ─────────────────────────────────────────────────────────────────────


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
