from unittest.mock import patch, MagicMock
from app.agents.tools.internal_api import read_internal_api_handler


def test_read_internal_api_rejects_unknown_endpoint():
    result = read_internal_api_handler(endpoint="some/random/path")
    assert "unknown endpoint" in result.lower() or "not allowed" in result.lower()


def test_read_internal_api_returns_json_string_on_success(monkeypatch):
    monkeypatch.setenv("NANOEASM_API_KEY_AGENTS_FOUNDER_OPS", "nk_agent_test")
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.text = '{"orgs_total": 42, "users_total": 75}'
    fake_response.raise_for_status = MagicMock()

    with patch("app.agents.tools.internal_api.requests.get",
                return_value=fake_response) as mock_get:
        result = read_internal_api_handler(endpoint="stats/weekly")
        assert "orgs_total" in result
        called_url = mock_get.call_args[0][0]
        assert called_url.endswith("/api/internal/stats/weekly")


def test_read_internal_api_passes_params(monkeypatch):
    monkeypatch.setenv("NANOEASM_API_KEY_AGENTS_FOUNDER_OPS", "nk_agent_test")
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.text = "[]"
    fake_response.raise_for_status = MagicMock()

    with patch("app.agents.tools.internal_api.requests.get",
                return_value=fake_response) as mock_get:
        read_internal_api_handler(endpoint="findings/recent",
                                    params={"severity": "high", "limit": 10})
        kwargs = mock_get.call_args[1]
        assert kwargs.get("params") == {"severity": "high", "limit": 10}


def test_read_internal_api_returns_error_string_on_4xx(monkeypatch):
    monkeypatch.setenv("NANOEASM_API_KEY_AGENTS_FOUNDER_OPS", "nk_agent_test")
    fake_response = MagicMock()
    fake_response.status_code = 403
    fake_response.text = '{"error":"scope_denied"}'

    def _raise(*a, **kw):
        from requests.exceptions import HTTPError
        raise HTTPError(response=fake_response)
    fake_response.raise_for_status = _raise

    with patch("app.agents.tools.internal_api.requests.get",
                return_value=fake_response):
        result = read_internal_api_handler(endpoint="stats/weekly")
        assert "403" in result or "scope_denied" in result


def test_read_internal_api_missing_env_var(monkeypatch):
    monkeypatch.delenv("NANOEASM_API_KEY_AGENTS_FOUNDER_OPS", raising=False)
    result = read_internal_api_handler(endpoint="stats/weekly")
    assert "NANOEASM_API_KEY_AGENTS_FOUNDER_OPS" in result
