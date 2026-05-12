from unittest.mock import patch, MagicMock
from app.agents.tools.github import github_query_handler


def test_github_query_calls_api(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN_AGENTS", "ghp_fake_token")

    fake = MagicMock()
    fake.status_code = 200
    fake.text = '[{"sha":"abc123","commit":{"message":"hello"}}]'
    fake.raise_for_status = MagicMock()

    with patch("app.agents.tools.github.requests.get", return_value=fake) as m:
        result = github_query_handler(endpoint="repos/foo/bar/commits")
        assert "abc123" in result
        called_url = m.call_args[0][0]
        assert called_url == "https://api.github.com/repos/foo/bar/commits"
        headers = m.call_args[1]["headers"]
        assert "token" in headers["Authorization"]


def test_github_query_passes_params(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN_AGENTS", "ghp_fake_token")

    fake = MagicMock()
    fake.status_code = 200
    fake.text = "[]"
    fake.raise_for_status = MagicMock()
    with patch("app.agents.tools.github.requests.get", return_value=fake) as m:
        github_query_handler(endpoint="repos/foo/bar/pulls",
                              params={"state": "merged", "per_page": 5})
        kw = m.call_args[1]
        assert kw["params"] == {"state": "merged", "per_page": 5}


def test_github_query_rejects_full_urls(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN_AGENTS", "ghp_fake_token")
    result = github_query_handler(endpoint="https://api.github.com/repos/foo/bar")
    assert "rejected" in result.lower() or "relative path" in result.lower()


def test_github_query_surfaces_rate_limit(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN_AGENTS", "ghp_fake_token")
    fake = MagicMock()
    fake.status_code = 403
    fake.headers = {
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": "1735689600",
    }
    fake.text = '{"message":"API rate limit exceeded"}'

    def _raise(*a, **kw):
        from requests.exceptions import HTTPError
        raise HTTPError(response=fake)
    fake.raise_for_status = _raise

    with patch("app.agents.tools.github.requests.get", return_value=fake):
        result = github_query_handler(endpoint="repos/foo/bar")
        assert "rate limit" in result.lower()
        assert "remaining" in result.lower() or "reset" in result.lower()


def test_github_query_missing_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN_AGENTS", raising=False)
    result = github_query_handler(endpoint="repos/foo/bar")
    assert "GITHUB_TOKEN_AGENTS" in result
