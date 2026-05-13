"""Tests for github_writer.create_pr — opens branch + commits files + opens PR."""
import base64
from unittest.mock import patch, MagicMock
import pytest

from app.agents.tools.github_writer import create_pr


def _mock_response(status_code=200, json_body=None, text=""):
    r = MagicMock()
    r.status_code = status_code
    r.json = MagicMock(return_value=json_body or {})
    r.text = text
    return r


def test_create_pr_happy_path(monkeypatch, db_session):
    monkeypatch.setenv("GITHUB_TOKEN_AGENTS", "ghp_fake_test_token")

    from app.agents.memory import write_team_memory
    write_team_memory(
        "github:repo_slug",
        {"rule": "Source code is at github.com/BoltEdge/boltedge-easm."},
        ["fact", "github"],
    )

    fake_get = _mock_response(200, {"object": {"sha": "basesha123"}})
    fake_create_ref = _mock_response(201, {"ref": "refs/heads/rob/test"})
    fake_put = _mock_response(201, {"content": {"sha": "file_sha"}})
    fake_create_pr = _mock_response(201, {
        "html_url": "https://github.com/BoltEdge/boltedge-easm/pull/42",
        "number": 42,
    })

    def _route(method, url, **kw):
        if method == "GET" and "/git/ref/heads/" in url:
            return fake_get
        if method == "POST" and url.endswith("/git/refs"):
            return fake_create_ref
        if method == "PUT" and "/contents/" in url:
            return fake_put
        if method == "POST" and url.endswith("/pulls"):
            return fake_create_pr
        raise AssertionError(f"unexpected {method} {url}")

    with patch("app.agents.tools.github_writer.requests.request",
                side_effect=_route):
        result = create_pr({
            "branch_name": "rob/test",
            "base": "master",
            "commit_message": "test commit",
            "files": [
                {"path": "backend/test.py", "content": "print('hi')\n"},
            ],
            "pr_title": "Test PR",
            "pr_body": "Test body — covers test_x in test_x.py",
        })

    assert result["pr_url"] == "https://github.com/BoltEdge/boltedge-easm/pull/42"
    assert result["pr_number"] == 42
    assert result["branch"] == "rob/test"


def test_create_pr_missing_token_raises(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN_AGENTS", raising=False)
    with pytest.raises(RuntimeError, match="GITHUB_TOKEN_AGENTS"):
        create_pr({
            "branch_name": "rob/x", "base": "master",
            "commit_message": "x", "files": [{"path": "a", "content": "b"}],
            "pr_title": "x", "pr_body": "y" * 60,
        })


def test_create_pr_surfaces_github_422(monkeypatch, db_session):
    monkeypatch.setenv("GITHUB_TOKEN_AGENTS", "ghp_test")
    from app.agents.memory import write_team_memory
    write_team_memory(
        "github:repo_slug",
        {"rule": "Source code is at github.com/BoltEdge/boltedge-easm."},
        ["fact"],
    )

    fake_get = _mock_response(200, {"object": {"sha": "basesha"}})
    fake_422 = _mock_response(422, {"message": "Reference already exists"},
                                text='{"message":"Reference already exists"}')

    def _route(method, url, **kw):
        if method == "GET":
            return fake_get
        return fake_422

    with patch("app.agents.tools.github_writer.requests.request",
                side_effect=_route):
        with pytest.raises(RuntimeError, match="422"):
            create_pr({
                "branch_name": "rob/existing", "base": "master",
                "commit_message": "x",
                "files": [{"path": "a.py", "content": "x"}],
                "pr_title": "Test", "pr_body": "Body — see test_a",
            })
