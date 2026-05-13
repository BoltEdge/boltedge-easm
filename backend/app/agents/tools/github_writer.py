"""GitHub write operations triggered by approved code-pr actions.

create_pr() is called by approvals._apply_action when a code-pr
pending_action is approved. It creates a branch off base, commits the
files, opens a PR, and returns the PR URL + number.

Failures (missing token, 4xx/5xx from GitHub, network) raise — the
caller records the error in pending_action.applied_result and surfaces
it in the approval queue UI.
"""
from __future__ import annotations
import base64
import os
import re

import requests

from app.agents.memory import retrieve_team_memory


GITHUB_API = "https://api.github.com"
TIMEOUT = 15


def _resolve_repo_slug() -> str:
    """Read the github:repo_slug fact from team_memory. The fact's
    `value.rule` field contains a sentence with the slug; we extract
    `OWNER/REPO` from a github.com URL inside it."""
    rows = retrieve_team_memory()
    for r in rows:
        if r.key == "github:repo_slug":
            text = (r.value.get("rule") if isinstance(r.value, dict) else "") or ""
            m = re.search(r"github\.com/([\w.-]+/[\w.-]+)", text)
            if m:
                return m.group(1)
    raise RuntimeError(
        "no github:repo_slug fact in team_memory; cannot determine target repo. "
        "Run scripts.seed_team_memory or add a fact pointing at github.com/<owner>/<repo>."
    )


def _req(method: str, url: str, *, token: str, json_body: dict | None = None) -> dict:
    """Issue an HTTP request to GitHub. Raises RuntimeError on non-2xx
    with the status code + body excerpt for diagnostics."""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Nano-EASM-Agent/1.0",
    }
    try:
        resp = requests.request(
            method, url, headers=headers, json=json_body, timeout=TIMEOUT,
        )
    except requests.exceptions.RequestException as e:
        raise RuntimeError(
            f"GitHub API {method} {url} failed: {type(e).__name__}: {e}"
        ) from e
    if resp.status_code >= 400:
        body_excerpt = (resp.text or "")[:500]
        raise RuntimeError(
            f"GitHub API {method} {url} returned {resp.status_code}: {body_excerpt}"
        )
    try:
        return resp.json()
    except ValueError:
        return {}


def create_pr(payload: dict) -> dict:
    """Open a PR on the Nano EASM repo per the payload.

    payload shape (validated upstream):
      branch_name: str
      base: str (default 'master')
      commit_message: str
      files: [{path: str, content: str}, ...]
      pr_title: str
      pr_body: str

    Returns:
      {pr_url: str, pr_number: int, branch: str} on success.

    Raises RuntimeError on any failure (missing token, GitHub 4xx/5xx,
    network error). Caller records the error string in
    pending_action.applied_result.

    Caveats:
      - Multi-file PRs commit files one at a time. If a later file
        fails, the branch is left with a partial commit on GitHub.
        The function does not clean up; the next re-proposal must use
        a different branch_name (the existing branch will collide with
        a 422 'Reference already exists' otherwise).
    """
    token = os.environ.get("GITHUB_TOKEN_AGENTS")
    if not token:
        raise RuntimeError(
            "GITHUB_TOKEN_AGENTS env var is not set; cannot open PR"
        )

    slug = _resolve_repo_slug()
    base = payload.get("base") or "master"
    branch = payload["branch_name"]

    # 1) Get base SHA
    ref = _req(
        "GET", f"{GITHUB_API}/repos/{slug}/git/ref/heads/{base}",
        token=token,
    )
    base_sha = ref["object"]["sha"]

    # 2) Create new branch ref
    _req(
        "POST", f"{GITHUB_API}/repos/{slug}/git/refs",
        token=token,
        json_body={"ref": f"refs/heads/{branch}", "sha": base_sha},
    )

    # 3) Commit each file via the contents API
    for f in payload["files"]:
        path = f["path"]
        content_b64 = base64.b64encode(
            f["content"].encode("utf-8")
        ).decode("ascii")
        _req(
            "PUT", f"{GITHUB_API}/repos/{slug}/contents/{path}",
            token=token,
            json_body={
                "message": payload["commit_message"],
                "content": content_b64,
                "branch": branch,
            },
        )

    # 4) Open the PR
    pr = _req(
        "POST", f"{GITHUB_API}/repos/{slug}/pulls",
        token=token,
        json_body={
            "title": payload["pr_title"],
            "body": payload["pr_body"],
            "head": branch,
            "base": base,
        },
    )

    return {
        "pr_url": pr["html_url"],
        "pr_number": pr["number"],
        "branch": branch,
    }
