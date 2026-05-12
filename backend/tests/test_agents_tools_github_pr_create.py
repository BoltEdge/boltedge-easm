from app.agents.tools import TOOL_REGISTRY


def test_github_pr_create_tool_is_registered():
    assert "github_pr_create" in TOOL_REGISTRY


def test_github_pr_create_is_marked_requires_approval():
    t = TOOL_REGISTRY["github_pr_create"]
    assert t.requires_approval is True
    assert t.action_type == "code-pr"


def test_github_pr_create_input_schema_requires_test_mention():
    """The tool's description must explicitly say PRs require tests
    in the body. The schema enforces pr_body minimum length."""
    t = TOOL_REGISTRY["github_pr_create"]
    desc = t.description.lower()
    assert "test" in desc
    schema = t.input_schema
    assert "files" in schema["required"]
    assert "pr_title" in schema["required"]
    assert "pr_body" in schema["required"]
    pattern = schema["properties"]["branch_name"].get("pattern")
    assert pattern is not None


def test_github_pr_create_handler_is_sentinel():
    """The actual create_pr lives in github_writer; the handler
    registered should be a sentinel that errors if called (the runtime
    must intercept on requires_approval=True)."""
    t = TOOL_REGISTRY["github_pr_create"]
    result = t.handler(
        branch_name="x", commit_message="y",
        files=[{"path": "a", "content": "b"}],
        pr_title="x", pr_body="y" * 60,
    )
    assert "should never" in result.lower() or "approval" in result.lower()
