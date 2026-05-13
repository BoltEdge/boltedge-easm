from app.agents.tools import ToolDef, TOOL_REGISTRY


def test_tooldef_defaults_requires_approval_to_false():
    def _noop(**kwargs):
        return ""

    t = ToolDef(
        name="x_default",
        description="d",
        input_schema={"type": "object", "properties": {}, "required": []},
        handler=_noop,
        idempotent=True,
        result_cap_bytes=100,
    )
    assert t.requires_approval is False
    assert t.action_type is None


def test_tooldef_accepts_requires_approval_true():
    def _noop(**kwargs):
        return ""

    t = ToolDef(
        name="x_writes",
        description="d",
        input_schema={"type": "object", "properties": {}, "required": []},
        handler=_noop,
        idempotent=False,
        result_cap_bytes=0,
        requires_approval=True,
        action_type="code-pr",
    )
    assert t.requires_approval is True
    assert t.action_type == "code-pr"


def test_existing_read_tools_still_default_no_approval():
    for name in ("read_internal_api", "web_fetch", "web_search",
                 "git_read", "github_query", "read_repo_file"):
        if name in TOOL_REGISTRY:
            assert TOOL_REGISTRY[name].requires_approval is False, (
                f"{name} should default to requires_approval=False"
            )
