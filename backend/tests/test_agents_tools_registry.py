from app.agents.tools import (
    TOOL_REGISTRY, ToolDef, register_tool, expose_tools_for,
    anthropic_tool_spec,
)


def test_tool_def_fields():
    def _fake_handler(**kwargs):
        return "ok"

    t = ToolDef(
        name="x_test",
        description="A test tool.",
        input_schema={"type": "object", "properties": {}, "required": []},
        handler=_fake_handler,
        idempotent=True,
        result_cap_bytes=1000,
    )
    assert t.name == "x_test"
    assert t.idempotent is True
    assert t.handler() == "ok"


def test_register_tool_adds_to_registry():
    def _fake(**kwargs):
        return "result"

    register_tool(ToolDef(
        name="x_register_test",
        description="d",
        input_schema={"type": "object", "properties": {}, "required": []},
        handler=_fake,
        idempotent=False,
        result_cap_bytes=100,
    ))
    assert "x_register_test" in TOOL_REGISTRY


def test_expose_tools_for_filters_by_allowlist():
    def _fake(**kwargs):
        return ""
    register_tool(ToolDef(
        name="x_one", description="", handler=_fake,
        input_schema={"type": "object", "properties": {}, "required": []},
        idempotent=True, result_cap_bytes=10,
    ))
    register_tool(ToolDef(
        name="x_two", description="", handler=_fake,
        input_schema={"type": "object", "properties": {}, "required": []},
        idempotent=True, result_cap_bytes=10,
    ))
    exposed = expose_tools_for(["x_one"])
    names = [t["name"] for t in exposed]
    assert names == ["x_one"]


def test_anthropic_tool_spec_shape():
    def _fake(**kwargs):
        return ""
    register_tool(ToolDef(
        name="x_spec_test",
        description="A spec test tool.",
        handler=_fake,
        input_schema={"type": "object",
                       "properties": {"q": {"type": "string"}},
                       "required": ["q"]},
        idempotent=True, result_cap_bytes=10,
    ))
    spec = anthropic_tool_spec(TOOL_REGISTRY["x_spec_test"])
    assert spec["name"] == "x_spec_test"
    assert spec["description"] == "A spec test tool."
    assert spec["input_schema"]["properties"]["q"]["type"] == "string"
