from app.agents.tools import TOOL_REGISTRY, expose_tools_for
from app.agents.tools.web import WEB_SEARCH_TOOL_TYPE, web_search_handler


def test_web_search_registered():
    assert "web_search" in TOOL_REGISTRY


def test_web_search_tool_spec_uses_server_side_type():
    """Server-side tools (Anthropic-native web_search) need a 'type'
    discriminator instead of an input_schema. expose_tools_for() must
    emit the server-side shape for web_search."""
    specs = expose_tools_for(["web_search"])
    assert len(specs) == 1
    assert specs[0].get("type") == WEB_SEARCH_TOOL_TYPE
    assert specs[0].get("name") == "web_search"


def test_web_search_handler_returns_passthrough_note():
    """If the local handler ever runs (shouldn't, because Anthropic
    executes server-side), it should return a clear no-op note."""
    result = web_search_handler(query="anything")
    assert ("server-side" in result.lower()
            or "handled by anthropic" in result.lower())


def test_existing_input_schema_tools_still_emit_old_shape():
    """Sanity: read_internal_api uses the input_schema shape, not the
    server_side_type shape."""
    specs = expose_tools_for(["read_internal_api"])
    assert specs[0].get("type") is None or "type" not in specs[0]
    assert "input_schema" in specs[0]
