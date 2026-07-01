import pytest

# The live server needs the optional `mcp` transport. Skip cleanly if absent so
# the core suite stays offline and fast.
pytest.importorskip("mcp")


def test_server_exposes_role_filtered_tools():
    from mcp_guardrail.server import build_server

    analyst = build_server(role="analyst")
    admin = build_server(role="admin")
    assert analyst.name == "mcp-guardrail-gateway"
    # FastMCP exposes registered tools; admin has send_email, analyst does not.
    analyst_names = _tool_names(analyst)
    admin_names = _tool_names(admin)
    assert "read_file" in analyst_names
    assert "send_email" not in analyst_names
    assert "send_email" in admin_names


def _tool_names(server) -> set[str]:
    import anyio

    tools = anyio.run(server.list_tools)
    return {t.name for t in tools}
