"""MCP gateway adapter tests.

Skip cleanly when the `mcp` package isn't installed.
"""

from __future__ import annotations

import pytest

mcp = pytest.importorskip("mcp", reason="mcp package not installed")

from clawkeeper_core.adapters.mcp import GatewayServer  # noqa: E402
from clawkeeper_core.judge import Judge  # noqa: E402


@pytest.fixture
def server():
    return GatewayServer(name="test-gw", judge=Judge())


def test_construct_server(server):
    assert server.name == "test-gw"
    assert server.fastmcp is not None


def test_register_guarded_tool_appears_in_tool_list(server):
    @server.guarded_tool(description="echo input back")
    async def echo(message: str) -> str:
        return message

    # The FastMCP instance should now know about the tool.
    tools = list(server.fastmcp._tool_manager._tools.values())
    names = [t.name for t in tools]
    assert "echo" in names


@pytest.mark.asyncio
async def test_benign_call_returns_result(server):
    @server.guarded_tool()
    async def echo(message: str) -> str:
        return f"echoed: {message}"

    # Set autoContinueAllowed so non-dangerous tools don't get held up.
    server.judge.policy = {"autoContinueAllowed": True}
    result = await server.call_tool("echo", {"message": "hi"})
    # FastMCP wraps return values into MCP content blocks. Just check
    # that the wrapped handler ran successfully (no exception, result truthy).
    assert result is not None


@pytest.mark.asyncio
async def test_dangerous_call_raises(server):
    """A tool named "bash" should hit the high-risk branch and raise."""
    @server.guarded_tool(name="bash")
    async def bash(command: str) -> str:
        return f"ran: {command}"

    with pytest.raises(Exception):  # McpError when available, RuntimeError otherwise
        await server.call_tool("bash", {"command": "rm -rf /"})


@pytest.mark.asyncio
async def test_user_stop_command_blocks(server):
    """A session_context message containing 'stop' should propagate."""
    server.set_session_context(
        messages=[{"role": "user", "content": "stop the build"}],
    )

    @server.guarded_tool(name="anything")
    async def anything() -> str:
        return "x"

    with pytest.raises(Exception):
        await server.call_tool("anything", {})


@pytest.mark.asyncio
async def test_session_context_is_carried_into_judge(server):
    """The session_context dict ends up in forwardedContext.metadata."""
    captured: list[dict] = []

    # Hijack judge.evaluate_async to capture the payload it receives
    async def fake_evaluate(payload):
        captured.append(payload)
        return {"decision": "continue"}

    server.judge.evaluate_async = fake_evaluate  # type: ignore[method-assign]

    @server.guarded_tool(name="ping")
    async def ping() -> str:
        return "pong"

    server.set_session_context(
        messages=[{"role": "user", "content": "do ping"}],
        session_id="sess-42",
        request_id="req-7",
        custom_tag="hermes",
    )
    await server.call_tool("ping", {})

    assert len(captured) == 1
    payload = captured[0]
    assert payload["requestId"] == "req-7"
    ctx = payload["forwardedContext"]
    assert ctx["metadata"]["sessionKey"] == "sess-42"
    assert ctx["metadata"]["custom_tag"] == "hermes"
    # The user message should appear before the synthesized tool message
    roles = [m["role"] for m in ctx["messages"]]
    assert roles[0] == "user"
    assert roles[-1] == "tool"


def test_missing_mcp_pkg_raises(monkeypatch):
    """If mcp isn't importable, instantiation should refuse cleanly."""
    from clawkeeper_core.adapters import mcp as adapter_mod

    monkeypatch.setattr(adapter_mod, "_MCP_AVAILABLE", False)
    with pytest.raises(ImportError, match="mcp package is required"):
        GatewayServer(name="x")
