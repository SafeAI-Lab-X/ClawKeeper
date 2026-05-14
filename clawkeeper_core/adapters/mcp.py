"""MCP gateway adapter — wraps tools registered on a FastMCP server so
every `tools/call` invocation routes through clawkeeper-core's Judge
before reaching the tool handler.

Usage:

    from clawkeeper_core import Judge
    from clawkeeper_core.adapters.mcp import GatewayServer

    server = GatewayServer(name="clawkeeper-gw", judge=Judge())

    @server.guarded_tool(description="Run a shell command")
    async def bash(command: str) -> str:
        ...

    server.run()                # stdio transport, ready for Claude Code / Cursor

What gets routed through Judge:
  - Tool name (used as the JS-style toolName).
  - Tool arguments (collected as forwardedContext.messages tool-message).
  - Optional user-supplied context (e.g. recent messages, session id) via
    `GatewayServer.set_session_context()`.

Decision mapping:
  - "continue" → forward to the wrapped handler, return its result normally.
  - "stop"     → raise McpError (the MCP client surfaces this as a
                  CallToolResult with isError=True).
  - "ask_user" → same as "stop" for now; gateway mode has no UI to ask.
                  A follow-up will pipe ask_user through a
                  human-in-the-loop bridge.
"""

from __future__ import annotations

import functools
from typing import Any, Awaitable, Callable

try:
    from mcp.server.fastmcp import FastMCP
    from mcp.shared.exceptions import McpError
    from mcp.types import ErrorData
    _MCP_AVAILABLE = True
except ImportError:
    FastMCP = None  # type: ignore[assignment]
    McpError = Exception  # type: ignore[assignment]
    ErrorData = None  # type: ignore[assignment]
    _MCP_AVAILABLE = False

from clawkeeper_core.judge import Judge

# MCP error codes — JSON-RPC reserved range for invalid params.
_ERROR_CODE_BLOCKED = -32603  # Internal error, used here for "blocked by safety policy"


class GatewayServer:
    """A FastMCP server with every registered tool guarded by a Judge.

    The class is a thin facade — internally it holds a FastMCP instance
    and a Judge. `guarded_tool` is the only registration entry point.
    """

    def __init__(
        self,
        name: str,
        judge: Judge | None = None,
        *,
        instructions: str | None = None,
    ) -> None:
        if not _MCP_AVAILABLE:
            raise ImportError(
                "mcp package is required for GatewayServer; install with `pip install mcp`"
            )
        self.name = name
        self.judge = judge or Judge()
        self._fastmcp = FastMCP(name=name, instructions=instructions)
        self._session_context: dict[str, Any] = {}

    @property
    def fastmcp(self) -> "FastMCP":
        """Escape hatch for tests / advanced users who need direct FastMCP access."""
        return self._fastmcp

    def set_session_context(self, **context: Any) -> None:
        """Stash recent messages / session id for the Judge.

        Adapters running outside an event loop can call this to give Judge
        more signal than just (tool, args). All keys are passed through to
        `forwardedContext.metadata`; `messages` (if provided) is merged
        ahead of the synthesized tool-call message.
        """
        self._session_context = dict(context)

    def guarded_tool(
        self,
        name: str | None = None,
        description: str | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator: register a guarded tool with the underlying FastMCP."""
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or fn.__name__
            wrapped = self._wrap_with_judge(fn, tool_name)
            self._fastmcp.add_tool(wrapped, name=tool_name, description=description)
            return wrapped
        return decorator

    def add_guarded_tool(
        self,
        fn: Callable[..., Any],
        name: str | None = None,
        description: str | None = None,
    ) -> None:
        """Imperative variant of `guarded_tool` — same behavior, no decorator."""
        tool_name = name or fn.__name__
        wrapped = self._wrap_with_judge(fn, tool_name)
        self._fastmcp.add_tool(wrapped, name=tool_name, description=description)

    def _wrap_with_judge(
        self,
        fn: Callable[..., Any],
        tool_name: str,
    ) -> Callable[..., Awaitable[Any]]:
        """Build the judge-runner that replaces the original tool handler."""

        @functools.wraps(fn)
        async def runner(*args: Any, **kwargs: Any) -> Any:
            payload = self._build_judge_payload(tool_name, kwargs or {"_args": list(args)})
            result = await self.judge.evaluate_async(payload)
            decision = result.get("decision") if isinstance(result, dict) else None

            if decision == "stop":
                raise _blocked_error(result, tool_name, reason="stop")
            if decision == "ask_user":
                raise _blocked_error(result, tool_name, reason="ask_user")

            # decision in {None, "continue"} → forward to the real handler.
            outcome = fn(*args, **kwargs)
            if hasattr(outcome, "__await__"):
                return await outcome  # type: ignore[no-any-return]
            return outcome

        return runner

    def _build_judge_payload(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        session_msgs = self._session_context.get("messages") or []
        if not isinstance(session_msgs, list):
            session_msgs = []
        tool_msg = {
            "role": "tool",
            "toolName": tool_name,
            "raw": _safe_dumps(args),
        }
        return {
            "mode": self._session_context.get("mode", "local"),
            "requestId": self._session_context.get("request_id"),
            "forwardedContext": {
                "messages": [*session_msgs, tool_msg],
                "metadata": {
                    "sessionKey": self._session_context.get("session_id"),
                    **{k: v for k, v in self._session_context.items()
                       if k not in ("messages", "session_id", "request_id", "mode")},
                },
            },
        }

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        """Pass-through to FastMCP — primarily for tests."""
        return await self._fastmcp.call_tool(name, arguments)

    def run(self, transport: str = "stdio") -> None:
        """Block on the FastMCP runtime. Use `stdio` for Claude Code / Cursor."""
        self._fastmcp.run(transport=transport)


def _safe_dumps(value: Any) -> str:
    import json
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def _blocked_error(judge_result: dict[str, Any], tool_name: str, *, reason: str) -> Exception:
    summary = judge_result.get("summary") or "Tool call refused by ClawKeeper safety policy."
    stop_reason = judge_result.get("stopReason") or reason
    if ErrorData is None:
        return RuntimeError(f"{summary} (tool={tool_name}, reason={stop_reason})")
    return McpError(ErrorData(
        code=_ERROR_CODE_BLOCKED,
        message=summary,
        data={
            "tool": tool_name,
            "stopReason": stop_reason,
            "riskLevel": judge_result.get("riskLevel"),
            "judge": judge_result,
        },
    ))
