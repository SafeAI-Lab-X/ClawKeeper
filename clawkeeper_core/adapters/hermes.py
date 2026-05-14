"""Hermes Agent adapter — wires ClawKeeper into NousResearch/hermes-agent.

Hermes exposes two interception surfaces we use:

1.  `tools.terminal_tool.set_approval_callback(cb)` and
    `tools.computer_use.tool.set_approval_callback(cb)` — the **gating** path.
    The callback is invoked when Hermes is about to run a dangerous command;
    its return value (one of "once" | "session" | "always" | "deny") decides
    what happens. This maps 1:1 to ClawKeeper's `Decision.outcome × scope`.

2.  ~10 observation callbacks on `AIAgent.__init__` (`tool_start_callback`,
    `tool_complete_callback`, `step_callback`, etc.) — the **telemetry** path.
    These feed the profiler / drift detector / decision memory but cannot block.

`install(judge, agent)` registers both. Hermes does not need any patches.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from clawkeeper_core.judge import Judge
from clawkeeper_core.schemas import (
    AgentEvent,
    JudgeContext,
    Outcome,
)

if TYPE_CHECKING:
    # Lazy — Hermes need not be installed for this module to import.
    from hermes_agent.run_agent import AIAgent  # noqa: F401


# Map ClawKeeper Decision -> Hermes approval-callback return string.
_HERMES_RETURN_FOR_OUTCOME = {
    Outcome.ALLOW: {"once": "once", "session": "session", "always": "always"},
    Outcome.ASK: {"once": "deny", "session": "deny", "always": "deny"},  # ask resolved upstream
    Outcome.DENY: {"once": "deny", "session": "deny", "always": "deny"},
}


def install(judge: Judge, agent: "AIAgent") -> None:
    """Wire a Judge into a constructed AIAgent.

    Call this after `AIAgent(...)` but before `agent.run(...)`.
    """
    # Lazy import — fail loudly only if Hermes really isn't there.
    from hermes_agent.tools import terminal_tool
    from hermes_agent.tools.computer_use import tool as computer_use_tool

    def approval_cb(command: str, description: str = "") -> str:
        ctx = JudgeContext(
            tool_name="bash",
            tool_args={"command": command, "description": description},
            messages=_recent_messages(agent),
            agent_id=getattr(agent, "session_id", None),
            session_id=getattr(agent, "session_id", None),
            metadata={"source": "hermes.terminal_tool"},
        )
        decision = judge.evaluate(ctx)
        return _HERMES_RETURN_FOR_OUTCOME[decision.outcome][decision.scope.value]

    terminal_tool.set_approval_callback(approval_cb)
    computer_use_tool.set_approval_callback(approval_cb)

    # Observation hooks — fire-and-forget, never block.
    _register_observers(judge, agent)


# ─── helpers ────────────────────────────────────────────────────────────────


def _recent_messages(agent: Any, n: int = 20) -> list:
    """Pull the last N messages out of the Hermes agent state, if accessible."""
    history = getattr(agent, "conversation_history", None) or []
    return history[-n:]


def _register_observers(judge: Judge, agent: Any) -> None:
    """Replace agent.*_callback attributes with wrapped versions.

    Hermes lets you set these on the instance directly; the agent's loop reads
    them on each step, so overwriting after `__init__` is safe.
    """
    prev_tool_start = agent.tool_start_callback
    prev_tool_complete = agent.tool_complete_callback

    def on_tool_start(name: str, args_preview: Any = None) -> None:
        _emit(judge, AgentEvent(
            ts=_now(),
            agent_id=getattr(agent, "session_id", "unknown"),
            session_id=getattr(agent, "session_id", None),
            kind="tool_start",
            payload={"name": name, "args_preview": _stringify(args_preview)},
        ))
        if prev_tool_start:
            prev_tool_start(name, args_preview)

    def on_tool_complete(name: str, args: Any = None, result: Any = None) -> None:
        _emit(judge, AgentEvent(
            ts=_now(),
            agent_id=getattr(agent, "session_id", "unknown"),
            session_id=getattr(agent, "session_id", None),
            kind="tool_complete",
            payload={"name": name, "result_preview": _stringify(result)[:500]},
        ))
        if prev_tool_complete:
            prev_tool_complete(name, args, result)

    agent.tool_start_callback = on_tool_start
    agent.tool_complete_callback = on_tool_complete


def _emit(judge: Judge, event: AgentEvent) -> None:
    profiler = getattr(judge, "profiler", None)
    if profiler is not None:
        profiler.update(event)


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def _stringify(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return "<unprintable>"
