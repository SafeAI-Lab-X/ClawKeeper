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
from clawkeeper_core.schemas import AgentEvent

if TYPE_CHECKING:
    # Lazy — Hermes need not be installed for this module to import.
    # Hermes Agent installs flat top-level modules (no `hermes_agent` namespace):
    #   - run_agent.AIAgent
    #   - tools.terminal_tool
    #   - tools.computer_use.tool
    from run_agent import AIAgent  # noqa: F401


# Map the JS-style judgement (returned as a dict by judge_forwarded_context)
# to the strings Hermes' set_approval_callback expects:
#   "once" / "session" / "always" → execute and persist at that scope
#   "deny"                        → refuse this command
#
# JS-style decisions:
#   "continue"  → allow the command (default scope: "once")
#   "stop"      → deny
#   "ask_user"  → from an approval callback we can't ask anyone — deny
_HERMES_RETURN_FOR_JS_DECISION: dict[str, str] = {
    "continue": "once",
    "stop": "deny",
    "ask_user": "deny",
}

# Backwards-compat alias for the previous Outcome-enum-keyed shape. Kept
# so consumers that imported the constant directly don't break; the live
# code path uses _HERMES_RETURN_FOR_JS_DECISION above.
_HERMES_RETURN_FOR_OUTCOME: dict = {}
try:
    from clawkeeper_core.schemas import Outcome, Scope
    _HERMES_RETURN_FOR_OUTCOME = {
        Outcome.ALLOW: {Scope.ONCE.value: "once", Scope.SESSION.value: "session", Scope.ALWAYS.value: "always"},
        Outcome.ASK: {Scope.ONCE.value: "deny", Scope.SESSION.value: "deny", Scope.ALWAYS.value: "deny"},
        Outcome.DENY: {Scope.ONCE.value: "deny", Scope.SESSION.value: "deny", Scope.ALWAYS.value: "deny"},
    }
except ImportError:
    pass


def install(judge: Judge, agent: "AIAgent") -> None:
    """Wire a Judge into a constructed AIAgent.

    Call this after `AIAgent(...)` but before `agent.run(...)`.
    """
    # Lazy import — fail loudly only if Hermes really isn't there.
    # Hermes 0.13 uses flat top-level modules: tools.terminal_tool and
    # tools.computer_use.tool (no `hermes_agent` namespace).
    import tools.terminal_tool as terminal_tool
    from tools.computer_use import tool as computer_use_tool

    def approval_cb(command: str, description: str = "") -> str:
        # judge_forwarded_context expects {mode, forwardedContext: {messages}}.
        # Build a one-shot context that re-presents the dangerous command as
        # if it had just been observed in a tool message.
        recent = _recent_messages(agent)
        forwarded_messages = [
            *(recent if isinstance(recent, list) else []),
            {"role": "tool", "toolName": "bash", "raw": command, "content": description},
        ]
        result = judge.evaluate({
            "mode": "local",
            "forwardedContext": {
                "messages": forwarded_messages,
                "metadata": {"sessionKey": getattr(agent, "session_id", None)},
            },
            "requestId": getattr(agent, "session_id", None),
        })
        # result is a dict from judge_forwarded_context. Map the JS-style
        # decision string ("continue" | "stop" | "ask_user") to a Hermes-style
        # return string ("once" | "session" | "always" | "deny").
        js_decision = result.get("decision", "ask_user") if isinstance(result, dict) else "ask_user"
        return _HERMES_RETURN_FOR_JS_DECISION.get(js_decision, "deny")

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
