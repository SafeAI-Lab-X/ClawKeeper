"""Hermes Agent adapter — wires ClawKeeper into NousResearch/hermes-agent.

Two interception surfaces (both are documented Hermes integration points,
no host internals patched for behaviour):

1.  `tools.terminal_tool.set_approval_callback(cb)` and
    `tools.computer_use.tool.set_approval_callback(cb)` — Hermes calls
    these when its own regex flags a command. ClawKeeper's Judge
    decides allow/ask/deny here.

2.  `tool_start_callback` / `tool_complete_callback` on `AIAgent` —
    these fire for EVERY tool call, regardless of whether Hermes
    flagged it. ClawKeeper runs its proactive guard chain here
    (exec_gate, path_guard, url_safety) so attacks that bypass
    Hermes's regex (Python heredocs, multi-turn drift) still get
    inspected. Closes the structural bypass surfaced by red-team
    scenario 07.a.

`install(judge, agent)` registers both. Hermes does not need any patches.

Compatibility: the existing public surface (`install(judge, agent)`,
behaviour of the approval callback) is preserved. The proactive
guard chain is additive.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from clawkeeper_core.adapters.base import (
    GuardCallable,
    make_event,
    run_guard_chain,
)
from clawkeeper_core.guards.credential_redact import credential_redact_guard
from clawkeeper_core.guards.exec_gate import guard_execution
from clawkeeper_core.guards.path_guard import guard_before_tool_call
from clawkeeper_core.guards.return_content_scan import return_content_scan_guard
from clawkeeper_core.guards.script_body_scan import script_body_scan_guard
from clawkeeper_core.guards.url_safety import url_safety_guard
from clawkeeper_core.judge import Judge
from clawkeeper_core.schemas import AgentEvent

if TYPE_CHECKING:
    from run_agent import AIAgent  # noqa: F401


# ─── Decision → Hermes-return mapping ──────────────────────────────────────

_HERMES_RETURN_FOR_JS_DECISION: dict[str, str] = {
    "continue": "once",
    "stop": "deny",
    "ask_user": "deny",
}

# Backwards-compat alias kept so consumers that imported this constant directly
# don't break.
_HERMES_RETURN_FOR_OUTCOME: dict = {}
try:
    from clawkeeper_core.schemas import Outcome, Scope
    _HERMES_RETURN_FOR_OUTCOME = {
        Outcome.ALLOW: {
            Scope.ONCE.value: "once",
            Scope.SESSION.value: "session",
            Scope.ALWAYS.value: "always",
        },
        Outcome.ASK: {Scope.ONCE.value: "deny", Scope.SESSION.value: "deny", Scope.ALWAYS.value: "deny"},
        Outcome.DENY: {Scope.ONCE.value: "deny", Scope.SESSION.value: "deny", Scope.ALWAYS.value: "deny"},
    }
except ImportError:
    pass


# ─── Blocking exception (raised from tool_start when a guard wants to stop) ──


class ClawKeeperBlock(Exception):
    """Raised by ClawKeeper's tool_start_callback to abort a tool call.

    Hermes's main loop catches callback exceptions and surfaces them to the
    LLM as a tool-execution failure. The decision dict on this exception is
    what gets logged for the audit trail.
    """

    def __init__(self, decision: dict):
        self.decision = decision
        super().__init__(decision.get("reason", "blocked by ClawKeeper"))


# ─── Default proactive guard chains ────────────────────────────────────────


def _default_pre_guards() -> list[GuardCallable]:
    """Pre-execution guards that inspect upcoming commands.

    Order matters: cheap pattern matches first, then path resolution,
    then URL parsing.
    """
    return [
        guard_execution,            # dangerous-command regex (CK's broader set than Hermes's)
        guard_before_tool_call,     # protected paths — also scans embedded paths in script bodies
        url_safety_guard,           # homoglyph + SSRF + blocked-hostname
        script_body_scan_guard,     # dynamic-path-construction heuristic (Path.home + .aws/, etc.)
    ]


def _default_post_guards() -> list[GuardCallable]:
    """Post-execution observers — scan tool results before the LLM consumes them.

    These are observation-and-log only on the Hermes side (we can't mutate the
    tool result that Hermes passes back to the LLM through `tool_complete_callback`).
    On the MCP gateway adapter, the same guards block at the result boundary.
    """
    return [
        return_content_scan_guard,
        credential_redact_guard,
    ]


# ─── Public API: install ────────────────────────────────────────────────────


def install(
    judge: Judge,
    agent: "AIAgent",
    *,
    pre_guards: list[GuardCallable] | None = None,
    post_guards: list[GuardCallable] | None = None,
    watcher_url: str | None = None,
) -> None:
    """Wire a Judge + a chain of guards into a constructed AIAgent.

    Call after `AIAgent(...)`, before `agent.run(...)`.

    `pre_guards` is the proactive chain run on every tool call via
    `tool_start_callback`. Defaults to the standard CK guard set.

    `post_guards` is run on every tool result via `tool_complete_callback`
    (observation only on Hermes — see module docstring).

    Both default chains are conservative: passing your own list lets a
    deployment opt in/out per guard.
    """
    pre = pre_guards if pre_guards is not None else _default_pre_guards()
    post = post_guards if post_guards is not None else _default_post_guards()

    # 1) Approval-callback path (Hermes-flagged commands → Judge decides).
    import tools.terminal_tool as terminal_tool
    from tools.computer_use import tool as computer_use_tool

    def approval_cb(command: str, description: str = "") -> str:
        event = {"toolName": "bash", "params": {"command": command, "description": description}}

        eg = guard_execution(event)
        if eg.get("block"):
            _record_decision(agent, "deny", source="exec_gate",
                             reason=eg.get("reason"), evidence=eg)
            return "deny"

        pg = guard_before_tool_call(event)
        if pg.get("block"):
            _record_decision(agent, "deny", source="path_guard",
                             reason=pg.get("reason"), evidence=pg)
            return "deny"

        # Build the Judge's forwarded-context payload.
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
        js_decision = result.get("decision", "ask_user") if isinstance(result, dict) else "ask_user"
        hermes_string = _HERMES_RETURN_FOR_JS_DECISION.get(js_decision, "deny")
        _record_decision(agent, hermes_string, source="judge",
                         reason=result.get("stopReason") if isinstance(result, dict) else None,
                         evidence=result if isinstance(result, dict) else {})
        return hermes_string

    terminal_tool.set_approval_callback(approval_cb)
    computer_use_tool.set_approval_callback(approval_cb)

    # NEW: register a Hermes `pre_tool_call` plugin hook.  This is the
    # documented Hermes API for blocking tool execution from outside the
    # built-in approval path — fires for every tool call (not just regex-
    # flagged ones), and Hermes honours the returned block message.
    _register_pre_tool_call_hook(judge, agent, pre_guards=pre, watcher_url=watcher_url)

    # 2) Observation + proactive-guard hooks on the agent instance.
    _register_observers(judge, agent, pre_guards=pre, post_guards=post)


# ─── helpers ────────────────────────────────────────────────────────────────


def _record_decision(
    agent: Any,
    hermes_return: str,
    *,
    source: str,
    reason: Any = None,
    evidence: Any = None,
) -> None:
    log = getattr(agent, "_clawkeeper_decisions", None)
    if log is None:
        log = []
        try:
            agent._clawkeeper_decisions = log  # type: ignore[attr-defined]
        except AttributeError:
            return
    log.append({
        "ts": _now().isoformat(),
        "hermes_return": hermes_return,
        "source": source,
        "reason": reason,
        "evidence": evidence,
    })


def _recent_messages(agent: Any, n: int = 20) -> list:
    history = getattr(agent, "conversation_history", None) or []
    return history[-n:]


def _register_pre_tool_call_hook(judge, agent, *, pre_guards, watcher_url=None):
    watcher_client = None
    if watcher_url:
        try:
            from clawkeeper_core.watcher.client import WatcherClient
            watcher_client = WatcherClient(base_url=watcher_url, on_unavailable="ask")
        except Exception as exc:
            import sys
            print(f"[clawkeeper] watcher client init failed: {exc!r}", file=sys.stderr)
            watcher_client = None

    """Register a Hermes plugin `pre_tool_call` hook that runs CK's guard chain.

    Returning {"action": "block", "message": ...} from this hook causes Hermes
    to skip tool execution and surface the message to the LLM as a tool error
    (the documented Hermes plugin API — `tools/approval.py::check_all_command_guards`
    is unrelated and not patched).
    """
    try:
        from hermes_cli.plugins import _ensure_plugins_discovered
    except ImportError:  # pragma: no cover
        return
    manager = _ensure_plugins_discovered()

    def ck_pre_tool_call(*, tool_name, args, task_id="", session_id="", tool_call_id=""):
        command = ""
        if isinstance(args, dict):
            command = str(args.get("command") or args.get("url") or "")
        event = make_event(
            tool_name=str(tool_name),
            command=command,
            params=args if isinstance(args, dict) else {},
            session_id=getattr(agent, "session_id", None),
            direction="pre_tool_call",
        )
        blocking, decisions = run_guard_chain(pre_guards, event, stop_on_block=True)
        for d in decisions:
            if d is None:
                continue
            _record_decision(
                agent,
                "deny" if d.get("block") else "once",
                source=d.get("source", "?"),
                reason=d.get("reason"),
                evidence=d.get("evidence"),
            )
        if blocking is not None:
            src = blocking.get("source", "?")
            reason = blocking.get("reason", "blocked")
            return {"action": "block", "message": f"[ClawKeeper:{src}] {reason}"}

        if watcher_client is not None:
            try:
                d = watcher_client.evaluate(
                    session_id=str(getattr(agent, "session_id", "default")),
                    tool_name=str(tool_name),
                    args=args if isinstance(args, dict) else {},
                )
                _record_decision(
                    agent,
                    "deny" if d.get("decision") in {"deny", "ask"} else "once",
                    source=f"watcher:{d.get('decision','?')}",
                    reason=d.get("reason"),
                    evidence=d,
                )
                if d.get("decision") in {"deny", "ask"}:
                    return {
                        "action": "block",
                        "message": f"[ClawKeeper:watcher] {d.get('reason','blocked by Watcher')}",
                    }
            except Exception as exc:
                import sys
                print(f"[clawkeeper] watcher consult error: {exc!r}", file=sys.stderr)

        return None

    manager._hooks.setdefault("pre_tool_call", []).append(ck_pre_tool_call)


def _register_observers(
    judge: Judge,
    agent: Any,
    *,
    pre_guards: list[GuardCallable],
    post_guards: list[GuardCallable],
) -> None:
    """Wrap `tool_start_callback` / `tool_complete_callback` on the agent.

    Preserves any previously-set callback so multiple wrappers stack.
    """
    prev_tool_start = agent.tool_start_callback
    prev_tool_complete = agent.tool_complete_callback

    def on_tool_start(*args: Any) -> None:
        if len(args) == 3:
            tool_call_id, name, tool_args = args
        elif len(args) == 2:
            tool_call_id, name, tool_args = None, args[0], args[1]
        else:
            return

        # Build the standard event the guards consume.
        command = ""
        params_dict = {}
        if isinstance(tool_args, dict):
            params_dict = dict(tool_args)
            command = str(tool_args.get("command") or tool_args.get("url") or "")
        else:
            command = str(tool_args)
        event = make_event(
            tool_name=str(name),
            command=command,
            params=params_dict,
            session_id=getattr(agent, "session_id", None),
            direction="pre_tool_call",
        )

        # Proactive guard chain — closes scenario 07.a (Hermes regex missed
        # the heredoc, so approval_cb was never invoked; now we run the same
        # guards on every tool start).
        blocking, decisions = run_guard_chain(pre_guards, event, stop_on_block=True)
        for d in decisions:
            if d is None:
                continue
            _record_decision(
                agent,
                "deny" if d.get("block") else "once",
                source=d.get("source", "proactive_guard"),
                reason=d.get("reason"),
                evidence=d.get("evidence"),
            )

        # Existing observer event (for profiler / drift detector).
        _emit(judge, AgentEvent(
            ts=_now(),
            agent_id=getattr(agent, "session_id", "unknown"),
            session_id=getattr(agent, "session_id", None),
            kind="tool_start",
            payload={
                "tool_call_id": tool_call_id,
                "name": name,
                "args_preview": _stringify(tool_args),
            },
        ))

        if prev_tool_start:
            prev_tool_start(*args)
        # NB: we do NOT raise here. Hermes wraps tool_start_callback in a
        # try/except that swallows exceptions; raising is purely advisory.
        # Real blocking happens in `_register_pre_tool_call_hook` below.

    def on_tool_complete(*args: Any) -> None:
        if len(args) == 4:
            tool_call_id, name, _tool_args, result = args
        elif len(args) == 3:
            tool_call_id, name, result = None, args[0], args[2]
        else:
            return

        # Build event for post-guards. Result text is what the LLM is about to see.
        event = make_event(
            tool_name=str(name),
            content=_stringify(result),
            params={"result": _stringify(result)},
            session_id=getattr(agent, "session_id", None),
            direction="post_tool_call",
        )
        # Post-guard chain is observation+log on Hermes (we can't mutate the
        # result inline). Decisions are still recorded for audit.
        _blocking, decisions = run_guard_chain(post_guards, event, stop_on_block=False)
        for d in decisions:
            if d is None:
                continue
            _record_decision(
                agent,
                "deny" if d.get("block") else "once",
                source=d.get("source", "post_guard"),
                reason=d.get("reason"),
                evidence=d.get("evidence"),
            )

        # Existing observer
        _emit(judge, AgentEvent(
            ts=_now(),
            agent_id=getattr(agent, "session_id", "unknown"),
            session_id=getattr(agent, "session_id", None),
            kind="tool_complete",
            payload={
                "tool_call_id": tool_call_id,
                "name": name,
                "result_preview": _stringify(result)[:500],
            },
        ))

        if prev_tool_complete:
            prev_tool_complete(*args)

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
