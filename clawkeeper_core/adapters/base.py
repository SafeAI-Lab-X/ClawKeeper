"""Agent-agnostic adapter base class.

A *guard* is a callable that takes a `dict` event (the same shape that
`guard_execution`, `guard_before_tool_call`, and the Judge already consume)
and returns a decision dict, or `None` to abstain.

An *adapter* knows how to:
  1. translate a host's native callbacks (Hermes `tool_start_callback`,
     OpenClaw watcher WebSocket message, Claude Code hook payload, MCP
     `tools/call` request, LangGraph middleware event, …) into the
     standard event dict;
  2. dispatch that event through a chain of guards;
  3. translate the resulting decision back into the host's native
     accept/deny vocabulary (Hermes's `"once"`/`"deny"` strings,
     OpenClaw's `continue`/`stop`, MCP's `isError`, …).

The decision dict shape (compatible with existing CK code):

    {
        "block": bool,                  # True if the guard wants to stop the call
        "outcome": "allow"|"deny"|"ask",
        "source": str,                  # which guard / rule
        "severity": "low"|"medium"|"high"|"critical"|"hardline",
        "reason": str,
        "evidence": dict,
    }

`None` from a guard means "no opinion — let the next one decide".
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, Optional

GuardEvent = dict[str, Any]
GuardDecision = dict[str, Any]
GuardCallable = Callable[[GuardEvent], Optional[GuardDecision]]


def make_event(
    *,
    tool_name: str,
    command: str = "",
    params: dict | None = None,
    content: str = "",
    description: str = "",
    session_id: str | None = None,
    direction: str = "pre_tool_call",  # "pre_tool_call" | "post_tool_call" | "return_content"
) -> GuardEvent:
    """Build the standard event dict the guards consume.

    `direction` lets guards opt in/out of phases.  Pre-tool-call guards
    (exec_gate, path_guard) inspect upcoming actions; post-tool-call and
    return-content guards (credential_redact, return_content_scan) inspect
    things the host already produced.
    """
    base: GuardEvent = {
        "toolName": tool_name,
        "direction": direction,
        "params": {"command": command, "description": description, **(params or {})},
    }
    if content:
        base["content"] = content
    if session_id is not None:
        base["session_id"] = session_id
    return base


def run_guard_chain(
    guards: list[GuardCallable],
    event: GuardEvent,
    *,
    stop_on_block: bool = True,
) -> tuple[GuardDecision | None, list[GuardDecision]]:
    """Walk a guard chain.

    Returns ``(first_blocking_decision_or_None, all_decisions_emitted)``.
    """
    seen: list[GuardDecision] = []
    blocking: GuardDecision | None = None
    for guard in guards:
        try:
            d = guard(event)
        except Exception as exc:  # noqa: BLE001 — guards must never crash the host
            d = {
                "block": False,
                "outcome": "allow",
                "source": getattr(guard, "__name__", "anon_guard"),
                "severity": "low",
                "reason": f"guard raised: {exc!r} (failing open by convention; "
                f"a guard with `failure_policy=fail-closed` should set block=True itself)",
                "evidence": {},
            }
        if d is None:
            continue
        seen.append(d)
        if d.get("block") and blocking is None:
            blocking = d
            if stop_on_block:
                break
    return blocking, seen


class BaseAdapter(ABC):
    """Abstract adapter — every per-host integration subclasses this.

    Subclasses MUST implement `install(host)` / `uninstall()`.  They
    typically wire host-specific callbacks to call `_dispatch_pre_tool_call`
    or `_dispatch_return_content` on themselves.
    """

    def __init__(
        self,
        *,
        guards: list[GuardCallable] | None = None,
        post_guards: list[GuardCallable] | None = None,
        return_content_guards: list[GuardCallable] | None = None,
    ):
        self.pre_guards: list[GuardCallable] = list(guards or [])
        self.post_guards: list[GuardCallable] = list(post_guards or [])
        self.return_content_guards: list[GuardCallable] = list(return_content_guards or [])
        self._decision_log: list[GuardDecision] = []

    @abstractmethod
    def install(self, host: Any) -> None:
        """Wire into the host's native callback system."""

    @abstractmethod
    def uninstall(self) -> None:
        """Detach from the host (idempotent)."""

    # ─── Dispatch entrypoints — host adapters call these from their bound callbacks ───

    def _dispatch_pre_tool_call(self, event: GuardEvent) -> GuardDecision | None:
        blocking, decisions = run_guard_chain(self.pre_guards, event, stop_on_block=True)
        self._decision_log.extend(decisions)
        return blocking

    def _dispatch_post_tool_call(self, event: GuardEvent) -> None:
        _blocking, decisions = run_guard_chain(self.post_guards, event, stop_on_block=False)
        self._decision_log.extend(decisions)

    def _dispatch_return_content(self, event: GuardEvent) -> GuardDecision | None:
        blocking, decisions = run_guard_chain(self.return_content_guards, event, stop_on_block=True)
        self._decision_log.extend(decisions)
        return blocking

    # ─── Introspection ───

    @property
    def decisions(self) -> list[GuardDecision]:
        return list(self._decision_log)

    def clear_decisions(self) -> None:
        self._decision_log.clear()
