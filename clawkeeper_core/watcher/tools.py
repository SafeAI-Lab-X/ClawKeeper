"""Data-gathering helpers used by the Watcher.

These are NOT smolagents `@tool`s in the multi-step-agent sense — they're
synchronous helpers the Watcher calls before issuing its single LLM call.
A future revision may upgrade to a multi-step ToolCallingAgent that uses
these as actual tools the LLM can invoke; for now we collect data eagerly
and feed it into one structured prompt.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from clawkeeper_core.adapters.base import make_event
from clawkeeper_core.guards.credential_redact import credential_redact_guard  # noqa: F401
from clawkeeper_core.guards.exec_gate import guard_execution
from clawkeeper_core.guards.path_guard import guard_before_tool_call
from clawkeeper_core.guards.return_content_scan import return_content_scan_guard  # noqa: F401
from clawkeeper_core.guards.script_body_scan import script_body_scan_guard
from clawkeeper_core.guards.url_safety import url_safety_guard
from clawkeeper_core.learned_rules import pin_snapshot

# ── Per-session call history ───────────────────────────────────────────────


class SessionHistory:
    """Bounded in-memory history of tool calls per session.

    Lives in the Watcher daemon process. Per-session because cross-agent
    leakage of trajectories would be a confused-deputy risk on its own.
    """

    def __init__(self, *, max_per_session: int = 50, max_sessions: int = 1000):
        self._max_per = max_per_session
        self._max_sessions = max_sessions
        self._calls: dict[str, deque[dict]] = {}
        self._intents: dict[str, str] = {}

    def remember_call(self, session_id: str, tool_name: str, args: dict | None) -> None:
        if session_id not in self._calls:
            if len(self._calls) >= self._max_sessions:
                # Drop the oldest session (LRU-ish: first key)
                oldest = next(iter(self._calls))
                self._calls.pop(oldest, None)
                self._intents.pop(oldest, None)
            self._calls[session_id] = deque(maxlen=self._max_per)
        cmd = ""
        if isinstance(args, dict):
            cmd = str(args.get("command") or args.get("url") or args)
        self._calls[session_id].append({"tool_name": tool_name, "command": cmd[:500]})

    def set_intent(self, session_id: str, intent: str) -> None:
        self._intents[session_id] = intent

    def recent_calls(self, session_id: str, n: int = 10) -> list[dict]:
        d = self._calls.get(session_id)
        if not d:
            return []
        return list(d)[-n:]

    def stated_intent(self, session_id: str) -> str:
        return self._intents.get(session_id, "")


# Module-level singleton used by the daemon.  Swappable for tests.
HISTORY = SessionHistory()


# ── Run deterministic guards and collect their findings ────────────────────


_PRE_TOOL_GUARDS = (
    guard_execution,
    guard_before_tool_call,
    script_body_scan_guard,
    url_safety_guard,
)


def classify_finding(decision: Any) -> str:  # noqa: PLR0911 -- explicit guard result categories
    """Classify guard output without conflating a normal return with a hit."""
    if decision is None:
        return "clean"
    if not isinstance(decision, dict) or not isinstance(decision.get("block"), bool):
        return "error"
    for field in ("outcome", "source", "severity", "reason", "matched"):
        if field in decision and decision[field] is not None and not isinstance(decision[field], str):
            return "error"
    if "signals" in decision and not isinstance(decision["signals"], list):
        return "error"
    if "evidence" in decision and not isinstance(decision["evidence"], dict):
        return "error"
    if "error" in decision or str(decision.get("source", "")).endswith(":error"):
        return "error"
    if decision.get("outcome") not in (None, "allow", "ask", "deny"):
        return "error"
    if decision["block"]:
        return "block"
    if decision.get("outcome") in ("ask", "deny") or any(
        decision.get(k) for k in ("matched", "signals", "evidence", "reason")
    ):
        return "finding"
    return "clean"


def gather_deterministic_findings(*, tool_name: str, args: dict | None) -> list[dict]:
    with pin_snapshot():
        return _gather_findings(tool_name=tool_name, args=args)


def _gather_findings(*, tool_name: str, args: dict | None) -> list[dict]:
    """Run the deterministic pre-tool-call guards and return their findings.

    Findings are dicts in the standard guard-decision shape. Empty list = clean.
    """
    command = ""
    params_dict: dict[str, Any] = {}
    if isinstance(args, dict):
        params_dict = dict(args)
        command = str(args.get("command") or args.get("url") or "")
    elif args is not None:
        command = str(args)
    event = make_event(
        tool_name=tool_name,
        command=command,
        params=params_dict,
        direction="pre_tool_call",
    )
    out: list[dict] = []
    for g in _PRE_TOOL_GUARDS:
        try:
            d = g(event)
        except Exception as e:  # noqa: BLE001 — guards must never crash the watcher
            d = {
                "block": False,
                "error": repr(e),
                "source": f"{getattr(g, '__name__', '?')}:error",
                "severity": "low",
                "reason": f"guard error: {e!r}",
            }
        kind = classify_finding(d)
        if kind == "clean":
            continue
        if not isinstance(d, dict):
            d = {"block": False, "error": "invalid guard return structure"}
        else:
            d = dict(d)
        d.setdefault("source", getattr(g, "__name__", "unknown_guard"))
        if kind == "error":
            d.setdefault("error", "invalid guard return structure")
            d["block"] = d.get("block") is True
            for field in ("source", "severity", "reason"):
                if not isinstance(d.get(field), str):
                    d.pop(field, None)
            d.setdefault("source", getattr(g, "__name__", "unknown_guard"))
            d.setdefault("reason", "guard evaluation failed")
        d["finding_kind"] = kind
        out.append(d)
    return out
