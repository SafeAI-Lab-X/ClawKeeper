"""Integration smoke tests for the Hermes Agent adapter.

The adapter only reads/writes a handful of attributes on the agent
(`tool_start_callback`, `tool_complete_callback`, `session_id`,
`conversation_history`). We use a duck-typed stub agent so the tests
don't need a real Hermes runtime / LLM provider.

These tests are skipped cleanly when Hermes' `tools.terminal_tool` is
not importable (e.g. running in the clawkeeper env rather than the
hermes-integration env).
"""

from __future__ import annotations

import pytest

# Skip the whole file if Hermes isn't installed in this env.
pytest.importorskip("tools.terminal_tool", reason="hermes-agent not installed")

from clawkeeper_core.adapters.hermes import (  # noqa: E402
    _HERMES_RETURN_FOR_OUTCOME,
    install,
)
from clawkeeper_core.judge import Judge  # noqa: E402
from clawkeeper_core.schemas import Outcome, Scope  # noqa: E402


class StubAgent:
    """Duck-types just enough of Hermes' AIAgent for the adapter."""

    def __init__(self):
        self.session_id = "test-session"
        self.conversation_history: list = []
        self.tool_start_callback = None
        self.tool_complete_callback = None


def test_install_does_not_raise():
    agent = StubAgent()
    judge = Judge()
    install(judge, agent)


def test_install_overwrites_approval_callbacks():
    import tools.terminal_tool as terminal_tool
    from tools.computer_use import tool as cu_tool

    # Reset to None first so we can detect the change. The two modules
    # expose the callback through different symbol shapes:
    #   - terminal_tool: _get_approval_callback() function
    #   - computer_use.tool: _approval_callback module-level var
    terminal_tool.set_approval_callback(None)
    cu_tool.set_approval_callback(None)
    assert terminal_tool._get_approval_callback() is None
    assert cu_tool._approval_callback is None

    judge = Judge()
    agent = StubAgent()
    install(judge, agent)

    assert terminal_tool._get_approval_callback() is not None
    assert cu_tool._approval_callback is not None


def test_install_overwrites_observation_callbacks():
    agent = StubAgent()
    judge = Judge()
    install(judge, agent)

    assert agent.tool_start_callback is not None
    assert agent.tool_complete_callback is not None
    # They should be callables (the wrappers).
    assert callable(agent.tool_start_callback)
    assert callable(agent.tool_complete_callback)


def test_observation_callbacks_chain_to_originals():
    agent = StubAgent()
    fired: list[tuple[str, str]] = []

    def original_start(name, args_preview=None):
        fired.append(("start", name))

    def original_complete(name, args=None, result=None):
        fired.append(("complete", name))

    agent.tool_start_callback = original_start
    agent.tool_complete_callback = original_complete

    judge = Judge()
    install(judge, agent)

    agent.tool_start_callback("bash", {"command": "ls"})
    agent.tool_complete_callback("bash", {"command": "ls"}, "ok")

    assert ("start", "bash") in fired
    assert ("complete", "bash") in fired


def test_approval_callback_maps_allow_outcomes():
    assert _HERMES_RETURN_FOR_OUTCOME[Outcome.ALLOW][Scope.ONCE.value] == "once"
    assert _HERMES_RETURN_FOR_OUTCOME[Outcome.ALLOW][Scope.SESSION.value] == "session"
    assert _HERMES_RETURN_FOR_OUTCOME[Outcome.ALLOW][Scope.ALWAYS.value] == "always"


def test_approval_callback_maps_deny_outcomes():
    assert _HERMES_RETURN_FOR_OUTCOME[Outcome.DENY][Scope.ONCE.value] == "deny"
    assert _HERMES_RETURN_FOR_OUTCOME[Outcome.DENY][Scope.SESSION.value] == "deny"
    assert _HERMES_RETURN_FOR_OUTCOME[Outcome.ASK][Scope.ONCE.value] == "deny"


def test_approval_callback_runs_judge_end_to_end():
    """Wire the callback, invoke it as Hermes' terminal_tool would,
    confirm the Judge's Decision flows through to the right return string.
    """
    import tools.terminal_tool as terminal_tool

    judge = Judge()
    agent = StubAgent()
    install(judge, agent)

    cb = terminal_tool._get_approval_callback()
    assert cb is not None
    # The real Judge runs full context-judge logic. A single dangerous
    # tool message ("rm -rf /") triggers the high-risk path → ask_user
    # → maps to "deny" via _HERMES_RETURN_FOR_JS_DECISION.
    result = cb("rm -rf /tmp/build", "clean build dir")
    assert result == "deny"


def test_approval_callback_allows_safe_continue_branch():
    """When the Judge's logic returns "continue" (e.g. an unimportant
    tool call with no dangerous content), the adapter returns "once".
    """
    import tools.terminal_tool as terminal_tool

    judge = Judge()
    # autoContinueAllowed bypasses the ask_user branch on high-risk tools
    judge.policy = {"autoContinueAllowed": True, "maxRiskBeforeStop": "critical"}
    agent = StubAgent()
    install(judge, agent)

    cb = terminal_tool._get_approval_callback()
    assert cb is not None
    result = cb("ls /tmp", "list temp")
    assert result == "once"


def test_observation_emits_event_to_profiler_when_present():
    agent = StubAgent()

    class StubProfiler:
        def __init__(self):
            self.events: list = []

        def update(self, event):
            self.events.append(event)

    profiler = StubProfiler()
    judge = Judge()
    judge.profiler = profiler  # adapter looks this up via getattr
    install(judge, agent)

    agent.tool_start_callback("bash", "ls /tmp")
    agent.tool_complete_callback("bash", {"command": "ls"}, "ok")

    kinds = [e.kind for e in profiler.events]
    assert "tool_start" in kinds
    assert "tool_complete" in kinds
