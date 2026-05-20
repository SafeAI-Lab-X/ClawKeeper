"""Unit tests for clawkeeper_core.adapters.base."""

from __future__ import annotations

import pytest

from clawkeeper_core.adapters.base import (
    BaseAdapter,
    make_event,
    run_guard_chain,
)


def _allow_all_guard(event):
    return {"block": False, "outcome": "allow", "source": "test:allow_all",
            "severity": "low", "reason": "ok", "evidence": {}}


def _deny_aws_guard(event):
    cmd = (event.get("params") or {}).get("command", "")
    if ".aws/" in cmd:
        return {"block": True, "outcome": "deny", "source": "test:deny_aws",
                "severity": "critical", "reason": "AWS path", "evidence": {}}
    return None


def _silent_guard(event):
    return None


def _broken_guard(event):
    raise RuntimeError("boom")


# ── run_guard_chain semantics ───────────────────────────────────────────────


def test_chain_stops_on_first_block():
    ev = make_event(tool_name="bash", command="cat ~/.aws/credentials")
    blocking, all_decisions = run_guard_chain(
        [_silent_guard, _deny_aws_guard, _allow_all_guard],
        ev,
        stop_on_block=True,
    )
    assert blocking is not None
    assert blocking["source"] == "test:deny_aws"
    # _allow_all_guard should NOT have fired (stop_on_block=True)
    assert all(d["source"] != "test:allow_all" for d in all_decisions)


def test_chain_continues_when_no_block():
    ev = make_event(tool_name="bash", command="ls -la")
    blocking, all_decisions = run_guard_chain([_silent_guard, _allow_all_guard], ev)
    assert blocking is None
    # _allow_all_guard fired (returned a non-None allow decision)
    assert any(d["source"] == "test:allow_all" for d in all_decisions)


def test_chain_does_not_propagate_guard_exceptions():
    ev = make_event(tool_name="bash", command="ls")
    blocking, all_decisions = run_guard_chain([_broken_guard, _allow_all_guard], ev)
    # The broken guard should be recorded as an "allow" fall-open, not propagated.
    assert blocking is None
    sources = [d["source"] for d in all_decisions]
    assert "test:allow_all" in sources


def test_make_event_shape():
    ev = make_event(tool_name="terminal", command="ls", description="list files")
    assert ev["toolName"] == "terminal"
    assert ev["params"]["command"] == "ls"
    assert ev["params"]["description"] == "list files"
    assert ev["direction"] == "pre_tool_call"


def test_make_event_with_content():
    ev = make_event(tool_name="web_extract", command="", content="page body")
    assert ev["content"] == "page body"


# ── BaseAdapter usability check ────────────────────────────────────────────


class _DummyAdapter(BaseAdapter):
    def install(self, host):
        self.installed = host

    def uninstall(self):
        self.installed = None


def test_dummy_adapter_dispatches_guards():
    adapter = _DummyAdapter(guards=[_deny_aws_guard])
    ev = make_event(tool_name="bash", command="cat ~/.aws/credentials")
    decision = adapter._dispatch_pre_tool_call(ev)
    assert decision is not None and decision["block"]
    # decision_log accumulates
    assert any(d["source"] == "test:deny_aws" for d in adapter.decisions)


def test_dummy_adapter_post_dispatch_does_not_short_circuit():
    """post_guards are observation-only; they accumulate every decision."""
    adapter = _DummyAdapter(post_guards=[_deny_aws_guard, _allow_all_guard])
    ev = make_event(tool_name="bash", command=".aws/x")
    adapter._dispatch_post_tool_call(ev)
    sources = [d["source"] for d in adapter.decisions]
    assert "test:deny_aws" in sources
    assert "test:allow_all" in sources
