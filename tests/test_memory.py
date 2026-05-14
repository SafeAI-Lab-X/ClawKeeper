"""Behavior-parity tests ported from
legacy/clawkeeper-watcher/plugins/clawkeeper-watcher/src/core/decision-memory.test.js.
"""

from __future__ import annotations

import pytest

from clawkeeper_core.memory import (
    _build_decision_memory_record,
    _should_persist_decision,
    _summarize_forwarded_context,
    append_decision_memory,
    get_beijing_date_stamp,
)


# ── shouldPersistDecision ─────────────────────────────────────────────────


class TestShouldPersistDecision:
    def test_persists_ask_user(self):
        assert _should_persist_decision({"decision": "ask_user", "riskLevel": "high"}) is True

    def test_persists_stop(self):
        assert _should_persist_decision({"decision": "stop", "riskLevel": "medium"}) is True

    def test_persists_medium_risk_continue(self):
        assert _should_persist_decision({"decision": "continue", "riskLevel": "medium"}) is True

    def test_skips_low_risk_continue(self):
        assert _should_persist_decision({"decision": "continue", "riskLevel": "low"}) is False


# ── summarizeForwardedContext ─────────────────────────────────────────────


class TestSummarizeForwardedContext:
    def test_extracts_session_summary(self):
        summary = _summarize_forwarded_context({
            "requestId": "req-1",
            "forwardedContext": {
                "metadata": {"sessionKey": "agent:main:main"},
                "messages": [
                    {"role": "user", "content": "first message"},
                    {"role": "assistant", "content": "working on it"},
                    {"role": "tool", "toolName": "bash"},
                    {"role": "user", "content": "please continue carefully"},
                    {"role": "tool", "name": "write"},
                ],
            },
        })
        assert summary == {
            "requestId": "req-1",
            "sessionKey": "agent:main:main",
            "messageCount": 5,
            "toolCount": 2,
            "toolNames": ["bash", "write"],
            "lastUserMessage": "please continue carefully",
        }


# ── buildDecisionMemoryRecord ────────────────────────────────────────────


class TestBuildDecisionMemoryRecord:
    def test_builds_compact_record(self):
        record = _build_decision_memory_record(
            mode="remote",
            body={
                "requestId": "req-2",
                "forwardedContext": {
                    "metadata": {"sessionKey": "agent:worker:one"},
                    "messages": [
                        {"role": "user", "content": "run the command"},
                        {"role": "tool", "toolName": "exec"},
                    ],
                },
            },
            decision={
                "decision": "ask_user",
                "stopReason": "waiting_user_confirmation",
                "riskLevel": "high",
                "nextAction": "ask_user",
                "needsUserDecision": True,
                "shouldContinue": False,
                "localEnhanced": False,
                "summary": "The context contains high-risk actions.",
                "evidence": ["requestId=req-2", "tool=exec", "toolCount=1"],
            },
        )
        assert record["mode"] == "remote"
        assert record["requestId"] == "req-2"
        assert record["sessionKey"] == "agent:worker:one"
        assert record["decision"] == "ask_user"
        assert record["stopReason"] == "waiting_user_confirmation"
        assert record["riskLevel"] == "high"
        assert record["toolNames"] == ["exec"]
        assert record["toolCount"] == 1
        assert record["lastUserMessage"] == "run the command"
        assert record["evidence"] == ["requestId=req-2", "tool=exec", "toolCount=1"]
        assert isinstance(record["timestamp"], str) and len(record["timestamp"]) > 0


# ── getBeijingDateStamp ──────────────────────────────────────────────────


class TestGetBeijingDateStamp:
    def test_format_matches_iso_date(self):
        stamp = get_beijing_date_stamp()
        # YYYY-MM-DD format
        assert len(stamp) == 10
        assert stamp[4] == "-" and stamp[7] == "-"


# ── append_decision_memory (skip + persist paths) ────────────────────────


class TestAppendDecisionMemory:
    @pytest.mark.asyncio
    async def test_skips_local_mode(self):
        result = await append_decision_memory(
            mode="local",
            body={},
            decision={"decision": "stop", "riskLevel": "high"},
        )
        assert result == {"saved": False, "reason": "skipped"}

    @pytest.mark.asyncio
    async def test_skips_low_risk_continue_remote(self):
        result = await append_decision_memory(
            mode="remote",
            body={},
            decision={"decision": "continue", "riskLevel": "low"},
        )
        assert result == {"saved": False, "reason": "skipped"}

    @pytest.mark.asyncio
    async def test_persists_remote_stop(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CLAWKEEPER_DECISION_MEMORY_DIR", str(tmp_path))
        result = await append_decision_memory(
            mode="remote",
            body={"forwardedContext": {"messages": [{"role": "user", "content": "x"}]}},
            decision={
                "decision": "stop",
                "stopReason": "tool_loop_limit",
                "riskLevel": "high",
                "nextAction": "stop_run",
                "summary": "halt",
                "evidence": [],
            },
        )
        assert result["saved"] is True
        from pathlib import Path
        f = Path(result["path"])
        assert f.exists()
        contents = f.read_text()
        assert "tool_loop_limit" in contents
        assert "\n" in contents  # newline-terminated
