"""Tests for the context judge.

No JS test file exists upstream; these tests are written from the source
itself, covering every branch of `judge_forwarded_context`.
"""

from __future__ import annotations

from typing import Any

from clawkeeper_core.judge import (
    DEFAULT_POLICY,
    Judge,
    judge_forwarded_context,
)


# ── Fixture helpers ───────────────────────────────────────────────────────


def make_input(messages: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {"mode": "local", "forwardedContext": {"messages": messages}, **extra}


def make_meta(**fields: Any) -> dict[str, Any]:
    return {"metadata": fields}


# ── Missing-input branches ────────────────────────────────────────────────


class TestMissingInput:
    def test_no_input(self):
        d = judge_forwarded_context()
        assert d["decision"] == "stop"
        assert d["stopReason"] == "missing_input"
        assert d["mode"] == "local"

    def test_no_forwarded_context(self):
        assert judge_forwarded_context({"mode": "remote"})["stopReason"] == "missing_input"

    def test_empty_messages(self):
        assert judge_forwarded_context({
            "forwardedContext": {"messages": []},
        })["stopReason"] == "missing_input"

    def test_includes_request_id_in_evidence(self):
        d = judge_forwarded_context({
            "forwardedContext": {"messages": []},
            "requestId": "abc-123",
        })
        assert "requestId=abc-123" in d["evidence"]


# ── User-requested stop ───────────────────────────────────────────────────


class TestUserStop:
    def test_english_stop(self):
        d = judge_forwarded_context(make_input([
            {"role": "user", "content": "stop the build"},
        ]))
        assert d["decision"] == "stop"
        assert d["stopReason"] == "user_requested_stop"

    def test_english_cancel(self):
        d = judge_forwarded_context(make_input([
            {"role": "user", "content": "cancel this please"},
        ]))
        assert d["stopReason"] == "user_requested_stop"

    def test_chinese_stop(self):
        d = judge_forwarded_context(make_input([
            {"role": "user", "content": "停止"},
        ]))
        assert d["stopReason"] == "user_requested_stop"

    def test_chinese_dont_want(self):
        d = judge_forwarded_context(make_input([
            {"role": "user", "content": "不要继续了"},
        ]))
        assert d["stopReason"] == "user_requested_stop"


# ── Tool errors / upstream failures ───────────────────────────────────────


class TestErrors:
    def test_tool_error_message(self):
        d = judge_forwarded_context(make_input([
            {"role": "user", "content": "do work"},
            {"role": "tool", "toolName": "read", "error": "file missing"},
        ]))
        assert d["decision"] == "stop"
        assert d["riskLevel"] == "high"
        assert d["stopReason"] == "unknown"  # no metadata.error

    def test_upstream_metadata_error(self):
        d = judge_forwarded_context({
            "forwardedContext": {
                "messages": [{"role": "user", "content": "do work"}],
                "metadata": {"success": False, "error": "boom"},
            },
        })
        assert d["stopReason"] == "upstream_error"
        assert "boom" in d["summary"]


# ── Tool loop limit ───────────────────────────────────────────────────────


class TestToolLoopLimit:
    def test_too_many_tools(self):
        d = judge_forwarded_context(make_input([
            {"role": "user", "content": "work"},
            {"role": "tool", "toolName": "read"},
            {"role": "tool", "toolName": "grep"},
            {"role": "tool", "toolName": "find"},
            {"role": "tool", "toolName": "stat"},
        ]))
        assert d["decision"] == "ask_user"
        assert d["stopReason"] == "tool_loop_limit"
        assert "4 tool calls" in d["userQuestion"]

    def test_excludes_clawbands_tools_from_count(self):
        d = judge_forwarded_context(make_input([
            {"role": "user", "content": "work"},
            {"role": "tool", "toolName": "clawbands_respond"},
            {"role": "tool", "toolName": "clawkeeper_bands_respond"},
            {"role": "tool", "toolName": "read"},
        ]))
        # toolCount is 1 (clawbands tools excluded) → under limit, no ask_user
        assert d["decision"] != "ask_user" or d["stopReason"] != "tool_loop_limit"


# ── High-risk confirmation ────────────────────────────────────────────────


class TestRiskConfirmation:
    def test_bash_tool_triggers_ask(self):
        d = judge_forwarded_context(make_input([
            {"role": "user", "content": "deploy"},
            {"role": "tool", "toolName": "bash"},
        ]))
        assert d["decision"] == "ask_user"
        assert d["stopReason"] == "waiting_user_confirmation"

    def test_write_tool_triggers_ask(self):
        d = judge_forwarded_context(make_input([
            {"role": "user", "content": "save it"},
            {"role": "tool", "toolName": "write"},
        ]))
        assert d["decision"] == "ask_user"

    def test_user_continue_alters_question_wording(self):
        d = judge_forwarded_context(make_input([
            {"role": "user", "content": "yes go ahead"},
            {"role": "tool", "toolName": "bash"},
        ]))
        assert d["decision"] == "ask_user"
        assert "already signaled to continue" in d["userQuestion"]

    def test_auto_continue_allows_bypass(self):
        d = judge_forwarded_context({
            "forwardedContext": {"messages": [
                {"role": "user", "content": "deploy"},
                {"role": "tool", "toolName": "bash"},
            ]},
            "policy": {"autoContinueAllowed": True},
        })
        # With autoContinue, bash still escalates risk to medium but doesn't ask;
        # default maxRiskBeforeStop=critical so this becomes continue.
        assert d["decision"] == "continue"


# ── High-risk policy threshold ────────────────────────────────────────────


class TestRiskThreshold:
    def test_command_tool_stops_when_threshold_low(self):
        d = judge_forwarded_context({
            "forwardedContext": {"messages": [
                {"role": "user", "content": "ok"},
                {"role": "tool", "toolName": "bash"},
            ]},
            "policy": {"autoContinueAllowed": True, "maxRiskBeforeStop": "medium"},
        })
        # bash triggers medium risk; threshold also medium → stop
        assert d["decision"] == "stop"
        assert d["stopReason"] == "high_risk_action"
        assert d["riskLevel"] == "medium"

    def test_no_command_with_low_threshold_continues(self):
        d = judge_forwarded_context({
            "forwardedContext": {"messages": [
                {"role": "user", "content": "ok"},
                {"role": "tool", "toolName": "read"},
            ]},
            "policy": {"maxRiskBeforeStop": "high"},
        })
        assert d["decision"] == "continue"

    def test_unknown_threshold_defaults_to_critical(self):
        d = judge_forwarded_context({
            "forwardedContext": {"messages": [
                {"role": "user", "content": "ok"},
                {"role": "tool", "toolName": "read"},
            ]},
            "policy": {"maxRiskBeforeStop": "garbage"},
        })
        assert d["decision"] == "continue"


# ── Happy path ────────────────────────────────────────────────────────────


class TestContinue:
    def test_simple_read_continues(self):
        d = judge_forwarded_context(make_input([
            {"role": "user", "content": "read the file"},
            {"role": "tool", "toolName": "read"},
        ]))
        assert d["decision"] == "continue"
        assert d["riskLevel"] == "low"
        assert d["continueHint"] is None  # no command tool

    def test_continue_with_command_includes_hint(self):
        d = judge_forwarded_context({
            "forwardedContext": {"messages": [
                {"role": "user", "content": "ok"},
                {"role": "tool", "toolName": "bash"},
            ]},
            "policy": {"autoContinueAllowed": True},
        })
        assert d["decision"] == "continue"
        assert d["continueHint"] and "command execution" in d["continueHint"]


# ── Mode handling ────────────────────────────────────────────────────────


class TestMode:
    def test_local_mode_sets_local_enhanced(self):
        d = judge_forwarded_context(make_input([
            {"role": "user", "content": "read"},
            {"role": "tool", "toolName": "read"},
        ], mode="local"))
        assert d["localEnhanced"] is True
        assert d["mode"] == "local"

    def test_remote_mode(self):
        d = judge_forwarded_context(make_input([
            {"role": "user", "content": "read"},
            {"role": "tool", "toolName": "read"},
        ], mode="remote"))
        assert d["localEnhanced"] is False
        assert d["mode"] == "remote"


# ── Evidence summarization ───────────────────────────────────────────────


class TestEvidence:
    def test_caps_at_eight_evidence_items(self):
        many_tools = [{"role": "tool", "toolName": f"t{i}", "error": f"err{i}"} for i in range(10)]
        d = judge_forwarded_context({
            "forwardedContext": {"messages": [{"role": "user", "content": "go"}, *many_tools]},
            "policy": {"maxToolStepsWithoutUserTurn": 100},  # don't trip the loop limit
        })
        # Top-level evidence has request/session/counts; tool summary slice is <= 8.
        summarized = [e for e in d["evidence"] if e.startswith("tool=") or e.startswith("error=")]
        assert len(summarized) <= 8

    def test_result_evidence_only_when_pattern_matches(self):
        d = judge_forwarded_context({
            "forwardedContext": {"messages": [
                {"role": "user", "content": "ok"},
                {"role": "tool", "toolName": "read", "result": "exitCode=0 plain output"},
                {"role": "tool", "toolName": "read", "result": "boring text"},
            ]},
            "policy": {"maxToolStepsWithoutUserTurn": 100},
        })
        result_lines = [e for e in d["evidence"] if e.startswith("result=")]
        assert len(result_lines) == 1
        assert "exitCode" in result_lines[0]


# ── Judge wrapper ────────────────────────────────────────────────────────


class TestJudgeWrapper:
    def test_evaluate_passes_through(self):
        judge = Judge()
        d = judge.evaluate(make_input([{"role": "user", "content": "stop"}]))
        assert d["stopReason"] == "user_requested_stop"

    def test_evaluate_injects_default_policy(self):
        judge = Judge(policy={"maxRiskBeforeStop": "medium", "autoContinueAllowed": True})
        d = judge.evaluate(make_input([
            {"role": "user", "content": "ok"},
            {"role": "tool", "toolName": "bash"},
        ]))
        assert d["decision"] == "stop"
        assert d["stopReason"] == "high_risk_action"

    def test_explicit_input_policy_wins(self):
        judge = Judge(policy={"autoContinueAllowed": True})
        d = judge.evaluate({
            **make_input([
                {"role": "user", "content": "ok"},
                {"role": "tool", "toolName": "bash"},
            ]),
            "policy": {"autoContinueAllowed": False},  # explicit override
        })
        assert d["decision"] == "ask_user"

    def test_default_policy_constant_matches_module(self):
        # Sanity: the module's DEFAULT_POLICY shape hasn't drifted
        assert DEFAULT_POLICY["maxToolStepsWithoutUserTurn"] == 3
        assert "bash" in DEFAULT_POLICY["requireUserConfirmationFor"]
