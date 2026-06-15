"""Behavior-parity tests ported from
legacy/clawkeeper-watcher/plugins/clawkeeper-watcher/src/core/agent-profiler.test.js.
"""

from __future__ import annotations

import time

from clawkeeper_core.profile import (
    _cache,
    build_agent_profiles,
    compute_deviation,
    detect_anomalies,
    invalidate_profile_cache,
)


def make_event(**overrides):
    base = {
        "timestamp": "2026-03-24T10:00:00.000Z",
        "type": "before_tool_call",
        "toolName": "read",
        "agentId": "agent-abc123",
        "sessionKey": "agent:agent-abc123:main",
    }
    base.update(overrides)
    return base


def make_decision(**overrides):
    base = {
        "timestamp": "2026-03-24T10:10:00.000Z",
        "sessionKey": "agent:agent-abc123:main",
        "decision": "ask_user",
        "riskLevel": "high",
    }
    base.update(overrides)
    return base


class TestBuildAgentProfiles:
    def test_aggregates_event_logs_per_agent(self):
        records = [
            make_event(toolName="read"),
            make_event(toolName="write"),
            make_event(
                type="llm_output", toolName=None,
                inputTokens=300, outputTokens=150, totalTokens=450,
            ),
            make_event(
                agentId="agent-def456",
                sessionKey="agent:agent-def456:main",
                toolName="glob",
            ),
        ]
        decisions = [
            make_decision(decision="ask_user"),
            make_decision(decision="continue"),
        ]
        profiles = build_agent_profiles(records, decision_records=decisions)
        p = profiles["agent-abc123"]
        assert p["toolCallCount"] == 2
        assert p["sessionCount"] == 1
        assert p["avgToolCallsPerSession"] == 2
        assert p["avgInputTokensPerCall"] == 300
        assert p["avgOutputTokensPerCall"] == 150
        assert p["avgTotalTokensPerCall"] == 450
        assert p["totalTokens"] == 450
        assert p["riskDecisionCount"] == 1
        assert p["judgeDecisionCount"] == 2
        assert p["riskRatio"] == 0.5
        assert sorted(p["knownTools"]) == ["read", "write"]
        assert p["toolDistribution"]["read"] == 0.5
        assert p["toolDistribution"]["write"] == 0.5


class TestComputeDeviation:
    def test_detects_tool_distribution_shift(self):
        baseline = {
            "agentId": "agent-abc123",
            "toolDistribution": {"bash": 0.05, "read": 0.95},
            "toolCallCount": 100,
            "knownTools": {"bash", "read"},
        }
        current = {
            "agentId": "agent-abc123",
            "toolDistribution": {"bash": 0.6, "read": 0.4},
            "toolCallCount": 5,
            "knownTools": {"bash", "read"},
        }
        deviations = compute_deviation(current, baseline)
        bash_change = next(c for c in deviations["toolFrequencyChanges"] if c["tool"] == "bash")
        assert round(bash_change["multiplier"] * 10) / 10 == 12.0
        assert deviations["toolDistributionDivergence"] > 0

    def test_detects_token_spike(self):
        baseline = {
            "agentId": "agent-abc123",
            "toolDistribution": {"read": 1},
            "toolCallCount": 10,
            "avgInputTokensPerCall": 100,
            "avgOutputTokensPerCall": 80,
            "avgTotalTokensPerCall": 180,
            "knownTools": {"read"},
        }
        current = {
            "agentId": "agent-abc123",
            "toolDistribution": {"read": 1},
            "toolCallCount": 1,
            "avgInputTokensPerCall": 320,
            "avgOutputTokensPerCall": 240,
            "avgTotalTokensPerCall": 560,
            "knownTools": {"read"},
        }
        deviations = compute_deviation(current, baseline)
        assert round(deviations["tokenDeviation"]["input"]["multiplier"] * 10) / 10 == 3.2
        assert round(deviations["tokenDeviation"]["output"]["multiplier"] * 10) / 10 == 3.0
        assert round(deviations["tokenDeviation"]["total"]["multiplier"] * 10) / 10 == 3.1

    def test_detects_novel_tools(self):
        baseline = {
            "agentId": "agent-abc123",
            "toolDistribution": {"read": 1},
            "toolCallCount": 10,
            "knownTools": {"read"},
        }
        current = {
            "agentId": "agent-abc123",
            "toolDistribution": {"exec": 1},
            "toolCallCount": 1,
            "knownTools": {"exec"},
        }
        deviations = compute_deviation(current, baseline)
        assert deviations["novelTools"] == ["exec"]

    def test_handles_missing_baseline(self):
        deviations = compute_deviation({"agentId": "agent-abc123"}, None)
        assert deviations["hasBaseline"] is False
        assert deviations["novelTools"] == []
        assert deviations["toolFrequencyChanges"] == []


class TestDetectAnomalies:
    def test_respects_threshold_configuration(self):
        report = detect_anomalies(
            {
                "agentId": "agent-abc123",
                "hasBaseline": True,
                "novelTools": [],
                "toolFrequencyChanges": [
                    {"tool": "bash", "baseline": 0.1, "current": 0.29, "multiplier": 2.9, "delta": 0.19},
                ],
                "tokenDeviation": {
                    "total": {"baseline": 100, "current": 240, "multiplier": 2.4},
                },
                "baseline": {
                    "sessionCount": 3,
                    "toolCallCount": 20,
                    "knownTools": {"bash", "read"},
                },
            },
            {"lookbackDays": 7, "toolDeviationThreshold": 3, "tokenDeviationThreshold": 2.5},
        )
        assert report["detected"] is False
        assert report["deviations"] == []

    def test_flags_novel_tools_with_configured_severity(self):
        report = detect_anomalies(
            {
                "agentId": "agent-abc123",
                "hasBaseline": True,
                "novelTools": ["exec"],
                "toolFrequencyChanges": [],
                "tokenDeviation": {},
                "baseline": {
                    "sessionCount": 3,
                    "toolCallCount": 20,
                    "knownTools": {"read", "write"},
                },
            },
            {"lookbackDays": 7, "novelToolSeverity": "high"},
        )
        assert report["detected"] is True
        assert report["severity"] == "high"
        assert report["deviations"][0]["type"] == "novel_tool"


class TestCache:
    def setup_method(self):
        invalidate_profile_cache()

    def test_invalidates_cached_profiles(self):
        _cache["entries"][7] = {
            "loadedAt": int(time.time() * 1000),
            "profileMap": {"agent-abc123": {"agentId": "agent-abc123"}},
        }
        assert len(_cache["entries"]) == 1
        invalidate_profile_cache()
        assert len(_cache["entries"]) == 0
