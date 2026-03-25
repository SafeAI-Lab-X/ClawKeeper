import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";
import {
  buildAgentProfiles,
  computeDeviation,
  detectAnomalies,
  invalidateProfileCache,
  _testExports,
} from "./agent-profiler.js";

const { _cache } = _testExports;

function makeEvent(overrides = {}) {
  return {
    timestamp: "2026-03-24T10:00:00.000Z",
    type: "before_tool_call",
    toolName: "read",
    agentId: "agent-abc123",
    sessionKey: "agent:agent-abc123:main",
    ...overrides,
  };
}

function makeDecision(overrides = {}) {
  return {
    timestamp: "2026-03-24T10:10:00.000Z",
    sessionKey: "agent:agent-abc123:main",
    decision: "ask_user",
    riskLevel: "high",
    ...overrides,
  };
}

void describe("buildAgentProfiles", () => {
  void it("aggregates event logs per agentId", () => {
    const records = [
      makeEvent({ toolName: "read", sessionKey: "agent:agent-abc123:main" }),
      makeEvent({ toolName: "write", sessionKey: "agent:agent-abc123:main" }),
      makeEvent({
        type: "llm_output",
        toolName: undefined,
        inputTokens: 300,
        outputTokens: 150,
        totalTokens: 450,
      }),
      makeEvent({
        agentId: "agent-def456",
        sessionKey: "agent:agent-def456:main",
        toolName: "glob",
      }),
    ];
    const decisions = [
      makeDecision({ decision: "ask_user", sessionKey: "agent:agent-abc123:main" }),
      makeDecision({ decision: "continue", sessionKey: "agent:agent-abc123:main" }),
    ];

    const profiles = buildAgentProfiles(records, { decisionRecords: decisions });
    const profile = profiles.get("agent-abc123");

    assert.ok(profile);
    assert.equal(profile.toolCallCount, 2);
    assert.equal(profile.sessionCount, 1);
    assert.equal(profile.avgToolCallsPerSession, 2);
    assert.equal(profile.avgInputTokensPerCall, 300);
    assert.equal(profile.avgOutputTokensPerCall, 150);
    assert.equal(profile.avgTotalTokensPerCall, 450);
    assert.equal(profile.totalTokens, 450);
    assert.equal(profile.riskDecisionCount, 1);
    assert.equal(profile.judgeDecisionCount, 2);
    assert.equal(profile.riskRatio, 0.5);
    assert.deepEqual(
      [...profile.knownTools].toSorted((a, b) => a.localeCompare(b)),
      ["read", "write"],
    );
    assert.equal(profile.toolDistribution.read, 0.5);
    assert.equal(profile.toolDistribution.write, 0.5);
  });
});

void describe("computeDeviation", () => {
  void it("detects tool distribution shift", () => {
    const baseline = {
      agentId: "agent-abc123",
      toolDistribution: { bash: 0.05, read: 0.95 },
      toolCallCount: 100,
      knownTools: new Set(["bash", "read"]),
    };
    const current = {
      agentId: "agent-abc123",
      toolDistribution: { bash: 0.6, read: 0.4 },
      toolCallCount: 5,
      knownTools: new Set(["bash", "read"]),
    };

    const deviations = computeDeviation(current, baseline);
    const bashChange = deviations.toolFrequencyChanges.find((entry) => entry.tool === "bash");

    assert.ok(bashChange);
    assert.equal(Math.round(bashChange.multiplier * 10) / 10, 12);
    assert.ok(deviations.toolDistributionDivergence > 0);
  });

  void it("detects token consumption spike", () => {
    const baseline = {
      agentId: "agent-abc123",
      toolDistribution: { read: 1 },
      toolCallCount: 10,
      avgInputTokensPerCall: 100,
      avgOutputTokensPerCall: 80,
      avgTotalTokensPerCall: 180,
      knownTools: new Set(["read"]),
    };
    const current = {
      agentId: "agent-abc123",
      toolDistribution: { read: 1 },
      toolCallCount: 1,
      avgInputTokensPerCall: 320,
      avgOutputTokensPerCall: 240,
      avgTotalTokensPerCall: 560,
      knownTools: new Set(["read"]),
    };

    const deviations = computeDeviation(current, baseline);

    assert.equal(Math.round(deviations.tokenDeviation.input.multiplier * 10) / 10, 3.2);
    assert.equal(Math.round(deviations.tokenDeviation.output.multiplier * 10) / 10, 3);
    assert.equal(Math.round(deviations.tokenDeviation.total.multiplier * 10) / 10, 3.1);
  });

  void it("detects novel tools", () => {
    const baseline = {
      agentId: "agent-abc123",
      toolDistribution: { read: 1 },
      toolCallCount: 10,
      knownTools: new Set(["read"]),
    };
    const current = {
      agentId: "agent-abc123",
      toolDistribution: { exec: 1 },
      toolCallCount: 1,
      knownTools: new Set(["exec"]),
    };

    const deviations = computeDeviation(current, baseline);

    assert.deepEqual(deviations.novelTools, ["exec"]);
  });

  void it("handles missing baseline gracefully", () => {
    const deviations = computeDeviation({ agentId: "agent-abc123" }, null);

    assert.equal(deviations.hasBaseline, false);
    assert.deepEqual(deviations.novelTools, []);
    assert.deepEqual(deviations.toolFrequencyChanges, []);
  });
});

void describe("detectAnomalies", () => {
  void it("respects threshold configuration", () => {
    const report = detectAnomalies(
      {
        agentId: "agent-abc123",
        hasBaseline: true,
        novelTools: [],
        toolFrequencyChanges: [
          { tool: "bash", baseline: 0.1, current: 0.29, multiplier: 2.9, delta: 0.19 },
        ],
        tokenDeviation: {
          total: { baseline: 100, current: 240, multiplier: 2.4 },
        },
        baseline: {
          sessionCount: 3,
          toolCallCount: 20,
          knownTools: new Set(["bash", "read"]),
        },
      },
      {
        lookbackDays: 7,
        toolDeviationThreshold: 3,
        tokenDeviationThreshold: 2.5,
      },
    );

    assert.equal(report.detected, false);
    assert.deepEqual(report.deviations, []);
  });

  void it("flags novel tools with configured severity", () => {
    const report = detectAnomalies(
      {
        agentId: "agent-abc123",
        hasBaseline: true,
        novelTools: ["exec"],
        toolFrequencyChanges: [],
        tokenDeviation: {},
        baseline: {
          sessionCount: 3,
          toolCallCount: 20,
          knownTools: new Set(["read", "write"]),
        },
      },
      {
        lookbackDays: 7,
        novelToolSeverity: "high",
      },
    );

    assert.equal(report.detected, true);
    assert.equal(report.severity, "high");
    assert.equal(report.deviations[0].type, "novel_tool");
  });
});

void describe("cache", () => {
  beforeEach(() => {
    invalidateProfileCache();
  });

  void it("invalidates cached profiles", () => {
    _cache.entries.set(7, {
      loadedAt: Date.now(),
      profileMap: new Map([["agent-abc123", { agentId: "agent-abc123" }]]),
    });

    assert.equal(_cache.entries.size, 1);
    invalidateProfileCache();
    assert.equal(_cache.entries.size, 0);
  });
});
