import assert from "node:assert/strict";
import { describe, it, beforeEach } from "node:test";
import {
  extractFingerprints,
  matchFingerprint,
  buildFingerprintReport,
  invalidateFingerprintCache,
  resolveFingerprint,
  _testExports,
} from "./risk-fingerprint.js";

const { buildFingerprintKey, getLookbackDateStamps, summarizeForwardedContextForFingerprint } =
  _testExports;

// ---------------------------------------------------------------------------
// Helpers: factory for decision memory records
// ---------------------------------------------------------------------------

function makeRecord(overrides = {}) {
  return {
    timestamp: "2026-03-24T10:00:00.000Z",
    mode: "remote",
    requestId: "req-1",
    sessionKey: "session-a",
    decision: "stop",
    stopReason: "tool_loop_limit",
    riskLevel: "high",
    nextAction: "stop_run",
    needsUserDecision: false,
    shouldContinue: false,
    localEnhanced: false,
    summary: "Tool loop detected.",
    evidence: ["toolCount=5"],
    messageCount: 6,
    toolCount: 2,
    toolNames: ["bash", "exec"],
    lastUserMessage: "run the script",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// buildFingerprintKey
// ---------------------------------------------------------------------------

void describe("buildFingerprintKey", () => {
  void it("builds key from sorted toolNames and stopReason", () => {
    assert.equal(
      buildFingerprintKey({ toolNames: ["exec", "bash"], stopReason: "tool_loop_limit" }),
      "bash,exec|tool_loop_limit",
    );
  });

  void it("sorts toolNames alphabetically", () => {
    assert.equal(
      buildFingerprintKey({ toolNames: ["write", "bash", "exec"], stopReason: "high_risk_action" }),
      "bash,exec,write|high_risk_action",
    );
  });

  void it("deduplicates toolNames", () => {
    assert.equal(
      buildFingerprintKey({ toolNames: ["bash", "bash", "exec"], stopReason: "tool_loop_limit" }),
      "bash,exec|tool_loop_limit",
    );
  });

  void it("handles empty toolNames", () => {
    assert.equal(
      buildFingerprintKey({ toolNames: [], stopReason: "user_requested_stop" }),
      "|user_requested_stop",
    );
  });

  void it("handles missing toolNames", () => {
    assert.equal(buildFingerprintKey({ stopReason: "upstream_error" }), "|upstream_error");
  });

  void it("handles missing stopReason", () => {
    assert.equal(buildFingerprintKey({ toolNames: ["bash"] }), "bash|unknown");
  });

  void it("handles non-string stopReason", () => {
    assert.equal(buildFingerprintKey({ toolNames: ["bash"], stopReason: 42 }), "bash|unknown");
  });
});

// ---------------------------------------------------------------------------
// getLookbackDateStamps
// ---------------------------------------------------------------------------

void describe("getLookbackDateStamps", () => {
  void it("returns correct number of date stamps", () => {
    const stamps = getLookbackDateStamps(3);
    assert.equal(stamps.length, 3);
  });

  void it("returns today first (most recent)", () => {
    // Use a fixed reference date to avoid timezone issues
    const ref = new Date("2026-03-24T04:00:00.000Z"); // Beijing: 2026-03-24 12:00
    const stamps = getLookbackDateStamps(3, ref);
    assert.equal(stamps[0], "2026-03-24");
    assert.equal(stamps[1], "2026-03-23");
    assert.equal(stamps[2], "2026-03-22");
  });

  void it("handles lookbackDays = 1 (just today)", () => {
    const ref = new Date("2026-03-24T04:00:00.000Z");
    const stamps = getLookbackDateStamps(1, ref);
    assert.equal(stamps.length, 1);
    assert.equal(stamps[0], "2026-03-24");
  });
});

// ---------------------------------------------------------------------------
// summarizeForwardedContextForFingerprint
// ---------------------------------------------------------------------------

void describe("summarizeForwardedContextForFingerprint", () => {
  void it("extracts unique tool names from messages", () => {
    const result = summarizeForwardedContextForFingerprint({
      forwardedContext: {
        messages: [
          { role: "tool", toolName: "bash" },
          { role: "tool", toolName: "exec" },
          { role: "tool", toolName: "bash" },
        ],
      },
    });
    assert.deepEqual(
      result.toolNames.toSorted((a, b) => a.localeCompare(b)),
      ["bash", "exec"],
    );
  });

  void it("handles missing forwardedContext", () => {
    const result = summarizeForwardedContextForFingerprint({});
    assert.deepEqual(result.toolNames, []);
  });

  void it("handles empty messages array", () => {
    const result = summarizeForwardedContextForFingerprint({
      forwardedContext: { messages: [] },
    });
    assert.deepEqual(result.toolNames, []);
  });

  void it("limits to 8 tool names", () => {
    const messages = Array.from({ length: 12 }, (_, i) => ({
      role: "tool",
      toolName: `tool-${i}`,
    }));
    const result = summarizeForwardedContextForFingerprint({
      forwardedContext: { messages },
    });
    assert.equal(result.toolNames.length, 8);
  });

  void it("supports name field fallback", () => {
    const result = summarizeForwardedContextForFingerprint({
      forwardedContext: {
        messages: [{ role: "tool", name: "write" }],
      },
    });
    assert.deepEqual(result.toolNames, ["write"]);
  });
});

// ---------------------------------------------------------------------------
// extractFingerprints
// ---------------------------------------------------------------------------

void describe("extractFingerprints", () => {
  void it("extracts fingerprints from stop and ask_user records", () => {
    const records = [
      makeRecord({ decision: "stop", stopReason: "tool_loop_limit" }),
      makeRecord({ decision: "ask_user", stopReason: "waiting_user_confirmation" }),
    ];
    const map = extractFingerprints(records);
    assert.equal(map.size, 2);
  });

  void it("ignores continue decisions", () => {
    const records = [
      makeRecord({ decision: "continue", riskLevel: "medium" }),
      makeRecord({ decision: "stop" }),
    ];
    const map = extractFingerprints(records);
    assert.equal(map.size, 1);
  });

  void it("counts occurrences correctly", () => {
    const records = [
      makeRecord({ decision: "stop", sessionKey: "s1" }),
      makeRecord({ decision: "stop", sessionKey: "s2" }),
      makeRecord({ decision: "stop", sessionKey: "s3" }),
    ];
    const map = extractFingerprints(records);
    const entry = map.values().next().value;
    assert.equal(entry.count, 3);
  });

  void it("tracks maxRiskLevel (highest wins)", () => {
    const records = [
      makeRecord({ decision: "stop", riskLevel: "medium" }),
      makeRecord({ decision: "stop", riskLevel: "critical" }),
      makeRecord({ decision: "stop", riskLevel: "high" }),
    ];
    const map = extractFingerprints(records);
    const entry = map.values().next().value;
    assert.equal(entry.maxRiskLevel, "critical");
  });

  void it("tracks unique sessions", () => {
    const records = [
      makeRecord({ decision: "stop", sessionKey: "s1" }),
      makeRecord({ decision: "stop", sessionKey: "s1" }),
      makeRecord({ decision: "stop", sessionKey: "s2" }),
    ];
    const map = extractFingerprints(records);
    const entry = map.values().next().value;
    assert.equal(entry.sessions.size, 2);
  });

  void it("handles empty and corrupt records gracefully", () => {
    const records = [null, undefined, {}, makeRecord({ decision: "stop" })];
    const map = extractFingerprints(records);
    assert.equal(map.size, 1);
  });

  void it("tracks lastSeen as latest timestamp", () => {
    const records = [
      makeRecord({ decision: "stop", timestamp: "2026-03-20T10:00:00.000Z" }),
      makeRecord({ decision: "stop", timestamp: "2026-03-24T10:00:00.000Z" }),
      makeRecord({ decision: "stop", timestamp: "2026-03-22T10:00:00.000Z" }),
    ];
    const map = extractFingerprints(records);
    const entry = map.values().next().value;
    assert.equal(entry.lastSeen, "2026-03-24T10:00:00.000Z");
  });
});

// ---------------------------------------------------------------------------
// matchFingerprint
// ---------------------------------------------------------------------------

void describe("matchFingerprint", () => {
  const records = [
    makeRecord({ decision: "stop", sessionKey: "s1" }),
    makeRecord({ decision: "stop", sessionKey: "s2" }),
    makeRecord({ decision: "stop", sessionKey: "s3" }),
  ];
  const fingerprintMap = extractFingerprints(records);

  void it("returns match when count >= threshold", () => {
    const match = matchFingerprint(
      { toolNames: ["bash", "exec"], stopReason: "tool_loop_limit" },
      fingerprintMap,
      2,
    );
    assert.ok(match);
    assert.equal(match.matched, true);
    assert.equal(match.occurrences, 3);
  });

  void it("returns null when count < threshold", () => {
    const match = matchFingerprint(
      { toolNames: ["bash", "exec"], stopReason: "tool_loop_limit" },
      fingerprintMap,
      10,
    );
    assert.equal(match, null);
  });

  void it("returns null when no matching key", () => {
    const match = matchFingerprint(
      { toolNames: ["unknown_tool"], stopReason: "never_seen" },
      fingerprintMap,
      1,
    );
    assert.equal(match, null);
  });

  void it("returns null for empty fingerprintMap", () => {
    const match = matchFingerprint(
      { toolNames: ["bash"], stopReason: "tool_loop_limit" },
      new Map(),
      1,
    );
    assert.equal(match, null);
  });

  void it("returns null for null fingerprintMap", () => {
    const match = matchFingerprint({ toolNames: ["bash"], stopReason: "tool_loop_limit" }, null, 1);
    assert.equal(match, null);
  });

  void it("populates all match fields correctly", () => {
    const match = matchFingerprint(
      { toolNames: ["bash", "exec"], stopReason: "tool_loop_limit" },
      fingerprintMap,
      1,
    );
    assert.ok(match);
    assert.equal(match.matched, true);
    assert.equal(typeof match.key, "string");
    assert.equal(typeof match.occurrences, "number");
    assert.equal(typeof match.maxRiskLevel, "string");
    assert.equal(typeof match.sessionCount, "number");
    assert.equal(typeof match.lastSeen, "string");
    assert.ok(Array.isArray(match.toolNames));
    assert.equal(typeof match.stopReason, "string");
    assert.equal(typeof match.warning, "string");
  });
});

// ---------------------------------------------------------------------------
// buildFingerprintReport
// ---------------------------------------------------------------------------

void describe("buildFingerprintReport", () => {
  void it("produces human-readable report for qualified fingerprints", () => {
    const records = [
      makeRecord({ decision: "stop", sessionKey: "s1" }),
      makeRecord({ decision: "stop", sessionKey: "s2" }),
    ];
    const map = extractFingerprints(records);
    const report = buildFingerprintReport(map, 2);
    assert.ok(report.includes("Risk Fingerprints"));
    assert.ok(report.includes("bash, exec"));
    assert.ok(report.includes("tool_loop_limit"));
  });

  void it("returns empty-state message when no patterns qualify", () => {
    const map = extractFingerprints([makeRecord({ decision: "stop" })]);
    const report = buildFingerprintReport(map, 5);
    assert.ok(report.includes("No recurring risk fingerprints"));
  });

  void it("sorts by count descending", () => {
    const records = [
      makeRecord({ decision: "stop", toolNames: ["bash"], stopReason: "r1", sessionKey: "s1" }),
      makeRecord({ decision: "stop", toolNames: ["bash"], stopReason: "r1", sessionKey: "s2" }),
      makeRecord({ decision: "stop", toolNames: ["bash"], stopReason: "r1", sessionKey: "s3" }),
      makeRecord({ decision: "stop", toolNames: ["exec"], stopReason: "r2", sessionKey: "s1" }),
      makeRecord({ decision: "stop", toolNames: ["exec"], stopReason: "r2", sessionKey: "s2" }),
    ];
    const map = extractFingerprints(records);
    const report = buildFingerprintReport(map, 2);
    // "bash|r1" (count 3) should appear before "exec|r2" (count 2)
    const bashPos = report.indexOf("bash|r1");
    const execPos = report.indexOf("exec|r2");
    assert.ok(bashPos < execPos, "Higher count fingerprint should appear first");
  });
});

// ---------------------------------------------------------------------------
// resolveFingerprint
// ---------------------------------------------------------------------------

void describe("resolveFingerprint", () => {
  void it("returns null when fingerprint is disabled", async () => {
    const result = await resolveFingerprint({
      body: {},
      decision: { stopReason: "tool_loop_limit" },
      config: {},
    });
    assert.equal(result, null);
  });

  void it("returns null when config.fingerprint.enabled is false", async () => {
    const result = await resolveFingerprint({
      body: {},
      decision: { stopReason: "tool_loop_limit" },
      config: { fingerprint: { enabled: false } },
    });
    assert.equal(result, null);
  });
});

// ---------------------------------------------------------------------------
// invalidateFingerprintCache
// ---------------------------------------------------------------------------

void describe("invalidateFingerprintCache", () => {
  beforeEach(() => {
    invalidateFingerprintCache();
  });

  void it("clears all cache entries", () => {
    const { _cache } = _testExports;
    // Simulate a cached entry
    _cache.entries.set(7, { fingerprintMap: new Map(), loadedAt: Date.now() });
    assert.equal(_cache.entries.size, 1);

    invalidateFingerprintCache();
    assert.equal(_cache.entries.size, 0);
  });
});
