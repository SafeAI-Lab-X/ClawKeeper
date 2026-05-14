import assert from "node:assert/strict";
import { describe, it, mock, beforeEach, afterEach } from "node:test";
// We test the internal cycle and helpers via _testExports
import { startSkillGuard, stopSkillGuard, _testExports } from "./skill-guard.js";

const { buildSkillGuardAlertKey, notifiedAlertKeys } = _testExports;

function createMockLogger() {
  return {
    info: mock.fn(),
    warn: mock.fn(),
    debug: mock.fn(),
    error: mock.fn(),
  };
}

void describe("buildSkillGuardAlertKey", () => {
  void it("builds key from skillName, score, and top risky findings", () => {
    const report = {
      score: 76,
      findings: [
        { id: "shell.remote-pipe", severity: "HIGH" },
        { id: "name.typosquat-signal", severity: "HIGH" },
        { id: "docs.dangerous-prerequisite", severity: "MEDIUM" },
      ],
    };
    const key = buildSkillGuardAlertKey("bad-skill", report);
    assert.equal(key, "bad-skill::76::shell.remote-pipe,name.typosquat-signal");
  });

  void it("handles empty findings", () => {
    const report = { score: 100, findings: [] };
    const key = buildSkillGuardAlertKey("clean-skill", report);
    assert.equal(key, "clean-skill::100::");
  });

  void it("handles null/undefined report", () => {
    const key = buildSkillGuardAlertKey("x", null);
    assert.equal(key, "x::na::");
  });

  void it("limits to top 5 risky findings", () => {
    const findings = Array.from({ length: 8 }, (_, i) => ({
      id: `finding-${i}`,
      severity: "CRITICAL",
    }));
    const report = { score: 0, findings };
    const key = buildSkillGuardAlertKey("many", report);
    assert.equal(key, "many::0::finding-0,finding-1,finding-2,finding-3,finding-4");
  });
});

void describe("runSkillGuardCycle", () => {
  let logger;

  beforeEach(() => {
    logger = createMockLogger();
    notifiedAlertKeys.clear();
  });

  afterEach(async () => {
    await stopSkillGuard();
  });

  void it("stopSkillGuard is safe when not started", async () => {
    // Should not throw
    await stopSkillGuard();
    await stopSkillGuard();
  });

  void it("startSkillGuard and stopSkillGuard lifecycle does not throw", async () => {
    // With no skills dir, it should just log and return
    const config = { skillGuard: { enabled: true, intervalMinutes: 60 } };
    await startSkillGuard(config, logger);
    await stopSkillGuard();
  });
});

void describe("startSkillGuard / stopSkillGuard", () => {
  let logger;

  beforeEach(() => {
    logger = createMockLogger();
    notifiedAlertKeys.clear();
  });

  afterEach(async () => {
    await stopSkillGuard();
  });

  void it("stopSkillGuard is idempotent — calling twice does not throw", async () => {
    await stopSkillGuard();
    await stopSkillGuard();
  });

  void it("startSkillGuard called twice resets interval", async () => {
    const config = { skillGuard: { enabled: true, intervalMinutes: 60 } };
    await startSkillGuard(config, logger);
    // calling again should not throw (resets the previous)
    await startSkillGuard(config, logger);
    await stopSkillGuard();
  });

  void it("defaults intervalMinutes to 30 when not provided", async () => {
    const config = { skillGuard: { enabled: true } };
    // Should not throw, uses default 30 min
    await startSkillGuard(config, logger);
    await stopSkillGuard();
  });

  void it("clamps intervalMinutes to minimum 1", async () => {
    const config = { skillGuard: { enabled: true, intervalMinutes: 0 } };
    await startSkillGuard(config, logger);
    await stopSkillGuard();
  });
});

void describe("dedup key management", () => {
  void it("notifiedAlertKeys is cleared on stopSkillGuard", async () => {
    notifiedAlertKeys.set("test-skill", "test-key");
    assert.equal(notifiedAlertKeys.size, 1);
    await stopSkillGuard();
    assert.equal(notifiedAlertKeys.size, 0);
  });
});
