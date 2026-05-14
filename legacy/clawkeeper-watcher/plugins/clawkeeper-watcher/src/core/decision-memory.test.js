import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { _testExports } from "./decision-memory.js";

const { buildDecisionMemoryRecord, shouldPersistDecision, summarizeForwardedContext } =
  _testExports;

void describe("shouldPersistDecision", () => {
  void it("persists ask_user decisions", () => {
    assert.equal(
      shouldPersistDecision({
        decision: "ask_user",
        riskLevel: "high",
      }),
      true,
    );
  });

  void it("persists stop decisions", () => {
    assert.equal(
      shouldPersistDecision({
        decision: "stop",
        riskLevel: "medium",
      }),
      true,
    );
  });

  void it("persists medium-risk continue decisions", () => {
    assert.equal(
      shouldPersistDecision({
        decision: "continue",
        riskLevel: "medium",
      }),
      true,
    );
  });

  void it("skips low-risk continue decisions", () => {
    assert.equal(
      shouldPersistDecision({
        decision: "continue",
        riskLevel: "low",
      }),
      false,
    );
  });
});

void describe("summarizeForwardedContext", () => {
  void it("extracts session summary from forwarded messages", () => {
    const summary = summarizeForwardedContext({
      requestId: "req-1",
      forwardedContext: {
        metadata: {
          sessionKey: "agent:main:main",
        },
        messages: [
          { role: "user", content: "first message" },
          { role: "assistant", content: "working on it" },
          { role: "tool", toolName: "bash" },
          { role: "user", content: "please continue carefully" },
          { role: "tool", name: "write" },
        ],
      },
    });

    assert.deepEqual(summary, {
      requestId: "req-1",
      sessionKey: "agent:main:main",
      messageCount: 5,
      toolCount: 2,
      toolNames: ["bash", "write"],
      lastUserMessage: "please continue carefully",
    });
  });
});

void describe("buildDecisionMemoryRecord", () => {
  void it("builds a compact record for remote memory", () => {
    const record = buildDecisionMemoryRecord({
      mode: "remote",
      body: {
        requestId: "req-2",
        forwardedContext: {
          metadata: {
            sessionKey: "agent:worker:one",
          },
          messages: [
            { role: "user", content: "run the command" },
            { role: "tool", toolName: "exec" },
          ],
        },
      },
      decision: {
        decision: "ask_user",
        stopReason: "waiting_user_confirmation",
        riskLevel: "high",
        nextAction: "ask_user",
        needsUserDecision: true,
        shouldContinue: false,
        localEnhanced: false,
        summary: "The context contains high-risk actions.",
        evidence: ["requestId=req-2", "tool=exec", "toolCount=1"],
      },
    });

    assert.equal(record.mode, "remote");
    assert.equal(record.requestId, "req-2");
    assert.equal(record.sessionKey, "agent:worker:one");
    assert.equal(record.decision, "ask_user");
    assert.equal(record.stopReason, "waiting_user_confirmation");
    assert.equal(record.riskLevel, "high");
    assert.deepEqual(record.toolNames, ["exec"]);
    assert.equal(record.toolCount, 1);
    assert.equal(record.lastUserMessage, "run the command");
    assert.deepEqual(record.evidence, ["requestId=req-2", "tool=exec", "toolCount=1"]);
    assert.ok(typeof record.timestamp === "string" && record.timestamp.length > 0);
  });
});
