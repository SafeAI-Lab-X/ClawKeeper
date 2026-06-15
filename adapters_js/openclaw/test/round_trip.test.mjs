/**
 * Round-trip test for the shim. Boots the Python server externally
 * (the test runner spawns it), then exercises judge() against it for
 * every relevant decision branch + the failure policies.
 *
 * Run with the Python server already listening on $CLAWKEEPER_TEST_URL
 * (default http://127.0.0.1:7474). Returns non-zero on assertion failure.
 */

import assert from "node:assert/strict";
import { judge } from "../src/judge.js";

const SERVER_URL = process.env.CLAWKEEPER_TEST_URL || "http://127.0.0.1:7474";


async function suite() {
  console.log(`[round_trip] using server: ${SERVER_URL}\n`);
  let passed = 0;
  let failed = 0;

  const it = async (name, fn) => {
    try {
      await fn();
      console.log(`  PASS  ${name}`);
      passed++;
    } catch (err) {
      console.log(`  FAIL  ${name}`);
      console.log(`        ${err.message}`);
      failed++;
    }
  };

  await it("user_requested_stop", async () => {
    const decision = await judge({
      mode: "local",
      forwardedContext: { messages: [{ role: "user", content: "stop" }] },
    }, { serverUrl: SERVER_URL });
    assert.equal(decision.decision, "stop");
    assert.equal(decision.stopReason, "user_requested_stop");
  });

  await it("dangerous bash -> ask_user", async () => {
    const decision = await judge({
      mode: "local",
      forwardedContext: {
        messages: [
          { role: "user", content: "deploy" },
          { role: "tool", toolName: "bash" },
        ],
      },
    }, { serverUrl: SERVER_URL });
    assert.equal(decision.decision, "ask_user");
    assert.equal(decision.stopReason, "waiting_user_confirmation");
  });

  await it("missing forwardedContext", async () => {
    const decision = await judge({ mode: "local" }, { serverUrl: SERVER_URL });
    assert.equal(decision.decision, "stop");
    assert.equal(decision.stopReason, "missing_input");
  });

  await it("benign read -> continue", async () => {
    const decision = await judge({
      mode: "local",
      forwardedContext: {
        messages: [
          { role: "user", content: "look at this" },
          { role: "tool", toolName: "read" },
        ],
      },
    }, { serverUrl: SERVER_URL });
    assert.equal(decision.decision, "continue");
  });

  await it("fail-closed on unreachable server", async () => {
    const decision = await judge(
      { mode: "local", forwardedContext: { messages: [{ role: "user", content: "x" }] } },
      { serverUrl: "http://127.0.0.1:1", failurePolicy: "fail-closed", timeoutMs: 500 },
    );
    assert.equal(decision.decision, "stop");
    assert.equal(decision.stopReason, "transport_failure_fail_closed");
  });

  await it("fail-open on unreachable server", async () => {
    const decision = await judge(
      { mode: "local", forwardedContext: { messages: [{ role: "user", content: "x" }] } },
      { serverUrl: "http://127.0.0.1:1", failurePolicy: "fail-open", timeoutMs: 500 },
    );
    assert.equal(decision.decision, "continue");
    assert.equal(decision.stopReason, "transport_failure_fail_open");
  });

  console.log(`\n[round_trip] ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

suite();
