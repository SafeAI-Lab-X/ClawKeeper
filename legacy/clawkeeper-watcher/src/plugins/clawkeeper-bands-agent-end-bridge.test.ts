import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setActivePluginRegistry } from "../plugins/runtime.js";
import { createOutboundTestPlugin, createTestRegistry } from "../test-utils/channel-plugins.js";

describe("clawkeeper-bands agent_end bridge", () => {
  const envSnapshot = {
    OPENCLAW_HOME: process.env.OPENCLAW_HOME,
    OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR,
    OPENCLAW_TEST_FAST: process.env.OPENCLAW_TEST_FAST,
  };

  let tempDir = "";

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "clawkeeper-bands-bridge-test-"));
    process.env.OPENCLAW_HOME = path.join(tempDir, ".openclaw");
    process.env.OPENCLAW_STATE_DIR = path.join(tempDir, ".openclaw");
    process.env.OPENCLAW_TEST_FAST = "1";
    vi.resetModules();
  });

  afterEach(() => {
    process.env.OPENCLAW_HOME = envSnapshot.OPENCLAW_HOME;
    process.env.OPENCLAW_STATE_DIR = envSnapshot.OPENCLAW_STATE_DIR;
    process.env.OPENCLAW_TEST_FAST = envSnapshot.OPENCLAW_TEST_FAST;
    vi.restoreAllMocks();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it("routes ask_user replies to the current session delivery target", async () => {
    const sendText = vi.fn(async () => ({ channel: "discord", messageId: "discord-msg-1" }));
    setActivePluginRegistry(
      createTestRegistry([
        {
          pluginId: "discord",
          source: "test",
          plugin: createOutboundTestPlugin({
            id: "discord",
            outbound: {
              deliveryMode: "direct",
              sendText,
            },
          }),
        },
      ]),
    );

    const storePath = path.join(tempDir, "sessions.json");
    fs.writeFileSync(
      storePath,
      `${JSON.stringify(
        {
          "agent:main:main": {
            deliveryContext: {
              channel: "discord",
              to: "channel:test-room",
            },
            lastChannel: "discord",
            lastTo: "channel:test-room",
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    const fetchMock = vi.fn(async () => {
      return new Response(
        JSON.stringify({
          version: 1,
          decision: "ask_user",
          stopReason: "waiting_user_confirmation",
          shouldContinue: false,
          needsUserDecision: true,
          userQuestion: "Please confirm before continuing.",
          summary: "High-risk action detected.",
          riskLevel: "high",
          evidence: ["tool=bash"],
          nextAction: "ask_user",
          continueHint: "Only continue after explicit confirmation.",
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        },
      );
    });
    vi.stubGlobal("fetch", fetchMock);

    const { createAgentEndBridgeHook } =
      await import("../../plugins/clawkeeper-bands/src/plugin/agent-end-bridge.js");
    const hook = createAgentEndBridgeHook(
      {
        bridge: {
          enabled: true,
          url: "http://127.0.0.1:18790",
          token: "test-token",
        },
      },
      {
        session: {
          store: storePath,
        },
      },
    );

    await hook(
      {
        success: true,
        durationMs: 123,
        messages: [
          { role: "user", content: "Please run bash and continue if safe." },
          { role: "assistant", content: "I will inspect first." },
          { role: "tool", toolName: "bash", result: "echo hello\nhello" },
        ],
      },
      {
        agentId: "main",
        sessionId: "session-bridge-test",
        sessionKey: "agent:main:main",
        workspaceDir: tempDir,
      },
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(sendText).toHaveBeenCalledTimes(1);
    expect(sendText).toHaveBeenCalledWith(
      expect.objectContaining({
        to: "channel:test-room",
        text: "Please confirm before continuing.",
      }),
    );
  });
});
