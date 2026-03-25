import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { invalidateProfileCache } from "../core/agent-profiler.js";
import { invalidateFingerprintCache } from "../core/risk-fingerprint.js";
import { createContextJudgeHttpHandler } from "./context-judge-http.js";

const originalEnv = {
  HOME: process.env.HOME,
  OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR,
};

let tempDir = "";

function makeLogger() {
  return {
    info() {},
    warn() {},
  };
}

async function invokeHandler(handler, body) {
  const payload = Buffer.from(JSON.stringify(body));
  const req = {
    method: "POST",
    async *[Symbol.asyncIterator]() {
      yield payload;
    },
  };

  const response = {
    statusCode: 0,
    headers: {},
    body: "",
    setHeader(name, value) {
      this.headers[name] = value;
    },
    end(value) {
      this.body = String(value ?? "");
    },
  };

  await handler(req, response);
  return JSON.parse(response.body);
}

beforeEach(async () => {
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawkeeper-context-judge-"));
  process.env.HOME = tempDir;
  process.env.OPENCLAW_STATE_DIR = path.join(tempDir, ".clawkeeper", "remote", "state");
  await fs.mkdir(process.env.OPENCLAW_STATE_DIR, { recursive: true });
  invalidateFingerprintCache();
  invalidateProfileCache();
});

afterEach(async () => {
  invalidateFingerprintCache();
  invalidateProfileCache();
  process.env.HOME = originalEnv.HOME;
  if (originalEnv.OPENCLAW_STATE_DIR === undefined) {
    delete process.env.OPENCLAW_STATE_DIR;
  } else {
    process.env.OPENCLAW_STATE_DIR = originalEnv.OPENCLAW_STATE_DIR;
  }
  if (tempDir) {
    await fs.rm(tempDir, { recursive: true, force: true });
    tempDir = "";
  }
});

void describe("createContextJudgeHttpHandler", () => {
  void it("invalidates fingerprint cache after persisting decision memory", async () => {
    const handler = createContextJudgeHttpHandler({
      logger: makeLogger(),
      mode: "remote",
      contextJudgeConfig: {
        fingerprint: {
          enabled: true,
          lookbackDays: 1,
          minOccurrences: 2,
        },
      },
    });

    const body = {
      requestId: "fp-seq-1",
      forwardedContext: {
        metadata: {
          sessionKey: "agent:demo:1",
        },
        messages: [
          { role: "user", content: "继续执行" },
          { role: "tool", toolName: "bash", raw: "echo hi" },
        ],
      },
    };

    const first = await invokeHandler(handler, body);
    const second = await invokeHandler(handler, {
      ...body,
      requestId: "fp-seq-2",
      forwardedContext: {
        ...body.forwardedContext,
        metadata: { sessionKey: "agent:demo:2" },
      },
    });
    const third = await invokeHandler(handler, {
      ...body,
      requestId: "fp-seq-3",
      forwardedContext: {
        ...body.forwardedContext,
        metadata: { sessionKey: "agent:demo:3" },
      },
    });

    assert.equal(first.fingerprint, undefined);
    assert.equal(second.fingerprint, undefined);
    assert.ok(third.fingerprint);
    assert.equal(third.fingerprint.key, "bash|waiting_user_confirmation");
    assert.equal(third.fingerprint.occurrences, 2);
  });
});
