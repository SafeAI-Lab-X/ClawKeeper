import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import { createAuditContext, runAudit } from "./audit-engine.js";
import { harden } from "./hardening.js";
import { rollback } from "./rollback.js";

const tempDirs = [];

async function makeStateDir() {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawkeeper-watcher-hardening-"));
  tempDirs.push(stateDir);
  return stateDir;
}

afterEach(async () => {
  await Promise.all(
    tempDirs.splice(0).map(async (dir) => {
      await fs.rm(dir, { recursive: true, force: true });
    }),
  );
});

void describe("harden + rollback", () => {
  void it("audits valid OpenClaw config keys and remediates them safely", async () => {
    const stateDir = await makeStateDir();
    const configPath = path.join(stateDir, "openclaw.json");
    await fs.writeFile(
      configPath,
      `${JSON.stringify(
        {
          gateway: {
            bind: "lan",
            auth: {
              mode: "token",
              token: "test-token",
            },
          },
          agents: {
            defaults: {
              sandbox: {
                mode: "off",
              },
            },
          },
          tools: {
            exec: {
              security: "full",
            },
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    const report = await runAudit(await createAuditContext(stateDir));
    assert.deepEqual(
      report.findings.map((item) => item.id).toSorted((left, right) => left.localeCompare(right)),
      [
        "behavior.runtime-constitution",
        "execution.bounded-filesystem",
        "execution.human-checkpoint",
        "network.local-gateway",
      ],
    );

    const hardenResult = await harden(stateDir);
    assert.deepEqual(hardenResult.actions, [
      "gateway.bind -> loopback",
      "agents.defaults.sandbox.mode -> all",
      "tools.exec.security -> allowlist",
      "AGENTS.md injected with runtime constitution",
    ]);

    const hardenedConfig = JSON.parse(await fs.readFile(configPath, "utf8"));
    assert.equal(hardenedConfig.gateway.bind, "loopback");
    assert.equal(hardenedConfig.agents.defaults.sandbox.mode, "all");
    assert.equal(hardenedConfig.tools.exec.security, "allowlist");

    const agentsPath = path.join(stateDir, "AGENTS.md");
    const agentsContent = await fs.readFile(agentsPath, "utf8");
    assert.match(agentsContent, /clawkeeper-watcher:rules:start/);

    const rollbackResult = await rollback(stateDir, path.basename(hardenResult.backupDir));
    assert.deepEqual(rollbackResult.restoredFiles, ["openclaw.json", "AGENTS.md"]);

    const rolledBackConfig = JSON.parse(await fs.readFile(configPath, "utf8"));
    assert.equal(rolledBackConfig.gateway.bind, "lan");
    assert.equal(rolledBackConfig.agents.defaults.sandbox.mode, "off");
    assert.equal(rolledBackConfig.tools.exec.security, "full");

    await assert.rejects(fs.access(agentsPath), { code: "ENOENT" });
  });
});
