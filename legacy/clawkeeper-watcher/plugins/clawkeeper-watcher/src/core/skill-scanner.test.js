import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import { scanSkill } from "./skill-scanner.js";

const tempDirs = [];
const originalEnv = {
  HOME: process.env.HOME,
  OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR,
};

async function makeTempDir() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "clawkeeper-watcher-skill-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  process.env.HOME = originalEnv.HOME;
  if (originalEnv.OPENCLAW_STATE_DIR === undefined) {
    delete process.env.OPENCLAW_STATE_DIR;
  } else {
    process.env.OPENCLAW_STATE_DIR = originalEnv.OPENCLAW_STATE_DIR;
  }

  await Promise.all(
    tempDirs.splice(0).map(async (dir) => {
      await fs.rm(dir, { recursive: true, force: true });
    }),
  );
});

void describe("scanSkill", () => {
  void it("resolves named skills from the user ~/.openclaw skill directory", async () => {
    const homeDir = await makeTempDir();
    const remoteStateDir = await makeTempDir();
    const skillDir = path.join(homeDir, ".openclaw", "skills", "demo-skill");
    await fs.mkdir(skillDir, { recursive: true });
    await fs.writeFile(path.join(skillDir, "SKILL.md"), "# demo-skill\n", "utf8");
    await fs.writeFile(path.join(skillDir, "skill.json"), '{"name":"demo-skill"}\n', "utf8");

    process.env.HOME = homeDir;
    process.env.OPENCLAW_STATE_DIR = remoteStateDir;

    const report = await scanSkill("demo-skill");
    assert.equal(report.skillDir, skillDir);
    assert.equal(report.skillName, "demo-skill");
    assert.equal(report.score, 100);
  });
});
