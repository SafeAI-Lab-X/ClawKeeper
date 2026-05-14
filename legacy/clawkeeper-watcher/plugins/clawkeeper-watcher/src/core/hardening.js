import fs from "node:fs/promises";
import path from "node:path";
import { createAuditContext } from "./audit-engine.js";
import { getControls } from "./controls.js";
import { getConfigPath } from "./state.js";

export async function harden(stateDir, pluginConfig = {}) {
  const backupDir = await createBackupDir(stateDir);
  const configPath = getConfigPath(stateDir);
  const context = await createAuditContext(stateDir, pluginConfig);
  const actions = [];
  const files = [];

  await backupFile(
    configPath,
    path.join(backupDir, path.basename(configPath)),
    files,
    path.basename(configPath),
  );
  await backupFile(
    path.join(stateDir, "AGENTS.md"),
    path.join(backupDir, "AGENTS.md"),
    files,
    "AGENTS.md",
  );

  for (const control of getControls()) {
    if (!control.remediate) {
      continue;
    }
    const outcome = await control.describe(context);
    if (!outcome?.autoFixable) {
      continue;
    }

    const action = await control.remediate(context);
    if (action) {
      actions.push(action);
    }
  }

  await fs.writeFile(
    path.join(backupDir, "manifest.json"),
    `${JSON.stringify(
      {
        createdAt: new Date().toISOString(),
        actions,
        files,
      },
      null,
      2,
    )}\n`,
    "utf-8",
  );

  return {
    backupDir,
    actions,
  };
}

async function createBackupDir(stateDir) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupDir = path.join(stateDir, ".clawkeeper-watcher", "backups", timestamp);
  await fs.mkdir(backupDir, { recursive: true });
  return backupDir;
}

async function backupFile(source, destination, files, relativePath) {
  try {
    await fs.access(source);
    await fs.mkdir(path.dirname(destination), { recursive: true });
    await fs.copyFile(source, destination);
    files.push({ relativePath, backupName: path.basename(destination), existed: true });
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      files.push({ relativePath, backupName: null, existed: false });
      return;
    }
    // best effort
  }
}
