import fs from "node:fs/promises";
import path from "node:path";

function getBackupRoot(stateDir) {
  return path.join(stateDir, ".clawkeeper-watcher", "backups");
}

export async function listBackups(stateDir) {
  try {
    return (await fs.readdir(getBackupRoot(stateDir))).toSorted().toReversed();
  } catch {
    return [];
  }
}

export async function rollback(stateDir, backupName) {
  const backups = await listBackups(stateDir);
  const selected = backupName ?? backups[0];
  if (!selected) {
    throw new Error("No Clawkeeper-Watcher backups found");
  }

  const backupDir = path.join(getBackupRoot(stateDir), selected);
  const manifest = JSON.parse(await fs.readFile(path.join(backupDir, "manifest.json"), "utf-8"));

  for (const file of manifest.files) {
    const target = path.join(stateDir, file.relativePath);
    if (file.backupName) {
      const source = path.join(backupDir, file.backupName);
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.copyFile(source, target);
      continue;
    }

    await fs.rm(target, { force: true });
  }

  return {
    backupDir,
    restoredFiles: manifest.files.map((file) => file.relativePath),
  };
}
