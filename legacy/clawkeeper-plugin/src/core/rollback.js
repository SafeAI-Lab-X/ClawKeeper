import fs from 'node:fs/promises';
import path from 'node:path';

function getBackupRoot(stateDir) {
  return path.join(stateDir, '.clawkeeper', 'backups');
}

export async function listBackups(stateDir) {
  try {
    return (await fs.readdir(getBackupRoot(stateDir))).sort().reverse();
  } catch {
    return [];
  }
}

export async function rollback(stateDir, backupName) {
  const backups = await listBackups(stateDir);
  const selected = backupName ?? backups[0];
  if (!selected) {
    throw new Error('No Clawkeeper backups found');
  }

  const backupDir = path.join(getBackupRoot(stateDir), selected);
  const manifest = JSON.parse(await fs.readFile(path.join(backupDir, 'manifest.json'), 'utf-8'));

  for (const file of manifest.files) {
    const source = path.join(backupDir, file.backupName);
    const target = path.join(stateDir, file.relativePath);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.copyFile(source, target);
  }

  return {
    backupDir,
    restoredFiles: manifest.files.map((file) => file.relativePath)
  };
}
