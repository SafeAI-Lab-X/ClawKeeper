import fs from 'node:fs';
import { createAuditContext, runAudit } from './audit-engine.js';

let watchers = [];
const watchTimers = new Map();

export async function startDriftMonitor(stateDir, pluginConfig = {}, logger = console) {
  await stopDriftMonitor();

  const context = await createAuditContext(stateDir, pluginConfig);
  for (const file of [context.configPath, context.soulPath]) {
    try {
      // Use watchFile for cross-platform stability with debouncing
      const fileWatcher = fs.watchFile(file, { interval: 1000 }, async (curr, prev) => {
        // Skip if file content hasn't actually changed (same mtime and size)
        if (curr.mtime === prev.mtime && curr.size === prev.size) {
          return;
        }

        // Debounce: avoid multiple rapid audits
        const fileKey = file;
        const existingTimer = watchTimers.get(fileKey);
        if (existingTimer) clearTimeout(existingTimer);

        const timer = setTimeout(async () => {
          try {
            const nextContext = await createAuditContext(stateDir, pluginConfig);
            const report = await runAudit(nextContext);
            const risky = report.findings.filter((item) => item.severity === 'CRITICAL' || item.severity === 'HIGH');
            if (risky.length > 0) {
              logger.warn(`[Clawkeeper] drift detected in ${file}: ${risky.map((item) => item.id).join(', ')}`);
            }
          } catch (error) {
            logger.error(`[Clawkeeper] drift monitor failed for ${file}: ${error.message}`);
          }
          watchTimers.delete(fileKey);
        }, 500);

        watchTimers.set(fileKey, timer);
      });
      watchers.push(fileWatcher);
    } catch {
      // best effort
    }
  }
}

export async function stopDriftMonitor() {
  for (const watcher of watchers) watcher.close();
  watchers = [];
  for (const timer of watchTimers.values()) clearTimeout(timer);
  watchTimers.clear();
}
