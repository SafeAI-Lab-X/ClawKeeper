import fs from "node:fs/promises";
import path from "node:path";
import { scanSkill } from "./skill-scanner.js";
import { notifySkillGuardAlertToUserBridge } from "./startup-audit-notify.js";
import { resolveUserOpenClawStateDir } from "./state.js";

/** @type {ReturnType<typeof setInterval> | null} */
let guardInterval = null;

/** skillName → last-notified alert fingerprint */
const notifiedAlertKeys = new Map();

const DEFAULT_INTERVAL_MINUTES = 30;
const MIN_INTERVAL_MINUTES = 1;

/**
 * Build a deduplication key from a skill scan report.
 * Format: `skillName::score::top5RiskyIds`
 * Key only changes when the actual risky findings change.
 */
function buildSkillGuardAlertKey(skillName, report) {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  const risky = findings
    .filter((item) => item?.severity === "CRITICAL" || item?.severity === "HIGH")
    .slice(0, 5)
    .map((item) => item?.id || item?.title)
    .filter(Boolean)
    .join(",");

  return `${skillName}::${report?.score ?? "na"}::${risky}`;
}

/**
 * Run a single scan cycle over all skills in ~/.openclaw/skills/.
 * - Logs every result
 * - Only notifies userBridge for CRITICAL/HIGH findings (with dedup)
 */
async function runSkillGuardCycle(pluginConfig, logger) {
  let stateDir;
  try {
    stateDir = await resolveUserOpenClawStateDir();
  } catch (error) {
    logger.warn?.(`[Clawkeeper] skill-guard: failed to resolve user state dir: ${error.message}`);
    return;
  }

  const skillsDir = path.join(stateDir, "skills");

  let entries;
  try {
    entries = await fs.readdir(skillsDir, { withFileTypes: true });
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "EACCES") {
      logger.debug?.(`[Clawkeeper] skill-guard: skills dir not found or not accessible, skipping`);
      return;
    }
    logger.warn?.(`[Clawkeeper] skill-guard: failed to read skills dir: ${error.message}`);
    return;
  }

  const skillDirs = entries.filter((entry) => entry.isDirectory());
  if (skillDirs.length === 0) {
    logger.debug?.(`[Clawkeeper] skill-guard: no skills found, skipping`);
    return;
  }

  const currentSkillNames = new Set();

  for (const entry of skillDirs) {
    const skillName = entry.name;
    if (skillName === "clawkeeper-watcher") {
      continue;
    }
    currentSkillNames.add(skillName);

    let report;
    try {
      report = await scanSkill(path.join(skillsDir, skillName));
    } catch (error) {
      logger.warn?.(`[Clawkeeper] skill-guard: scan failed for ${skillName}: ${error.message}`);
      continue;
    }

    const summary = report.summary ?? {};
    logger.info?.(
      `[Clawkeeper] skill-guard scanned ${skillName}: score=${report.score}/100 ` +
        `critical=${summary.critical ?? 0} high=${summary.high ?? 0} ` +
        `medium=${summary.medium ?? 0} low=${summary.low ?? 0}`,
    );

    const risky = (report.findings ?? []).filter(
      (item) => item?.severity === "CRITICAL" || item?.severity === "HIGH",
    );

    if (risky.length > 0) {
      const alertKey = buildSkillGuardAlertKey(skillName, report);
      if (notifiedAlertKeys.get(skillName) !== alertKey) {
        try {
          const notifyResult = await notifySkillGuardAlertToUserBridge({
            pluginConfig,
            report,
            logger,
            skillName,
          });
          if (notifyResult.sent) {
            notifiedAlertKeys.set(skillName, alertKey);
            logger.info?.(`[Clawkeeper] skill-guard alert sent for ${skillName}`);
          }
        } catch (error) {
          // Don't update key on failure so we retry next cycle
          logger.warn?.(
            `[Clawkeeper] skill-guard alert notification failed for ${skillName}: ${error.message}`,
          );
        }
      }
    } else if (notifiedAlertKeys.has(skillName)) {
      // Skill is now clean — clear key so regression re-triggers notification
      notifiedAlertKeys.delete(skillName);
    }
  }

  // Prune stale keys for uninstalled skills
  for (const key of notifiedAlertKeys.keys()) {
    if (!currentSkillNames.has(key)) {
      notifiedAlertKeys.delete(key);
    }
  }
}

/**
 * Start periodic skill guard scanning.
 * Local mode only. Runs one immediate cycle, then repeats on interval.
 */
export async function startSkillGuard(pluginConfig = {}, logger = console) {
  await stopSkillGuard();

  const rawInterval = pluginConfig.skillGuard?.intervalMinutes;
  const intervalMinutes = Math.max(
    MIN_INTERVAL_MINUTES,
    Number.isFinite(rawInterval) ? rawInterval : DEFAULT_INTERVAL_MINUTES,
  );
  const intervalMs = intervalMinutes * 60 * 1000;

  // Immediate first scan
  await runSkillGuardCycle(pluginConfig, logger);

  guardInterval = setInterval(() => {
    runSkillGuardCycle(pluginConfig, logger).catch((error) => {
      logger.warn?.(`[Clawkeeper] skill-guard cycle error: ${error.message}`);
    });
  }, intervalMs);

  // Don't prevent Node from exiting
  if (guardInterval.unref) {
    guardInterval.unref();
  }
}

/**
 * Stop the skill guard timer and clear dedup state.
 */
export async function stopSkillGuard() {
  if (guardInterval !== null) {
    clearInterval(guardInterval);
    guardInterval = null;
  }
  notifiedAlertKeys.clear();
}

// Exported for testing only
export const _testExports = {
  runSkillGuardCycle,
  buildSkillGuardAlertKey,
  get notifiedAlertKeys() {
    return notifiedAlertKeys;
  },
};
