import { getControls } from "./controls.js";
import { PLUGIN_NAME, VERSION } from "./metadata.js";
import { getConfigPath, getSoulPath, readJsonIfExists } from "./state.js";

const SCORE_BY_SEVERITY = {
  CRITICAL: 20,
  HIGH: 10,
  MEDIUM: 5,
  LOW: 2,
  INFO: 0,
};

export async function createAuditContext(stateDir, pluginConfig = {}) {
  const configPath = getConfigPath(stateDir);
  const config = await readJsonIfExists(configPath);
  return {
    stateDir,
    configPath,
    soulPath: getSoulPath(stateDir),
    config,
    strictMode: Boolean(pluginConfig.strictMode),
  };
}

export async function runAudit(context) {
  const findings = [];
  for (const control of getControls()) {
    const outcome = await control.describe(context);
    if (!outcome) {
      continue;
    }
    const autoFixable = outcome.autoFixable ?? Boolean(control.remediate);
    findings.push({
      id: control.id,
      category: control.category,
      threat: control.threat,
      intent: control.intent,
      severity: outcome.severity ?? control.severity,
      title: control.title,
      description: outcome.description,
      evidence: outcome.evidence ?? {},
      remediation: outcome.remediation,
      autoFixable,
      canAutoFix: autoFixable,
      nextStep: buildNextStep({
        autoFixable,
        severity: outcome.severity ?? control.severity,
        remediation: outcome.remediation,
        id: control.id,
      }),
    });
  }

  return {
    tool: PLUGIN_NAME,
    version: VERSION,
    timestamp: new Date().toISOString(),
    stateDir: context.stateDir,
    configPath: context.configPath,
    score: calculateScore(findings),
    summary: summarize(findings),
    threatSummary: summarizeThreats(findings),
    nextSteps: buildNextSteps(findings),
    findings,
  };
}

function calculateScore(findings) {
  const deducted = findings.reduce((sum, item) => sum + SCORE_BY_SEVERITY[item.severity], 0);
  return Math.max(0, 100 - deducted);
}

function summarize(findings) {
  return findings.reduce(
    (summary, item) => {
      summary[item.severity.toLowerCase()] += 1;
      if (item.autoFixable) {
        summary.autoFixable += 1;
      }
      return summary;
    },
    {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      autoFixable: 0,
    },
  );
}

function summarizeThreats(findings) {
  return findings.reduce((summary, item) => {
    summary[item.threat] = (summary[item.threat] ?? 0) + 1;
    return summary;
  }, {});
}

function buildNextStep({ autoFixable, severity, remediation, id }) {
  if (autoFixable) {
    return `Can be auto-fixed. First run \`npx openclaw clawkeeper-watcher harden\`, then re-run \`npx openclaw clawkeeper-watcher audit\` to verify ${id}.`;
  }

  if (severity === "CRITICAL" || severity === "HIGH") {
    return `Manual action required. Fix according to "${remediation}", then re-run \`npx openclaw clawkeeper-watcher audit\`.`;
  }

  return `After adjusting per "${remediation}", re-run \`npx openclaw clawkeeper-watcher audit\` to confirm the results.`;
}

function buildNextSteps(findings) {
  if (findings.length === 0) {
    return [
      "No issues found. Continue maintaining security posture and regularly run `npx openclaw clawkeeper-watcher audit`.",
    ];
  }

  const criticalOrHigh = findings.filter(
    (item) => item.severity === "CRITICAL" || item.severity === "HIGH",
  );
  const autoFixable = findings.filter((item) => item.autoFixable);
  const manual = findings.filter((item) => !item.autoFixable);
  const steps = [];

  if (criticalOrHigh.length > 0) {
    steps.push(
      `Address high-severity items first: ${criticalOrHigh.map((item) => item.id).join(", ")}.`,
    );
  }

  if (autoFixable.length > 0) {
    steps.push("Run `npx openclaw clawkeeper-watcher harden` for items that can be auto-fixed.");
  }

  if (manual.length > 0) {
    steps.push(`Items requiring manual fixes: ${manual.map((item) => item.id).join(", ")}.`);
  }

  steps.push("After fixes are complete, run `npx openclaw clawkeeper-watcher audit` to verify.");
  return steps;
}
