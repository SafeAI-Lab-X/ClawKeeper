export function formatConsoleReport(report) {
  const threats = Object.entries(report.threatSummary)
    .map(([key, value]) => `${key}=${String(value)}`)
    .join(" ");

  const lines = [
    "Clawkeeper-Watcher Audit Report",
    `score      ${report.score}/100`,
    `target_dir ${report.stateDir}`,
    `summary    critical=${report.summary.critical} high=${report.summary.high} medium=${report.summary.medium} low=${report.summary.low} auto_fixable=${report.summary.autoFixable}`,
    `threats    ${threats || "none"}`,
    "",
  ];

  if (report.findings.length === 0) {
    lines.push("status     clean");
    return lines.join("\n");
  }

  for (const item of report.findings) {
    lines.push(`${item.severity.padEnd(8)} ${item.id}`);
    lines.push(`title      ${item.title}`);
    lines.push(`detail     ${item.description}`);
    lines.push(`context    threat=${item.threat} intent=${item.intent}`);
    lines.push(`evidence   ${JSON.stringify(item.evidence)}`);
    lines.push(`autofix    ${item.canAutoFix ? "available" : "manual"}`);
    lines.push(`fix        ${item.remediation}`);
    lines.push(`next       ${item.nextStep}`);
    lines.push("");
  }

  if (report.nextSteps?.length) {
    lines.push("action_plan");
    for (const step of report.nextSteps) {
      lines.push(`- ${step}`);
    }
  }

  return lines.join("\n");
}

export function formatSkillScanReport(report) {
  const lines = [
    "Clawkeeper-Watcher Skill Scan",
    `skill_dir   ${report.skillDir}`,
    `score       ${report.score}/100`,
    `summary     critical=${report.summary.critical} high=${report.summary.high} medium=${report.summary.medium} low=${report.summary.low}`,
    "",
  ];

  if (report.findings.length === 0) {
    lines.push("status      clean");
    return lines.join("\n");
  }

  for (const item of report.findings) {
    lines.push(`${item.severity.padEnd(8)} ${item.id}`);
    lines.push(`file        ${item.file}`);
    lines.push(`title       ${item.title}`);
    lines.push(`evidence    ${JSON.stringify(item.evidence)}`);
    lines.push(`autofix     ${item.canAutoFix ? "available" : "manual"}`);
    lines.push(`fix         ${item.remediation}`);
    lines.push(`next        ${item.nextStep}`);
    lines.push("");
  }

  if (report.nextSteps?.length) {
    lines.push("action_plan");
    for (const step of report.nextSteps) {
      lines.push(`- ${step}`);
    }
  }

  return lines.join("\n");
}
