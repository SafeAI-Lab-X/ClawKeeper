import fs from "node:fs/promises";
import path from "node:path";
import { resolveStateDir, resolveUserOpenClawStateDir } from "./state.js";

export async function scanSkill(input, options = {}) {
  const skillRoots = await resolveSkillRoots(options);
  const skillDir = await resolveSkillDir(input, skillRoots);
  const rules = await loadRules(options.rulesPath);
  const files = await collectFiles(skillDir);
  const findings = [];
  const skillName = path.basename(skillDir);

  findings.push(...evaluateSkillName(skillName, rules));

  for (const file of files) {
    const relativePath = path.relative(skillDir, file);
    const content = await fs.readFile(file, "utf-8");
    const target = classifyTarget(relativePath);

    for (const pattern of rules.skillRiskPatterns ?? []) {
      if (pattern.target !== target) {
        continue;
      }
      if (!matches(content, pattern)) {
        continue;
      }

      findings.push({
        id: pattern.id,
        severity: pattern.severity,
        title: pattern.title,
        file: relativePath,
        evidence: extractEvidence(content, pattern),
        remediation: pattern.remediation,
        canAutoFix: false,
        nextStep: `Check implementation related to ${pattern.id} in ${relativePath}, then re-run scan after applying "${pattern.remediation}".`,
      });
    }

    if (relativePath.toLowerCase() === "readme.md") {
      findings.push(...scanPrerequisites(content, relativePath, rules));
    }
  }

  const missingFiles = await checkRequiredFiles(skillDir);
  for (const missing of missingFiles) {
    findings.push(missing);
  }

  return {
    skillDir,
    skillName,
    score: calculateSkillScore(findings),
    summary: summarizeFindings(findings),
    findings,
    nextSteps: buildNextSteps(findings),
  };
}

async function resolveSkillRoots(options) {
  if (typeof options.stateDir === "string" && options.stateDir.trim()) {
    return [path.resolve(options.stateDir)];
  }

  const [stateDir, userStateDir] = await Promise.all([
    resolveStateDir(),
    resolveUserOpenClawStateDir(),
  ]);

  return [...new Set([userStateDir, stateDir].filter(Boolean))];
}

async function resolveSkillDir(input, skillRoots) {
  if (!input) {
    throw new Error("Skill path or name is required");
  }

  if (path.isAbsolute(input) || input.includes("/") || input.startsWith(".")) {
    return path.resolve(input);
  }

  for (const stateDir of skillRoots) {
    const candidate = path.join(stateDir, "skills", input);
    try {
      await fs.access(candidate);
      return candidate;
    } catch {
      // try next root
    }
  }

  return path.join(skillRoots[0], "skills", input);
}

async function loadRules(customRulesPath) {
  const rulesPath = customRulesPath
    ? path.resolve(customRulesPath)
    : path.join(
        path.dirname(new URL(import.meta.url).pathname),
        "..",
        "..",
        "skill",
        "configs",
        "core-rules.json",
      );
  return JSON.parse(await fs.readFile(rulesPath, "utf-8"));
}

async function collectFiles(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await collectFiles(fullPath)));
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }

  return files;
}

function classifyTarget(relativePath) {
  if (relativePath.endsWith(".sh") || relativePath.endsWith(".bash")) {
    return "script";
  }
  if (relativePath === "SKILL.md" || relativePath.endsWith(".md")) {
    return "skill";
  }
  return "other";
}

function matches(content, pattern) {
  if (pattern.mode === "substring") {
    return content.toLowerCase().includes(String(pattern.pattern).toLowerCase());
  }

  const regex = new RegExp(pattern.pattern, "i");
  return regex.test(content);
}

function extractEvidence(content, pattern) {
  if (pattern.mode === "substring") {
    return { pattern: pattern.pattern };
  }

  const regex = new RegExp(pattern.pattern, "i");
  const match = content.match(regex);
  return { pattern: pattern.pattern, match: match?.[0] ?? null };
}

function evaluateSkillName(skillName, rules) {
  const normalized = skillName.toLowerCase();
  const findings = [];
  const nameParts = new Set(normalized.split(/[^a-z0-9]+/).filter(Boolean));

  if (/(clawh|skilkeeper|openclaww|officia1)/i.test(normalized)) {
    findings.push({
      id: "name.typosquat-signal",
      severity: "HIGH",
      title: "Skill name shows typosquatting signal",
      file: "(name)",
      evidence: { skillName },
      remediation:
        "Verify publisher, repository source, and installation source. Avoid installing skills with similar naming.",
      canAutoFix: false,
      nextStep: `Confirm that ${skillName} is the expected skill. If the source is unclear, do not install it yet.`,
    });
  }

  if ((rules.suspiciousSkillNames ?? []).some((token) => nameParts.has(token))) {
    findings.push({
      id: "name.high-lure-theme",
      severity: "LOW",
      title: "Skill name uses high-lure theme keywords",
      file: "(name)",
      evidence: {
        skillName,
        matchedTheme: (rules.suspiciousSkillNames ?? []).find((token) => nameParts.has(token)),
      },
      remediation:
        "Increase source verification for skills containing keywords like updater, wallet, installer.",
      canAutoFix: false,
      nextStep: `Supplement the source and purpose description for ${skillName}, then decide whether to continue installation.`,
    });
  }

  return findings;
}

function scanPrerequisites(content, relativePath, rules) {
  const findings = [];
  const lower = content.toLowerCase();

  for (const phrase of rules.dangerousPrerequisitePatterns ?? []) {
    if (!lower.includes(String(phrase).toLowerCase())) {
      continue;
    }
    findings.push({
      id: "docs.dangerous-prerequisite",
      severity: "MEDIUM",
      title: "README requires dangerous prerequisite operation",
      file: relativePath,
      evidence: { phrase },
      remediation:
        "Change prerequisite steps to minimal privilege installation flow without requiring system protection to be disabled.",
      canAutoFix: false,
      nextStep: `Check installation prerequisites in ${relativePath}, remove steps like "${phrase}" and re-run the scan.`,
    });
  }

  return findings;
}

async function checkRequiredFiles(skillDir) {
  const findings = [];
  const required = [
    {
      file: "SKILL.md",
      severity: "MEDIUM",
      title: "Missing skill main rules file",
      remediation: "Add SKILL.md with clear execution boundaries.",
    },
    {
      file: "skill.json",
      severity: "LOW",
      title: "Missing skill metadata file",
      remediation: "Add skill.json with name, version, and entry point.",
    },
  ];

  for (const item of required) {
    try {
      await fs.access(path.join(skillDir, item.file));
    } catch {
      findings.push({
        id: `structure.missing-${item.file.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
        severity: item.severity,
        title: item.title,
        file: item.file,
        evidence: { exists: false },
        remediation: item.remediation,
        canAutoFix: false,
        nextStep: `Complete ${item.file} first, then re-run the scan.`,
      });
    }
  }

  return findings;
}

function calculateSkillScore(findings) {
  const weights = { CRITICAL: 25, HIGH: 12, MEDIUM: 6, LOW: 2 };
  const deducted = findings.reduce((sum, item) => sum + (weights[item.severity] ?? 0), 0);
  return Math.max(0, 100 - deducted);
}

function summarizeFindings(findings) {
  return findings.reduce(
    (summary, item) => {
      summary[item.severity.toLowerCase()] += 1;
      return summary;
    },
    { critical: 0, high: 0, medium: 0, low: 0 },
  );
}

function buildNextSteps(findings) {
  if (findings.length === 0) {
    return [
      "No known dangerous patterns detected. You can proceed with manual review of critical side-effect scripts.",
    ];
  }

  const highRisk = findings.filter(
    (item) => item.severity === "CRITICAL" || item.severity === "HIGH",
  );
  const steps = [];
  if (highRisk.length > 0) {
    steps.push(
      `Address high-risk items first: ${highRisk.map((item) => `${item.id}@${item.file}`).join(", ")}.`,
    );
  }
  steps.push("Re-run `npx openclaw clawkeeper-watcher scan-skill <name-or-path>` after fixes.");
  return steps;
}
