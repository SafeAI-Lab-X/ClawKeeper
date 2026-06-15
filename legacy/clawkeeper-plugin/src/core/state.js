import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { DEFAULT_RULES, RULE_BLOCK_END, RULE_BLOCK_START } from './metadata.js';

export async function resolveStateDir() {
  const candidates = [
    process.env.OPENCLAW_HOME,
    path.join(os.homedir(), '.openclaw'),
    path.join(os.homedir(), '.moltbot'),
    path.join(os.homedir(), '.clawdbot'),
    path.join(os.homedir(), 'clawd')
  ].filter(Boolean);

  for (const candidate of candidates) {
    try {
      await fs.access(candidate);
      return candidate;
    } catch {
      // continue
    }
  }

  return candidates[1];
}

export function getConfigPath(stateDir) {
  for (const name of ['openclaw.json', 'moltbot.json', 'clawdbot.json']) {
    const fullPath = path.join(stateDir, name);
    if (fsSyncExists(fullPath)) return fullPath;
  }
  return path.join(stateDir, 'openclaw.json');
}

export function getSkillInstallPath(stateDir) {
  return path.join(stateDir, 'skills', 'clawkeeper');
}

export async function readJsonIfExists(filePath) {
  try {
    const raw = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

export async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

export async function writeJson(filePath, value) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf-8');
}

export function getSoulPath(stateDir) {
  return path.join(stateDir, 'AGENTS.md');
}

export async function readSoul(stateDir) {
  try {
    return await fs.readFile(getSoulPath(stateDir), 'utf-8');
  } catch {
    return '';
  }
}

export function buildRuleBlock() {
  const lines = [
    RULE_BLOCK_START,
    '## Clawkeeper Operational Constitution',
    'This is not a set of static prohibitions, but an execution constraint chain: first confirm the boundary, then obtain information, and then implement the action.',
    ...DEFAULT_RULES.map((rule, index) => `${index + 1}. ${rule}`),
    RULE_BLOCK_END
  ];
  return `${lines.join(os.EOL)}${os.EOL}`;
}

export function hasRuleBlock(content) {
  return content.includes(RULE_BLOCK_START) && content.includes(RULE_BLOCK_END);
}

export async function ensureRuleBlock(stateDir) {
  const soulPath = getSoulPath(stateDir);
  const content = await readSoul(stateDir);
  if (hasRuleBlock(content)) {
    return { changed: false, path: soulPath };
  }

  const nextContent = content.trim().length > 0
    ? `${content.replace(/\s*$/, '')}${os.EOL}${os.EOL}${buildRuleBlock()}`
    : `# AGENTS${os.EOL}${os.EOL}${buildRuleBlock()}`;

  await fs.mkdir(path.dirname(soulPath), { recursive: true });
  await fs.writeFile(soulPath, nextContent, 'utf-8');
  return { changed: true, path: soulPath };
}

function fsSyncExists(filePath) {
  try {
    return !!filePath && fsSync.existsSync(filePath);
  } catch {
    return false;
  }
}
