/**
 * Clawkeeper Budget Guard (v1.1 feature: Token Budget Control)
 *
 * Tracks LLM token usage in a rolling window and short-circuits the
 * agent when configured limits are exceeded. Two enforcement points:
 *
 *   1. before_agent_reply hook (primary) — returns a synthetic reply
 *      that halts the LLM call entirely for the next turn.
 *   2. before_tool_call hook (fallback)  — refuses any tool execution
 *      while the budget is exhausted, in case a code path skips
 *      before_agent_reply (sub-agents, retries, etc.).
 *
 * Accounting happens in llm_output hook, where event.usage carries the
 * input/output token counts reported by the provider.
 *
 * State file: $OPENCLAW_WORKSPACE/clawkeeper/budget.json
 *
 * Design notes:
 *  - Synchronous fs reads/writes. Concurrency is single-process here,
 *    so no locking — we use atomic rename for write safety.
 *  - Rolling window: when now > windowStart + windowDays the counters
 *    reset and windowStart advances.
 *  - Limits: any of input/output/total tripping the cap counts as over.
 *  - Failure mode: if the state file is unreadable we treat budget as
 *    "ok" so a corrupt config doesn't wedge the agent. Operators can
 *    delete the file to force a fresh start.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_RULES_PATH = path.join(__dirname, '..', 'config', 'core-rules.json');

let cachedConfig = null;

function loadConfig(rulesPath = DEFAULT_RULES_PATH) {
  if (cachedConfig && cachedConfig._source === rulesPath) return cachedConfig;
  let cfg = {};
  try {
    const raw = JSON.parse(fs.readFileSync(rulesPath, 'utf-8'));
    cfg = raw.budgetGuard || {};
  } catch {
    cfg = {};
  }
  cachedConfig = {
    enabled: cfg.enabled !== false,
    windowDays: typeof cfg.windowDays === 'number' ? cfg.windowDays : 1,
    limits: {
      input: cfg.limits?.input ?? 1000000,
      output: cfg.limits?.output ?? 200000,
      total: cfg.limits?.total ?? 1200000,
    },
    warnRatio: typeof cfg.warnRatio === 'number' ? cfg.warnRatio : 0.8,
    stateFile: cfg.stateFile || null,
    _source: rulesPath,
  };
  return cachedConfig;
}

/** Force cache invalidation (primarily for tests). */
export function resetBudgetCache() { cachedConfig = null; }

/** Resolve the budget state file path; defaults to workspace/clawkeeper/budget.json. */
export function resolveBudgetFile(cfg = loadConfig()) {
  if (cfg.stateFile) {
    return cfg.stateFile.replace(/^~(?=$|[\\/])/, os.homedir());
  }
  const ws = process.env.OPENCLAW_WORKSPACE || path.join(os.homedir(), '.openclaw', 'workspace');
  return path.join(ws, 'clawkeeper', 'budget.json');
}

/** Build a fresh budget record. */
function freshBudget(cfg) {
  return {
    windowStart: new Date().toISOString(),
    windowDays: cfg.windowDays,
    limits: { ...cfg.limits },
    thresholds: { warn: cfg.warnRatio },
    usage: { input: 0, output: 0, total: 0, calls: 0 },
    lastDecision: 'ok',
  };
}

/** Read the persisted budget; create a fresh one on miss/corrupt. */
export function loadBudget(filePath) {
  const cfg = loadConfig();
  const f = filePath || resolveBudgetFile(cfg);
  try {
    const raw = JSON.parse(fs.readFileSync(f, 'utf-8'));
    if (!raw || typeof raw !== 'object') return freshBudget(cfg);
    raw.limits = raw.limits || { ...cfg.limits };
    raw.usage = raw.usage || { input: 0, output: 0, total: 0, calls: 0 };
    raw.thresholds = raw.thresholds || { warn: cfg.warnRatio };
    return raw;
  } catch {
    return freshBudget(cfg);
  }
}

/** Atomically persist a budget record. */
export function saveBudget(budget, filePath) {
  const cfg = loadConfig();
  const f = filePath || resolveBudgetFile(cfg);
  try {
    fs.mkdirSync(path.dirname(f), { recursive: true });
    const tmp = f + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(budget, null, 2));
    fs.renameSync(tmp, f);
    return true;
  } catch (err) {
    console.error('[Clawkeeper] budget-guard save failed:', err.message);
    return false;
  }
}

/** Reset the window if its start + windowDays has elapsed. */
function rollWindowIfNeeded(budget) {
  const start = Date.parse(budget.windowStart);
  if (!Number.isFinite(start)) return budget;
  const days = typeof budget.windowDays === 'number' ? budget.windowDays : 1;
  const expiresAt = start + days * 24 * 60 * 60 * 1000;
  if (Date.now() >= expiresAt) {
    budget.windowStart = new Date().toISOString();
    budget.usage = { input: 0, output: 0, total: 0, calls: 0 };
    budget.lastDecision = 'ok';
  }
  return budget;
}

/** Compare current usage against limits. */
function classify(budget) {
  const { usage, limits, thresholds } = budget;
  const warn = thresholds?.warn ?? 0.8;
  const ratios = {
    input: limits.input ? usage.input / limits.input : 0,
    output: limits.output ? usage.output / limits.output : 0,
    total: limits.total ? usage.total / limits.total : 0,
  };
  if (ratios.input >= 1 || ratios.output >= 1 || ratios.total >= 1) return { status: 'over', ratios };
  if (ratios.input >= warn || ratios.output >= warn || ratios.total >= warn) return { status: 'warn', ratios };
  return { status: 'ok', ratios };
}

/**
 * Pure check, no mutation. Used by before_agent_reply / before_tool_call
 * to decide whether the next LLM call (or tool execution) should proceed.
 */
export function checkBudget(filePath) {
  const cfg = loadConfig();
  if (!cfg.enabled) return { block: false, status: 'disabled' };
  const budget = rollWindowIfNeeded(loadBudget(filePath));
  const c = classify(budget);
  return {
    block: c.status === 'over',
    status: c.status,
    ratios: c.ratios,
    usage: budget.usage,
    limits: budget.limits,
  };
}

/**
 * Accumulate usage from an llm_output event and persist.
 * @param {{input?: number, output?: number}} usage
 */
export function recordUsage(usage = {}, filePath) {
  const cfg = loadConfig();
  if (!cfg.enabled) return { status: 'disabled' };
  const budget = rollWindowIfNeeded(loadBudget(filePath));
  const inTokens = Number(usage.input) || 0;
  const outTokens = Number(usage.output) || 0;
  budget.usage.input += inTokens;
  budget.usage.output += outTokens;
  budget.usage.total += inTokens + outTokens;
  budget.usage.calls += 1;
  const c = classify(budget);
  budget.lastDecision = c.status;
  saveBudget(budget, filePath);
  return {
    status: c.status,
    ratios: c.ratios,
    usage: budget.usage,
    limits: budget.limits,
    delta: { input: inTokens, output: outTokens },
  };
}

/** Format a one-line human-readable summary for log/reply messages. */
export function formatBudgetSummary(state) {
  const u = state.usage || {};
  const l = state.limits || {};
  return `input=${u.input}/${l.input} output=${u.output}/${l.output} total=${u.total}/${l.total} calls=${u.calls ?? '?'}`;
}
