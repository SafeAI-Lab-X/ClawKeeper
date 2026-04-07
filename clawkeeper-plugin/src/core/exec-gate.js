/**
 * Clawkeeper Execution Gate (v1.1 feature: Pre-execution Block Gate)
 *
 * Synchronous regex-based dangerous command detector for bash-like
 * tool calls. Runs after the path-guard inside the before_tool_call
 * hook so the interceptor can hard-block clearly destructive shell
 * invocations before the agent gets to execute them.
 *
 * Design notes:
 *  - Zero external deps. Rules live in core-rules.json under
 *    `executionGate.dangerousCommands` and are compiled to RegExp on
 *    first load, then cached.
 *  - For bash-like tools we collect command text from common field
 *    names (command/cmd/script/input/code/bash/shell). Failing that we
 *    fall back to concatenating every string param so obfuscated tool
 *    schemas still get scanned.
 *  - For non-bash tools we still scan any string params, since some
 *    integrations smuggle shell snippets through generic tool args.
 *  - On rule-load failure we honour `executionGate.failurePolicy`:
 *    `fail-closed` blocks the call, anything else lets it through.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_RULES_PATH = path.join(__dirname, '..', 'config', 'core-rules.json');

let cachedGate = null;
const DEFAULT_FAILURE_POLICY = 'fail-closed';

/**
 * Load (and cache) executionGate rules from core-rules.json.
 * @param {string} [rulesPath]
 */
export function loadExecGate(rulesPath = DEFAULT_RULES_PATH) {
  if (cachedGate && cachedGate._source === rulesPath) return cachedGate;
  const raw = JSON.parse(fs.readFileSync(rulesPath, 'utf-8'));
  const cfg = raw.executionGate || {};
  const rules = (cfg.dangerousCommands || []).map((r) => ({
    ...r,
    regex: new RegExp(r.pattern, 'i'),
  }));
  cachedGate = {
    rules,
    config: {
      enabled: cfg.enabled !== false,
      failurePolicy: cfg.failurePolicy || 'fail-open',
      bashLikeTools: cfg.bashLikeTools || [],
    },
    _source: rulesPath,
  };
  return cachedGate;
}

/** Force cache invalidation (primarily for tests). */
export function resetExecGateCache() { cachedGate = null; }

/** Recursively walk a value and collect all string leaves. */
function collectStringValues(obj, out = []) {
  if (obj == null) return out;
  if (typeof obj === 'string') { out.push(obj); return out; }
  if (Array.isArray(obj)) { for (const v of obj) collectStringValues(v, out); return out; }
  if (typeof obj === 'object') { for (const v of Object.values(obj)) collectStringValues(v, out); return out; }
  return out;
}

/**
 * Pull the most plausible "command text" out of a tool call's params.
 * @param {string} toolName
 * @param {Record<string, unknown>} params
 * @param {string[]} [bashLikeTools]
 * @returns {string}
 */
export function extractCommandText(toolName, params, bashLikeTools = []) {
  const tName = String(toolName || '').toLowerCase();
  const bashLike = new Set(bashLikeTools.map((s) => s.toLowerCase()));
  const looksLikeBash = bashLike.has(tName) || /bash|shell|exec|command|terminal/.test(tName);
  const p = params || {};

  if (looksLikeBash) {
    const named = [p.command, p.cmd, p.script, p.input, p.code, p.bash, p.shell]
      .filter((v) => typeof v === 'string')
      .join('\n');
    if (named) return named;
  }
  return collectStringValues(params).join('\n');
}

/**
 * Main entry: decide whether this tool call should be blocked based
 * on dangerous command patterns.
 *
 * @param {{toolName: string, params: Record<string, unknown>}} event
 * @returns {{block: boolean, matched?: string, severity?: string, reason?: string, command?: string, error?: string}}
 */
export function guardExecution(event) {
  let loaded;
  try {
    loaded = loadExecGate();
  } catch (err) {
    // Honour the last-known failurePolicy (or the module default) so
    // that a corrupted/missing config file cannot silently disable the
    // gate when the operator configured fail-closed.
    const policy = cachedGate?.config?.failurePolicy || DEFAULT_FAILURE_POLICY;
    if (policy === 'fail-closed') {
      return { block: true, error: err.message, reason: 'exec-gate rule load failed (fail-closed policy)' };
    }
    return { block: false, error: err.message };
  }
  const { rules, config } = loaded;
  if (!config.enabled) return { block: false };

  const command = extractCommandText(event.toolName, event.params, config.bashLikeTools);
  if (!command) return { block: false };

  for (const rule of rules) {
    if (rule.regex.test(command)) {
      return {
        block: true,
        matched: rule.id,
        severity: rule.severity,
        reason: rule.reason,
        command: command.length > 500 ? command.slice(0, 500) + '…' : command,
      };
    }
  }
  return { block: false };
}
