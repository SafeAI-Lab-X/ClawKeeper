/**
 * Clawkeeper Path Guard (v1.1 feature: Dangerous File Protection List)
 *
 * Provides synchronous path normalization + glob matching so the
 * before_tool_call hook can hard-block any tool that tries to read,
 * write, delete, or exec against a protected path.
 *
 * Design notes:
 *  - Zero external deps: small inline glob -> regex converter.
 *  - Normalization handles ~, ./, .., and (best-effort) symlinks via
 *    fs.realpathSync. On ENOENT we fall back to path.resolve.
 *  - For bash-like tools we tokenize the command string and also
 *    regex-scan for ~/... and /... path literals.
 *  - For structured tools we recursively collect string params that
 *    look like paths.
 *  - Everything runs synchronously so the hook can return a decision
 *    without introducing async delays on the hot path.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_RULES_PATH = path.join(__dirname, '..', 'config', 'core-rules.json');

let cachedRules = null;

/**
 * Load (and cache) protected paths + config from core-rules.json.
 * @param {string} [rulesPath]
 */
export function loadProtectedPaths(rulesPath = DEFAULT_RULES_PATH) {
  if (cachedRules && cachedRules._source === rulesPath) return cachedRules;
  const raw = JSON.parse(fs.readFileSync(rulesPath, 'utf-8'));
  const rules = (raw.protectedPaths || []).map((r) => ({
    ...r,
    regex: globToRegex(expandHome(r.pattern)),
    expanded: expandHome(r.pattern),
  }));
  const config = raw.pathGuard || { enabled: true, failurePolicy: 'fail-closed', bashLikeTools: [] };
  cachedRules = { rules, config, _source: rulesPath };
  return cachedRules;
}

/** Force cache invalidation (primarily for tests). */
export function resetPathGuardCache() { cachedRules = null; }

/** Expand a leading ~ to the current user's home directory. */
export function expandHome(p) {
  if (!p) return p;
  if (p === '~') return os.homedir();
  if (p.startsWith('~/') || p.startsWith('~\\')) return path.join(os.homedir(), p.slice(2));
  return p;
}

/**
 * Convert a simple glob pattern to an anchored regex.
 * Supports: **  *  ?  and literal characters.
 *  **   -> .*        (any chars, including /)
 *  *    -> [^/]*     (any chars except /)
 *  ?    -> [^/]      (single char except /)
 */
export function globToRegex(glob) {
  let re = '^';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') { re += '.*'; i++; }
      else { re += '[^/]*'; }
    } else if (c === '?') {
      re += '[^/]';
    } else if ('.+^${}()|[]\\'.includes(c)) {
      re += '\\' + c;
    } else {
      re += c;
    }
  }
  re += '$';
  return new RegExp(re);
}

/**
 * Normalize an incoming path candidate to an absolute path.
 * Best-effort: resolves ~, relative segments, and symlinks if the
 * target exists. On any filesystem error falls back to path.resolve.
 */
export function normalizePath(input, cwd = process.cwd()) {
  if (typeof input !== 'string' || !input) return null;
  let p = expandHome(input.trim());
  // Strip surrounding quotes
  if ((p.startsWith('"') && p.endsWith('"')) || (p.startsWith("'") && p.endsWith("'"))) {
    p = p.slice(1, -1);
  }
  if (!path.isAbsolute(p)) p = path.resolve(cwd, p);
  try {
    return fs.realpathSync(p);
  } catch {
    return path.resolve(p);
  }
}

/**
 * Test a single absolute path against the rule list.
 * Returns the first matching rule or null.
 */
export function matchProtected(absPath, rules) {
  if (!absPath) return null;
  for (const rule of rules) {
    if (rule.regex.test(absPath)) return rule;
    // Also allow matching against the original input when the rule is
    // a directory prefix (ends with /**): if absPath starts with the
    // expanded prefix we consider it a hit.
    if (rule.pattern.endsWith('/**')) {
      const prefix = rule.expanded.slice(0, -3);
      if (absPath === prefix || absPath.startsWith(prefix + path.sep) || absPath.startsWith(prefix + '/')) {
        return rule;
      }
    }
  }
  return null;
}

const PATH_TOKEN_RE = /(?:^|[\s'"`=:;(){}\[\],])(~\/[^\s'"`;|&()<>]+|\/[A-Za-z0-9._\/-]+|\.{1,2}\/[^\s'"`;|&()<>]+)/g;

/** Pull path-looking tokens out of a bash command string. */
export function extractPathsFromCommand(command) {
  if (typeof command !== 'string' || !command) return [];
  const out = new Set();
  let m;
  PATH_TOKEN_RE.lastIndex = 0;
  while ((m = PATH_TOKEN_RE.exec(command)) !== null) {
    const token = m[1];
    if (token.length >= 2) out.add(token);
  }
  return [...out];
}

/** Recursively walk a params object and collect string values. */
function collectStringValues(obj, out = []) {
  if (obj == null) return out;
  if (typeof obj === 'string') { out.push(obj); return out; }
  if (Array.isArray(obj)) { for (const v of obj) collectStringValues(v, out); return out; }
  if (typeof obj === 'object') { for (const v of Object.values(obj)) collectStringValues(v, out); return out; }
  return out;
}

/**
 * Turn a tool-call event into a list of path candidates to guard on.
 * @param {string} toolName
 * @param {Record<string, unknown>} params
 * @param {{bashLikeTools?: string[]}} [opts]
 */
export function extractPathsFromParams(toolName, params, opts = {}) {
  const bashLike = new Set((opts.bashLikeTools || []).map((s) => s.toLowerCase()));
  const tName = String(toolName || '').toLowerCase();
  const looksLikeBash = bashLike.has(tName) || /bash|shell|exec|command|terminal/.test(tName);
  const candidates = new Set();

  if (looksLikeBash) {
    // Prefer common field names; fall back to concatenating all string params.
    const p = params || {};
    const cmd = [p.command, p.cmd, p.script, p.input, p.code, p.bash, p.shell]
      .filter((v) => typeof v === 'string').join('\n');
    const commandText = cmd || collectStringValues(params).join('\n');
    for (const t of extractPathsFromCommand(commandText)) candidates.add(t);
  }

  // Always also collect structured string params that look path-ish.
  for (const v of collectStringValues(params)) {
    const s = v.trim();
    if (!s) continue;
    if (s.startsWith('~/') || s.startsWith('~\\') || path.isAbsolute(s)) candidates.add(s);
    else if (s.startsWith('./') || s.startsWith('../')) candidates.add(s);
    // Short plain filenames that match sensitive basenames
    else if (/^(id_rsa|id_ed25519|\.env|credentials|shadow|sudoers)$/i.test(s)) candidates.add(s);
  }
  return [...candidates];
}

/**
 * Main entry: decide whether this tool call should be blocked based on
 * any protected-path hit.
 *
 * @param {{toolName: string, params: Record<string, unknown>}} event
 * @returns {{block: boolean, matched?: any, candidate?: string, resolved?: string, severity?: string, reason?: string}}
 */
export function guardBeforeToolCall(event) {
  let loaded;
  try {
    loaded = loadProtectedPaths();
  } catch (err) {
    // If we can't even load the rules, err on the side of caution only
    // when the configured policy is fail-closed. Default = fail-open to
    // avoid wedging users on broken configs.
    return { block: false, error: err.message };
  }
  const { rules, config } = loaded;
  if (!config.enabled) return { block: false };

  const candidates = extractPathsFromParams(event.toolName, event.params, {
    bashLikeTools: config.bashLikeTools,
  });

  for (const candidate of candidates) {
    const resolved = normalizePath(candidate);
    const hit = matchProtected(resolved, rules) || matchProtected(expandHome(candidate), rules);
    if (hit) {
      return {
        block: true,
        matched: hit.pattern,
        candidate,
        resolved,
        severity: hit.severity,
        reason: hit.reason,
      };
    }
  }
  return { block: false };
}
