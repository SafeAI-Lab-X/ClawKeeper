/**
 * Clawkeeper Permission Store (v1.1 feature 2: persistent allow/deny)
 *
 * Plugin-only persistence layer for user authorization decisions on
 * tool calls. Two state files:
 *
 *   $WS/clawkeeper/permissions-session.json   — wiped on plugin start
 *   $WS/clawkeeper/permissions-forever.json   — survives across runs
 *
 * Decisions are keyed by (toolName, fingerprint), where fingerprint is
 * a sha256 of the normalized command/path. A check returns one of:
 *
 *   { decision: 'allow' }   → bypass all downstream gates
 *   { decision: 'deny'  }   → block immediately
 *   { decision: 'none'  }   → fall through to regular rule chain
 *
 * Forever entries take precedence over session entries; an explicit
 * deny always wins over an allow at the same scope.
 *
 * Interaction model: there is no in-process prompt — operators write
 * decisions out-of-band via `openclaw clawkeeper permission allow|deny`,
 * which is enough to validate the persistence path end-to-end.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

const BASH_LIKE_TOOLS = new Set([
  'bash', 'shell', 'exec', 'command', 'run_command', 'execute_command', 'terminal',
]);
const PATH_LIKE_TOOLS = new Set([
  'read_file', 'read', 'fs_read', 'file_read',
  'write_file', 'write', 'fs_write', 'file_write',
]);

function workspaceDir() {
  return process.env.OPENCLAW_WORKSPACE || path.join(os.homedir(), '.openclaw', 'workspace');
}

export function resolveSessionFile() {
  return path.join(workspaceDir(), 'clawkeeper', 'permissions-session.json');
}

export function resolveForeverFile() {
  return path.join(workspaceDir(), 'clawkeeper', 'permissions-forever.json');
}

function freshStore() {
  return { entries: [] };
}

function readStore(filePath) {
  try {
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    if (!raw || typeof raw !== 'object' || !Array.isArray(raw.entries)) return freshStore();
    return raw;
  } catch {
    return freshStore();
  }
}

function writeStore(filePath, store) {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const tmp = filePath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(store, null, 2));
    fs.renameSync(tmp, filePath);
    return true;
  } catch (err) {
    console.error('[Clawkeeper] permission-store save failed:', err.message);
    return false;
  }
}

/**
 * Build a stable fingerprint for a (tool, params) pair. Bash-like tools
 * key on the trimmed command string; path-like tools key on the resolved
 * path. Anything else falls back to a JSON dump of params.
 */
export function fingerprintFor(toolName, params = {}) {
  const t = String(toolName || '').toLowerCase();
  let material;
  if (BASH_LIKE_TOOLS.has(t)) {
    const cmd = params.command || params.cmd || params.script || '';
    material = `cmd:${String(cmd).trim()}`;
  } else if (PATH_LIKE_TOOLS.has(t)) {
    const p = params.path || params.file || params.filename || '';
    material = `path:${String(p).trim()}`;
  } else {
    try { material = `json:${JSON.stringify(params)}`; }
    catch { material = `json:unserializable`; }
  }
  return crypto.createHash('sha256').update(material).digest('hex').slice(0, 32);
}

/**
 * Look up an entry. Forever > session; deny > allow within same scope.
 */
export function checkPermission(toolName, params) {
  const fp = fingerprintFor(toolName, params);
  const tool = String(toolName || '').toLowerCase();

  for (const file of [resolveForeverFile(), resolveSessionFile()]) {
    const store = readStore(file);
    const matches = store.entries.filter((e) => e.tool === tool && e.fingerprint === fp);
    if (matches.length === 0) continue;
    // deny wins within same scope
    const denied = matches.find((e) => e.decision === 'deny');
    if (denied) {
      return { decision: 'deny', scope: file === resolveForeverFile() ? 'forever' : 'session', entry: denied, fingerprint: fp };
    }
    const allowed = matches.find((e) => e.decision === 'allow');
    if (allowed) {
      return { decision: 'allow', scope: file === resolveForeverFile() ? 'forever' : 'session', entry: allowed, fingerprint: fp };
    }
  }
  return { decision: 'none', fingerprint: fp };
}

/**
 * Insert or update an entry. Removes any prior record with the same
 * (tool, fingerprint) at the same scope before inserting, so toggling
 * allow ↔ deny is idempotent.
 */
export function grantPermission({ tool, params, decision, scope, reason }) {
  if (!['allow', 'deny'].includes(decision)) {
    throw new Error(`invalid decision: ${decision}`);
  }
  if (!['session', 'forever'].includes(scope)) {
    throw new Error(`invalid scope: ${scope}`);
  }
  const file = scope === 'forever' ? resolveForeverFile() : resolveSessionFile();
  const store = readStore(file);
  const fp = fingerprintFor(tool, params);
  const t = String(tool || '').toLowerCase();
  store.entries = store.entries.filter((e) => !(e.tool === t && e.fingerprint === fp));
  store.entries.push({
    tool: t,
    fingerprint: fp,
    decision,
    scope,
    reason: reason || null,
    created_at: new Date().toISOString(),
    sample: sampleOf(tool, params),
  });
  writeStore(file, store);
  return { fingerprint: fp, scope };
}

function sampleOf(toolName, params = {}) {
  const t = String(toolName || '').toLowerCase();
  if (BASH_LIKE_TOOLS.has(t)) return String(params.command || params.cmd || '').slice(0, 200);
  if (PATH_LIKE_TOOLS.has(t)) return String(params.path || params.file || '').slice(0, 200);
  try { return JSON.stringify(params).slice(0, 200); } catch { return ''; }
}

export function revokePermission({ tool, fingerprint, scope }) {
  const file = scope === 'forever' ? resolveForeverFile() : resolveSessionFile();
  const store = readStore(file);
  const t = String(tool || '').toLowerCase();
  const before = store.entries.length;
  store.entries = store.entries.filter((e) => !(e.tool === t && e.fingerprint === fingerprint));
  writeStore(file, store);
  return { removed: before - store.entries.length };
}

export function listPermissions(scope = null) {
  const out = [];
  const targets = scope === 'forever' ? ['forever']
                : scope === 'session' ? ['session']
                : ['forever', 'session'];
  for (const s of targets) {
    const file = s === 'forever' ? resolveForeverFile() : resolveSessionFile();
    const store = readStore(file);
    for (const e of store.entries) out.push({ ...e, scope: s });
  }
  return out;
}

/** Wipe the session-level store. Called on plugin startup. */
export function resetSessionPermissions() {
  try {
    writeStore(resolveSessionFile(), freshStore());
    return true;
  } catch {
    return false;
  }
}

/** Wipe the forever store (testing/admin only). */
export function resetForeverPermissions() {
  try {
    writeStore(resolveForeverFile(), freshStore());
    return true;
  } catch {
    return false;
  }
}
