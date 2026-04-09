import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// Isolate state by pointing OPENCLAW_WORKSPACE at a per-run tmp dir
// before importing the module under test.
const TMP_WS = fs.mkdtempSync(path.join(os.tmpdir(), 'clawkeeper-perm-'));
process.env.OPENCLAW_WORKSPACE = TMP_WS;

const {
  fingerprintFor,
  checkPermission,
  grantPermission,
  revokePermission,
  listPermissions,
  resetSessionPermissions,
  resetForeverPermissions,
  resolveSessionFile,
  resolveForeverFile,
} = await import('../src/core/permission-store.js');

function clean() {
  resetSessionPermissions();
  resetForeverPermissions();
}

test('fingerprint is stable for same bash command', () => {
  const a = fingerprintFor('exec', { command: 'echo hi' });
  const b = fingerprintFor('exec', { command: 'echo hi' });
  assert.equal(a, b);
  const c = fingerprintFor('exec', { command: 'echo bye' });
  assert.notEqual(a, c);
});

test('fingerprint normalizes across bash-like tool aliases', () => {
  const a = fingerprintFor('exec', { command: 'ls /tmp' });
  const b = fingerprintFor('bash', { command: 'ls /tmp' });
  assert.equal(a, b);
});

test('checkPermission returns none when stores are empty', () => {
  clean();
  const r = checkPermission('exec', { command: 'pwd' });
  assert.equal(r.decision, 'none');
});

test('forever-scope allow is observed by checkPermission', () => {
  clean();
  grantPermission({ tool: 'exec', params: { command: 'echo clawkeeper-permission-test' }, decision: 'allow', scope: 'forever' });
  const r = checkPermission('exec', { command: 'echo clawkeeper-permission-test' });
  assert.equal(r.decision, 'allow');
  assert.equal(r.scope, 'forever');
});

test('session-scope deny blocks within session', () => {
  clean();
  grantPermission({ tool: 'exec', params: { command: 'rm -rf ./build' }, decision: 'deny', scope: 'session' });
  const r = checkPermission('exec', { command: 'rm -rf ./build' });
  assert.equal(r.decision, 'deny');
  assert.equal(r.scope, 'session');
});

test('forever entry takes precedence over session entry', () => {
  clean();
  grantPermission({ tool: 'exec', params: { command: 'whoami' }, decision: 'deny', scope: 'session' });
  grantPermission({ tool: 'exec', params: { command: 'whoami' }, decision: 'allow', scope: 'forever' });
  const r = checkPermission('exec', { command: 'whoami' });
  assert.equal(r.decision, 'allow');
  assert.equal(r.scope, 'forever');
});

test('resetSessionPermissions wipes session entries but keeps forever ones', () => {
  clean();
  grantPermission({ tool: 'exec', params: { command: 'a' }, decision: 'allow', scope: 'session' });
  grantPermission({ tool: 'exec', params: { command: 'b' }, decision: 'allow', scope: 'forever' });
  resetSessionPermissions();
  assert.equal(checkPermission('exec', { command: 'a' }).decision, 'none');
  assert.equal(checkPermission('exec', { command: 'b' }).decision, 'allow');
});

test('grant is idempotent — second grant replaces first', () => {
  clean();
  grantPermission({ tool: 'exec', params: { command: 'date' }, decision: 'deny', scope: 'forever' });
  grantPermission({ tool: 'exec', params: { command: 'date' }, decision: 'allow', scope: 'forever' });
  const entries = listPermissions('forever').filter((e) => e.tool === 'exec');
  assert.equal(entries.length, 1);
  assert.equal(entries[0].decision, 'allow');
});

test('revokePermission removes the matching entry', () => {
  clean();
  grantPermission({ tool: 'exec', params: { command: 'uptime' }, decision: 'allow', scope: 'forever' });
  const fp = fingerprintFor('exec', { command: 'uptime' });
  const r = revokePermission({ tool: 'exec', fingerprint: fp, scope: 'forever' });
  assert.equal(r.removed, 1);
  assert.equal(checkPermission('exec', { command: 'uptime' }).decision, 'none');
});

test('state files are created under OPENCLAW_WORKSPACE', () => {
  clean();
  grantPermission({ tool: 'exec', params: { command: 'x' }, decision: 'allow', scope: 'forever' });
  assert.ok(fs.existsSync(resolveForeverFile()));
  assert.ok(resolveForeverFile().startsWith(TMP_WS));
  assert.ok(resolveSessionFile().startsWith(TMP_WS));
});
