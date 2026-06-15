import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import {
  globToRegex,
  expandHome,
  normalizePath,
  extractPathsFromCommand,
  extractPathsFromParams,
  guardBeforeToolCall,
  loadProtectedPaths,
  resetPathGuardCache,
} from '../src/core/path-guard.js';

test('globToRegex: ** matches nested, * does not cross /', () => {
  assert.ok(globToRegex('/a/**').test('/a/b/c'));
  assert.ok(globToRegex('/a/*').test('/a/b'));
  assert.ok(!globToRegex('/a/*').test('/a/b/c'));
  assert.ok(globToRegex('/a/?.txt').test('/a/b.txt'));
});

test('expandHome: ~ -> homedir', () => {
  assert.equal(expandHome('~/.ssh/id_rsa'), path.join(os.homedir(), '.ssh/id_rsa'));
  assert.equal(expandHome('/etc/shadow'), '/etc/shadow');
});

test('normalizePath: absolute & relative', () => {
  assert.equal(normalizePath('/tmp'), '/tmp');
  assert.ok(path.isAbsolute(normalizePath('~/.bashrc')));
});

test('extractPathsFromCommand: picks up ~ and absolute tokens', () => {
  const tokens = extractPathsFromCommand('cat ~/.ssh/id_rsa && ls /etc/shadow | head');
  assert.ok(tokens.includes('~/.ssh/id_rsa'));
  assert.ok(tokens.includes('/etc/shadow'));
});

test('extractPathsFromParams: bash-like tool', () => {
  const paths = extractPathsFromParams('bash', { command: 'cat ~/.ssh/id_rsa' }, { bashLikeTools: ['bash'] });
  assert.ok(paths.includes('~/.ssh/id_rsa'));
});

test('extractPathsFromParams: structured tool with path field', () => {
  const paths = extractPathsFromParams('read_file', { path: '~/.aws/credentials' });
  assert.ok(paths.includes('~/.aws/credentials'));
});

test('guardBeforeToolCall: blocks ~/.ssh/id_rsa via read_file', () => {
  resetPathGuardCache();
  const r = guardBeforeToolCall({ toolName: 'read_file', params: { path: '~/.ssh/id_rsa' } });
  assert.equal(r.block, true);
  assert.equal(r.severity, 'CRITICAL');
  assert.match(r.matched, /\.ssh/);
});

test('guardBeforeToolCall: blocks cat ~/.ssh/id_rsa via bash', () => {
  resetPathGuardCache();
  const r = guardBeforeToolCall({ toolName: 'bash', params: { command: 'cat ~/.ssh/id_rsa' } });
  assert.equal(r.block, true);
});

test('guardBeforeToolCall: blocks /etc/shadow via bash', () => {
  resetPathGuardCache();
  const r = guardBeforeToolCall({ toolName: 'bash', params: { command: 'sudo cat /etc/shadow' } });
  assert.equal(r.block, true);
  assert.equal(r.severity, 'CRITICAL');
});

test('guardBeforeToolCall: allows benign paths', () => {
  resetPathGuardCache();
  const r = guardBeforeToolCall({ toolName: 'read_file', params: { path: '/tmp/foo.txt' } });
  assert.equal(r.block, false);
});

test('guardBeforeToolCall: allows benign bash', () => {
  resetPathGuardCache();
  const r = guardBeforeToolCall({ toolName: 'bash', params: { command: 'ls /tmp && echo hi' } });
  assert.equal(r.block, false);
});

test('guardBeforeToolCall: blocks write to ~/.bashrc', () => {
  resetPathGuardCache();
  const r = guardBeforeToolCall({ toolName: 'write_file', params: { path: '~/.bashrc', content: 'evil' } });
  assert.equal(r.block, true);
  assert.equal(r.matched, '~/.bashrc');
});

test('guardBeforeToolCall: blocks rm -rf ~/.ssh via bash', () => {
  resetPathGuardCache();
  const r = guardBeforeToolCall({ toolName: 'bash', params: { command: 'rm -rf ~/.ssh' } });
  assert.equal(r.block, true);
});

test('loadProtectedPaths: rules are non-empty and have regex', () => {
  resetPathGuardCache();
  const { rules } = loadProtectedPaths();
  assert.ok(rules.length > 0);
  assert.ok(rules.every((r) => r.regex instanceof RegExp));
});
