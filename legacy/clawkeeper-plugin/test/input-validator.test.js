import { test } from 'node:test';
import assert from 'node:assert/strict';

import { validateToolInput, resetValidatorCache } from '../src/core/input-validator.js';

function v(toolName, params) {
  resetValidatorCache();
  return validateToolInput(toolName, params);
}

test('passes a well-formed bash call', () => {
  const r = v('bash', { command: 'ls -la /tmp' });
  assert.equal(r.block, false);
});

test('blocks bash call missing required command', () => {
  const r = v('bash', { cwd: '/tmp' });
  assert.equal(r.block, true);
  assert.match(r.reason, /command.*required/);
});

test('blocks bash call with non-string command', () => {
  const r = v('bash', { command: 12345 });
  assert.equal(r.block, true);
  assert.match(r.reason, /expected string/);
});

test('blocks bash command exceeding maxLength', () => {
  const r = v('bash', { command: 'a'.repeat(8001) });
  assert.equal(r.block, true);
  assert.match(r.reason, /maxLength/);
});

test('blocks bash command containing NUL byte', () => {
  const r = v('bash', { command: 'echo hi\u0000evil' });
  assert.equal(r.block, true);
  assert.match(r.reason, /pattern/);
});

test('passes shell alias just like bash', () => {
  const r = v('shell', { command: 'pwd' });
  assert.equal(r.block, false);
});

test('blocks read_file missing path', () => {
  const r = v('read_file', {});
  assert.equal(r.block, true);
});

test('blocks write_file with newline in path', () => {
  const r = v('write_file', { path: '/tmp/a\nb', content: 'x' });
  assert.equal(r.block, true);
});

test('passes unknown tool by default (unknownToolPolicy=pass)', () => {
  const r = v('some_random_tool', { foo: 'bar' });
  assert.equal(r.block, false);
  assert.equal(r.unknownTool, true);
});
