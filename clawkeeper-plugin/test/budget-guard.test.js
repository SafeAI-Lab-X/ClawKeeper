import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

import {
  loadBudget,
  saveBudget,
  recordUsage,
  checkBudget,
  resetBudgetCache,
  formatBudgetSummary,
} from '../src/core/budget-guard.js';

function tmpFile(label) {
  return path.join(os.tmpdir(), `clawkeeper-budget-${label}-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
}

test('fresh budget round-trips through save/load', () => {
  resetBudgetCache();
  const f = tmpFile('rt');
  const b = loadBudget(f);
  assert.equal(b.usage.total, 0);
  saveBudget(b, f);
  const b2 = loadBudget(f);
  assert.equal(b2.usage.total, 0);
  fs.rmSync(f, { force: true });
});

test('recordUsage accumulates and returns ok under limits', () => {
  resetBudgetCache();
  const f = tmpFile('ok');
  const r = recordUsage({ input: 10, output: 5 }, f);
  assert.equal(r.status, 'ok');
  assert.equal(r.usage.input, 10);
  assert.equal(r.usage.output, 5);
  assert.equal(r.usage.total, 15);
  fs.rmSync(f, { force: true });
});

test('recordUsage flips to warn at warnRatio', () => {
  resetBudgetCache();
  const f = tmpFile('warn');
  // limits from core-rules: input=1000, output=500, total=1500; warnRatio=0.8
  // input 800/1000=0.8 trips warn; output 300/500=0.6, total 1100/1500=0.73 stay ok
  recordUsage({ input: 800, output: 300 }, f);
  const r = checkBudget(f);
  assert.equal(r.status, 'warn');
  fs.rmSync(f, { force: true });
});

test('recordUsage flips to over at the limit', () => {
  resetBudgetCache();
  const f = tmpFile('over');
  recordUsage({ input: 1000, output: 500 }, f); // total=1500 = total cap
  const r = checkBudget(f);
  assert.equal(r.status, 'over');
  assert.equal(r.block, true);
  fs.rmSync(f, { force: true });
});

test('any single dimension over its cap trips over', () => {
  resetBudgetCache();
  const f = tmpFile('dim');
  // input cap is 1000; push only input
  recordUsage({ input: 1001, output: 0 }, f);
  const r = checkBudget(f);
  assert.equal(r.status, 'over');
  fs.rmSync(f, { force: true });
});

test('rolling window resets when expired', () => {
  resetBudgetCache();
  const f = tmpFile('roll');
  // seed with an exhausted budget whose window started >2 days ago
  const stale = {
    windowStart: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
    windowDays: 1,
    limits: { input: 1000, output: 500, total: 1500 },
    thresholds: { warn: 0.8 },
    usage: { input: 9999, output: 9999, total: 19998, calls: 99 },
    lastDecision: 'over',
  };
  saveBudget(stale, f);
  const r = checkBudget(f);
  assert.equal(r.status, 'ok');
  assert.equal(r.usage.total, 0);
  fs.rmSync(f, { force: true });
});

test('checkBudget returns ok on missing state file', () => {
  resetBudgetCache();
  const f = tmpFile('missing');
  const r = checkBudget(f);
  assert.equal(r.block, false);
  assert.equal(r.status, 'ok');
});

test('formatBudgetSummary renders human-readable line', () => {
  const s = formatBudgetSummary({
    usage: { input: 1, output: 2, total: 3, calls: 4 },
    limits: { input: 10, output: 20, total: 30 },
  });
  assert.match(s, /input=1\/10/);
  assert.match(s, /total=3\/30/);
});
