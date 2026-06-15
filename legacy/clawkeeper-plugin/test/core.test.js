import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createAuditContext, runAudit } from '../src/core/audit-engine.js';
import { harden } from '../src/core/hardening.js';
import { rollback } from '../src/core/rollback.js';

test('audit finds risky defaults', async () => {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), 'clawkeeper-audit-'));
  await fs.writeFile(path.join(stateDir, 'openclaw.json'), JSON.stringify({
    gateway: { bind: '0.0.0.0' },
    sandbox: { mode: 'danger-full-access' },
    exec: { approvals: 'never' }
  }, null, 2));

  const context = await createAuditContext(stateDir, { strictMode: true });
  const report = await runAudit(context);

  assert.equal(report.findings.length, 6);
  assert.equal(report.summary.high >= 2, true);
  assert.equal(report.summary.critical, 1);
  assert.ok(report.findings.some((item) => item.id === 'behavior.runtime-constitution'));
  assert.ok(report.findings.some((item) => item.id === 'skill.runtime-presence'));
  assert.equal(typeof report.findings[0].threat, 'string');
  assert.equal(typeof report.findings[0].intent, 'string');
  assert.equal(typeof report.findings[0].evidence, 'object');
  assert.equal(typeof report.findings[0].canAutoFix, 'boolean');
  assert.equal(typeof report.findings[0].nextStep, 'string');
  assert.equal(Array.isArray(report.nextSteps), true);
});

test('hardening writes safe defaults and rules', async () => {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), 'clawkeeper-harden-'));
  await fs.writeFile(path.join(stateDir, 'openclaw.json'), JSON.stringify({
    gateway: { bind: '0.0.0.0' },
    sandbox: { mode: 'danger-full-access' },
    exec: { approvals: 'never' }
  }, null, 2));

  const result = await harden(stateDir);
  const config = JSON.parse(await fs.readFile(path.join(stateDir, 'openclaw.json'), 'utf-8'));
  const soul = await fs.readFile(path.join(stateDir, 'SOUL.md'), 'utf-8');

  assert.ok(result.backupDir.includes('.clawkeeper/backups'));
  assert.equal(config.gateway.bind, '127.0.0.1');
  assert.equal(config.sandbox.mode, 'workspace-write');
  assert.equal(config.exec.approvals, 'on-request');
  assert.ok(soul.includes('clawkeeper:rules:start'));
});

test('rollback restores previous config and soul', async () => {
  const stateDir = await fs.mkdtemp(path.join(os.tmpdir(), 'clawkeeper-rollback-'));
  await fs.writeFile(path.join(stateDir, 'openclaw.json'), JSON.stringify({
    gateway: { bind: '0.0.0.0' },
    sandbox: { mode: 'danger-full-access' },
    exec: { approvals: 'never' }
  }, null, 2));
  await fs.writeFile(path.join(stateDir, 'SOUL.md'), '# old soul\n', 'utf-8');

  await harden(stateDir);
  const restored = await rollback(stateDir);
  const config = JSON.parse(await fs.readFile(path.join(stateDir, 'openclaw.json'), 'utf-8'));
  const soul = await fs.readFile(path.join(stateDir, 'SOUL.md'), 'utf-8');

  assert.ok(restored.restoredFiles.includes('openclaw.json'));
  assert.equal(config.gateway.bind, '0.0.0.0');
  assert.equal(soul, '# old soul\n');
});
