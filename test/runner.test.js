import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { appendAuditEvent } from '../src/audit.js';
import { runGuardedCommand } from '../src/runner.js';

test('runGuardedCommand executes safe command and records command/output reports', async () => {
  const dataDir = await mkdtemp(join(tmpdir(), '404gent-runner-'));
  const reports = [];
  const result = await runGuardedCommand([process.execPath, '-e', 'console.log("hello runner")'], {
    config: { dataDir },
    recordReport: async (report) => {
      reports.push(report);
      await appendAuditEvent(report, { dataDir });
    },
    stdout: { write() {} },
    stderr: { write() {} }
  });

  assert.equal(result.exitCode, 0);
  assert.equal(reports[0].event.type, 'command');
  assert.equal(reports[1].event.type, 'output');
  assert.match(result.stdoutText, /hello runner/);
});

test('runGuardedCommand blocks dangerous command before execution', async () => {
  const reports = [];
  const result = await runGuardedCommand(['rm', '-rf', '/'], {
    recordReport: async (report) => reports.push(report),
    stdout: { write() {} },
    stderr: { write() {} }
  });

  assert.equal(result.exitCode, 126);
  assert.equal(result.commandReport.decision, 'block');
  assert.equal(result.outputReport, null);
  assert.equal(reports.length, 1);
});

test('runGuardedCommand scans sensitive output', async () => {
  const result = await runGuardedCommand([
    process.execPath,
    '-e',
    'console.log("AWS_SECRET_ACCESS_KEY=example")'
  ], {
    stdout: { write() {} },
    stderr: { write() {} }
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.outputReport.decision, 'block');
});
