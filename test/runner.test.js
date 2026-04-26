import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
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

test('runGuardedCommand redacts sensitive output before writing streams', async () => {
  let displayed = '';
  const result = await runGuardedCommand([
    process.execPath,
    '-e',
    'console.log("AWS_SECRET_ACCESS_KEY=example")'
  ], {
    stdout: { write(chunk) { displayed += chunk; } },
    stderr: { write() {} }
  });

  assert.equal(result.exitCode, 0);
  assert.match(result.stdoutText, /AWS_SECRET_ACCESS_KEY=example/);
  assert.doesNotMatch(displayed, /AWS_SECRET_ACCESS_KEY=example/);
  assert.match(displayed, /\[REDACTED\]/);
  assert.equal(result.streamReports.some((report) => report.decision === 'block'), true);
});

test('runGuardedCommand redacts sensitive output split across stream chunks', async () => {
  let displayed = '';
  const spawnImpl = () => {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    process.nextTick(() => {
      child.stdout.emit('data', Buffer.from('AWS_SECRET_'));
      child.stdout.emit('data', Buffer.from('ACCESS_KEY=example\n'));
      child.emit('close', 0);
    });
    return child;
  };

  const result = await runGuardedCommand(['fake'], {
    spawnImpl,
    stdout: { write(chunk) { displayed += chunk; } },
    stderr: { write() {} }
  });

  assert.equal(result.exitCode, 0);
  assert.match(result.stdoutText, /AWS_SECRET_ACCESS_KEY=example/);
  assert.doesNotMatch(displayed, /AWS_SECRET_ACCESS_KEY=example/);
  assert.match(displayed, /\[REDACTED\]/);
});
