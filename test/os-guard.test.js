import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyzeEvent } from '../src/policy/engine.js';
import { guardAndRecord } from '../src/guard.js';
import { createExecEvent, createOpenEvent, createOsEventFromPayload, createUnlinkEvent } from '../src/integrations/os-guard.js';
import { createPolicyServer } from '../src/server.js';

test('OS open event preserves metadata and blocks sensitive files', () => {
  const event = createOpenEvent('.env', {
    agent: 'demo',
    pid: 1234,
    mode: 'native-notify',
    authDecision: 'deny',
    reason: 'sensitive file: .env',
    cache: false
  });
  const result = analyzeEvent(event);
  assert.equal(result.event.type, 'os');
  assert.equal(result.event.meta.operation, 'open');
  assert.equal(result.event.meta.authDecision, 'deny');
  assert.equal(result.decision, 'block');
  assert.equal(result.findings[0].id, 'os-sensitive-file-open');
});

test('OS exec event warns on network transfer tools', () => {
  const result = analyzeEvent(createExecEvent(['curl', 'https://example.test/upload'], {
    agent: 'demo',
    pid: 1234
  }));
  assert.equal(result.event.meta.operation, 'exec');
  assert.deepEqual(result.event.meta.argv, ['curl', 'https://example.test/upload']);
  assert.equal(result.decision, 'warn');
  assert.equal(result.findings[0].id, 'os-network-tool-exec');
});

test('OS open event blocks cloud credentials', () => {
  const result = analyzeEvent(createOpenEvent('.404gent/os-guard-demo/aws_credentials', {
    agent: 'demo',
    pid: 1234
  }));
  assert.equal(result.decision, 'block');
  assert.equal(result.findings[0].id, 'os-cloud-credentials-open');
});

test('OS unlink simulation blocks sensitive file deletes', () => {
  const result = analyzeEvent(createUnlinkEvent('.env', {
    agent: 'demo',
    pid: 1234
  }));
  assert.equal(result.event.meta.operation, 'unlink');
  assert.equal(result.decision, 'block');
  assert.equal(result.findings[0].id, 'os-sensitive-file-unlink');
});

test('OS Guard events record audit vector and state', async () => {
  const dataDir = await mkdtemp(join(tmpdir(), '404gent-os-'));
  const result = await guardAndRecord(createOpenEvent('credentials.json'), { dataDir });
  const audit = await readFile(join(dataDir, 'events.jsonl'), 'utf8');
  const state = JSON.parse(await readFile(join(dataDir, 'state.json'), 'utf8'));
  assert.equal(result.decision, 'block');
  assert.match(audit, /"type":"os"/);
  assert.equal(state.lastDecision, 'block');
});

test('OS event payload validation rejects invalid payloads', () => {
  assert.throws(() => createOsEventFromPayload({ type: 'open' }), /path/);
  assert.throws(() => createOsEventFromPayload({ type: 'exec', argv: [] }), /argv/);
  assert.throws(() => createOsEventFromPayload({ type: 'unlink' }), /path/);
  assert.throws(() => createOsEventFromPayload({ type: 'rename', path: '.env' }), /Unsupported/);
});

test('policy server accepts OS events and returns decisions', async (t) => {
  const dataDir = await mkdtemp(join(tmpdir(), '404gent-server-'));
  const server = createPolicyServer({ config: { dataDir } });
  const listened = await new Promise((resolve, reject) => {
    server.once('error', (error) => {
      if (error.code === 'EPERM') {
        resolve(false);
        return;
      }
      reject(error);
    });
    server.listen(0, '127.0.0.1', () => resolve(true));
  });
  if (!listened) {
    t.skip('Sandbox does not allow local TCP listen.');
    return;
  }
  const { port } = server.address();

  try {
    const response = await fetch(`http://127.0.0.1:${port}/os-event`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'open', path: '.env', pid: 4321, agent: 'demo' })
    });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.decision, 'block');
    assert.equal(body.findings[0].id, 'os-sensitive-file-open');
  } finally {
    server.close();
  }
});

test('policy server serves local evidence images from data directory', async (t) => {
  const dataDir = await mkdtemp(join(tmpdir(), '404gent-server-images-'));
  await mkdir(join(dataDir, 'images', 'raw'), { recursive: true });
  await writeFile(join(dataDir, 'images', 'raw', 'sample.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47]));

  const server = createPolicyServer({ config: { dataDir } });
  const listened = await new Promise((resolve, reject) => {
    server.once('error', (error) => {
      if (error.code === 'EPERM') {
        resolve(false);
        return;
      }
      reject(error);
    });
    server.listen(0, '127.0.0.1', () => resolve(true));
  });
  if (!listened) {
    t.skip('Sandbox does not allow local TCP listen.');
    return;
  }
  const { port } = server.address();

  try {
    const response = await fetch(`http://127.0.0.1:${port}/images/raw/sample.png`);
    const body = Buffer.from(await response.arrayBuffer());
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('content-type'), 'image/png');
    assert.deepEqual([...body], [0x89, 0x50, 0x4e, 0x47]);

    const traversal = await fetch(`http://127.0.0.1:${port}/images/%2e%2e/events.jsonl`);
    assert.equal(traversal.status, 400);
  } finally {
    server.close();
  }
});

test('OS Guard simulation scenarios are documented', async () => {
  const raw = await readFile('examples/os-guard/scenarios.json', 'utf8');
  const scenarios = JSON.parse(raw);
  assert.ok(Array.isArray(scenarios));
  assert.ok(scenarios.length >= 5);

  for (const scenario of scenarios) {
    assert.equal(typeof scenario.name, 'string');
    assert.ok(Array.isArray(scenario.command), scenario.name);
    assert.ok(['allow', 'warn', 'block'].includes(scenario.expectedDecision), scenario.name);
    assert.equal(scenario.command[0], 'node', scenario.name);
    assert.equal(scenario.command[1], 'src/cli.js', scenario.name);
    assert.equal(scenario.command[2], 'os-guard', scenario.name);
  }
});
