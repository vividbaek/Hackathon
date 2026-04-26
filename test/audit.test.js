import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { appendAuditEvent } from '../src/audit.js';

test('writes audit events as jsonl', async () => {
  const dataDir = await mkdtemp(join(tmpdir(), '404gent-audit-'));
  await appendAuditEvent({ decision: 'allow' }, { dataDir });
  const raw = await readFile(join(dataDir, 'events.jsonl'), 'utf8');
  assert.match(raw, /"decision":"allow"/);
});
