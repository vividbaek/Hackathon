import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readState, updateState } from '../src/state.js';

test('initializes and updates state', async () => {
  const dataDir = await mkdtemp(join(tmpdir(), '404gent-state-'));
  const initial = await readState({ dataDir });
  assert.equal(initial.eventCount, 0);
  const next = await updateState({ decision: 'block', severity: 'critical' }, { dataDir });
  assert.equal(next.eventCount, 1);
  assert.equal(next.lastDecision, 'block');
});
