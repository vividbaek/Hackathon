import test from 'node:test';
import assert from 'node:assert/strict';
import { scanOutput } from '../src/output-monitor.js';

test('blocks credential-like output', () => {
  const result = scanOutput('AWS_SECRET_ACCESS_KEY=example');
  assert.equal(result.decision, 'block');
});
