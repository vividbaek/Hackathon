import test from 'node:test';
import assert from 'node:assert/strict';
import { createDiagnostic } from '../src/diagnostics.js';

test('creates diagnostics from scan result', () => {
  const diagnostic = createDiagnostic({ decision: 'allow', severity: 'info', findings: [] });
  assert.equal(diagnostic.decision, 'allow');
});
