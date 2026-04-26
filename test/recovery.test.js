import test from 'node:test';
import assert from 'node:assert/strict';
import { suggestRecovery } from '../src/recovery.js';

test('suggests recovery for blocked results', () => {
  const suggestions = suggestRecovery({ decision: 'block' });
  assert.ok(suggestions.length > 0);
});
