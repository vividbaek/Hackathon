import test from 'node:test';
import assert from 'node:assert/strict';
import { createMockLlmProvider } from '../src/providers/llm.js';

test('mock llm provider returns configured response', async () => {
  const provider = createMockLlmProvider({ decision: 'block' });
  assert.deepEqual(await provider.evaluate(), { decision: 'block' });
});
