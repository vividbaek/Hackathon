import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeEvent } from '../src/policy/engine.js';
import { createAnthropicProvider, createMockLlmProvider, shouldReviewWithLlm } from '../src/providers/llm.js';

test('mock llm provider returns configured response', async () => {
  const provider = createMockLlmProvider({ decision: 'block' });
  assert.deepEqual(await provider.evaluate(), { decision: 'block' });
});

test('shouldReviewWithLlm respects config gates', () => {
  const report = analyzeEvent({ type: 'image', text: 'normal screenshot' });
  assert.equal(shouldReviewWithLlm(report, { llm: { enabled: false } }), false);
  assert.equal(shouldReviewWithLlm(report, {
    llm: {
      enabled: true,
      reviewTypes: ['image'],
      reviewDecisions: ['allow']
    }
  }), true);
});

test('anthropic provider sends Messages API request and parses JSON findings', async () => {
  const calls = [];
  const provider = createAnthropicProvider({
    apiKey: 'test-key',
    model: 'claude-test',
    fetchImpl: async (url, request) => {
      calls.push({ url, request });
      return {
        ok: true,
        async json() {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  skipped: false,
                  findings: [
                    {
                      id: 'llm-review-visual-injection',
                      severity: 'high',
                      category: 'visual_prompt_injection',
                      rationale: 'Image text is suspicious.',
                      remediation: 'Block the image-derived prompt.',
                      match: 'hidden instruction'
                    }
                  ]
                })
              }
            ]
          };
        }
      };
    }
  });

  const report = analyzeEvent({ type: 'image', text: 'hidden instruction' });
  const result = await provider.evaluate(report);

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://api.anthropic.com/v1/messages');
  assert.equal(calls[0].request.headers['x-api-key'], 'test-key');
  assert.equal(calls[0].request.headers['anthropic-version'], '2023-06-01');
  assert.equal(JSON.parse(calls[0].request.body).model, 'claude-test');
  assert.equal(result.findings[0].id, 'llm-review-visual-injection');
});
