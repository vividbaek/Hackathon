import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { defaultRules } from './policy/default-rules.js';

export const DEFAULT_CONFIG = {
  dataDir: '.404gent',
  failClosed: false,
  blockSeverities: ['critical', 'high'],
  llm: {
    enabled: false,
    provider: 'anthropic',
    model: 'claude-sonnet-4-5',
    apiKeyEnv: 'ANTHROPIC_API_KEY',
    reviewTypes: ['image', 'vision_observation', 'llm', 'prompt'],
    reviewDecisions: ['allow', 'warn']
  },
  rules: defaultRules
};

function mergeConfig(base, override) {
  return {
    ...base,
    ...override,
    rules: Object.hasOwn(override, 'rules') ? override.rules : base.rules
  };
}

export async function loadConfig({ configPath } = {}) {
  if (!configPath) {
    return structuredClone(DEFAULT_CONFIG);
  }

  const absolutePath = resolve(configPath);
  const raw = await readFile(absolutePath, 'utf8');
  const parsed = JSON.parse(raw);
  return mergeConfig(structuredClone(DEFAULT_CONFIG), parsed);
}
