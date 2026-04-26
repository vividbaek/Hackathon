import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { defaultRules } from './policy/default-rules.js';

export const DEFAULT_CONFIG = {
  dataDir: '.404gent',
  failClosed: false,
  mode: 'enforce',
  companyId: 'default',
  vectorStore: {
    provider: 'jsonl'
  },
  blockSeverities: ['critical', 'high'],
  llm: {
    enabled: false,
    provider: 'anthropic',
    model: 'claude-sonnet-4-5',
    apiKeyEnv: 'ANTHROPIC_API_KEY',
    visionProvider: 'anthropic',
    googleApiKeyEnv: 'GOOGLE_API_KEY',
    googleVisionModel: 'gemini-2.0-flash',
    reviewTypes: ['image', 'vision_observation', 'llm', 'prompt'],
    reviewDecisions: ['allow', 'warn']
  },
  learn: {
    inference: {
      enabled: true,
      provider: 'openai',
      model: 'gpt-5-mini',
      apiKeyEnv: 'OPENAI_API_KEY'
    }
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

export function applyCompanyProfile(config, companyId) {
  const profile = config.companyProfiles?.[companyId];
  if (!profile) {
    return { ...config, companyId };
  }

  return mergeConfig({ ...config, companyId }, profile);
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
