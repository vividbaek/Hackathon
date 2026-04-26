import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

export function learnPaths(config = {}) {
  const dataDir = config.dataDir ?? '.404gent';
  return {
    dataDir,
    events: join(dataDir, 'events.jsonl'),
    attackLogs: join(dataDir, 'attack-logs.json'),
    pendingRules: join(dataDir, 'pending-rules.json'),
    shadowRules: join(dataDir, 'shadow-rules.json'),
    shadowEvents: join(dataDir, 'shadow-events.jsonl'),
    approvedRules: config.learn?.approvedRulesPath ?? join(dataDir, 'approved-rules.json'),
    rejectedRules: join(dataDir, 'rejected-rules.json'),
    samples: join(dataDir, 'learn-samples.json'),
    ruleCandidates: join(dataDir, 'rule-candidates.json')
  };
}

export async function readJson(path, fallback) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return fallback;
    throw error;
  }
}

export async function writeJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

export function parseJsonLines(raw) {
  return raw
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

export async function readJsonLines(path) {
  try {
    return parseJsonLines(await readFile(path, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

export async function appendJsonLine(path, value) {
  await mkdir(dirname(path), { recursive: true });
  await appendFile(path, `${JSON.stringify(value)}\n`);
}
