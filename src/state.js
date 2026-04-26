import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

export function getStatePath(config = {}) {
  return join(config.dataDir ?? '.404gent', 'state.json');
}

export async function readState(config = {}) {
  try {
    return JSON.parse(await readFile(getStatePath(config), 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') {
      return { eventCount: 0, lastDecision: null, lastSeverity: 'info' };
    }
    throw error;
  }
}

export async function writeState(state, config = {}) {
  const path = getStatePath(config);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(state, null, 2)}\n`);
}

export async function updateState(result, config = {}) {
  const current = await readState(config);
  const next = {
    ...current,
    eventCount: current.eventCount + 1,
    lastDecision: result.decision,
    lastSeverity: result.severity,
    updatedAt: new Date().toISOString()
  };
  await writeState(next, config);
  return next;
}
