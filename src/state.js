import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
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
    if (error instanceof SyntaxError) {
      return { eventCount: 0, lastDecision: null, lastSeverity: 'info', recoveredFromCorruptState: true };
    }
    throw error;
  }
}

export async function writeState(state, config = {}) {
  const path = getStatePath(config);
  await mkdir(dirname(path), { recursive: true });
  const tempPath = `${path}.${process.pid}.${Date.now()}.${Math.random().toString(36).slice(2)}.tmp`;
  await writeFile(tempPath, `${JSON.stringify(state, null, 2)}\n`);
  await rename(tempPath, path);
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
