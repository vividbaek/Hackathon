import { mkdir, appendFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

export function getEventsPath(config = {}) {
  return join(config.dataDir ?? '.404gent', 'events.jsonl');
}

export async function appendAuditEvent(event, config = {}) {
  const path = getEventsPath(config);
  await mkdir(dirname(path), { recursive: true });
  await appendFile(path, `${JSON.stringify({ ...event, recordedAt: new Date().toISOString() })}\n`);
}
