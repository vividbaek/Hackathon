import { mkdir, appendFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

export function getVectorEventsPath(config = {}) {
  return join(config.dataDir ?? '.404gent', 'vectors.jsonl');
}

export function createVectorDocument(report) {
  return {
    id: report.id,
    timestamp: report.timestamp,
    type: report.event.type,
    companyId: report.event.companyId,
    agentId: report.event.agentId,
    text: report.event.text,
    decision: report.decision,
    findingIds: report.findings.map((finding) => finding.id),
    embeddings: report.event.embeddings,
    evidence: report.event.evidence
  };
}

export async function appendVectorDocument(report, config = {}) {
  const provider = config.vectorStore?.provider ?? 'jsonl';
  if (provider !== 'jsonl') {
    return { skipped: true, provider, reason: 'provider_not_configured' };
  }

  const path = getVectorEventsPath(config);
  await mkdir(dirname(path), { recursive: true });
  await appendFile(path, `${JSON.stringify(createVectorDocument(report))}\n`);
  return { skipped: false, provider, path };
}
