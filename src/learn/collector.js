import { learnPaths, readJsonLines, writeJson } from './store.js';

export const SURFACE_LAYER = {
  prompt: 'prompt',
  command: 'shell',
  os: 'es',
  output: 'output',
  image: 'screen',
  vision_observation: 'screen',
  llm: 'llm'
};

function eventType(report = {}) {
  return report.event?.type ?? report.surface ?? 'unknown';
}

function eventText(report = {}) {
  return report.event?.text ?? report.text ?? '';
}

function contextFor(report = {}) {
  const meta = report.event?.meta ?? {};
  const evidence = report.event?.evidence ?? {};
  const agent = meta.agent ?? report.event?.agentId ?? report.agentId;
  const fromAgent = meta.fromAgent ?? meta.from_agent ?? evidence.fromAgent;
  const chain = Array.isArray(meta.chain)
    ? meta.chain
    : [fromAgent, agent].filter(Boolean);

  return {
    agent,
    from_agent: fromAgent,
    chain,
    source: meta.source ?? evidence.imagePath ?? report.event?.source,
    source_type: meta.sourceType ?? meta.source_type ?? (evidence.imagePath ? 'file' : undefined)
  };
}

export function normalizeAttackEvent(report, finding) {
  const type = eventType(report);
  return {
    id: `${report.id}:${finding.id}`,
    eventId: report.id,
    timestamp: report.timestamp ?? report.recordedAt ?? report.scannedAt,
    layer: SURFACE_LAYER[type] ?? type,
    surface: type,
    action: report.decision === 'allow' ? 'detect' : report.decision,
    input: eventText(report),
    matched_rule: finding.id,
    category: finding.category,
    severity: finding.severity,
    match: finding.match ?? '',
    rationale: finding.rationale,
    remediation: finding.remediation,
    context: contextFor(report)
  };
}

export async function collectAttackLogs(config = {}, { windowMinutes } = {}) {
  const paths = learnPaths(config);
  const reports = await readJsonLines(paths.events);
  const cutoff = windowMinutes ? Date.now() - windowMinutes * 60 * 1000 : 0;
  const attacks = [];

  for (const report of reports) {
    const timestamp = Date.parse(report.timestamp ?? report.recordedAt ?? report.scannedAt ?? 0);
    if (cutoff && (!Number.isFinite(timestamp) || timestamp < cutoff)) {
      continue;
    }
    if (!['block', 'warn'].includes(report.decision)) {
      continue;
    }
    for (const finding of report.findings ?? []) {
      attacks.push(normalizeAttackEvent(report, finding));
    }
  }

  const output = {
    generatedAt: new Date().toISOString(),
    source: paths.events,
    count: attacks.length,
    attacks
  };
  await writeJson(paths.attackLogs, output);
  return output;
}
