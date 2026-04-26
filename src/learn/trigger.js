import { learnPaths, readJson, readJsonLines } from './store.js';

const HIGH_SEVERITIES = new Set(['high', 'critical']);

export async function learnStatus(config = {}) {
  const paths = learnPaths(config);
  const minEvents = config.learn?.trigger?.min_events ?? 20;
  const events = await readJsonLines(paths.events);
  const riskyEvents = events.filter((event) => ['block', 'warn'].includes(event.decision));
  const highSeverityEvents = riskyEvents.filter((event) => {
    return (event.findings ?? []).some((finding) => HIGH_SEVERITIES.has(finding.severity));
  });
  const pending = await readJson(paths.pendingRules, { rules: [] });
  const shadow = await readJson(paths.shadowRules, { rules: [] });

  return {
    events: riskyEvents.length,
    minEvents,
    highSeverity: highSeverityEvents.length,
    ready: riskyEvents.length >= minEvents || highSeverityEvents.length > 0,
    pendingRules: (pending.rules ?? []).filter((rule) => rule.status !== 'rejected').length,
    shadowRules: (shadow.rules ?? []).length
  };
}

export function shouldAnalyze(status, { manual = false } = {}) {
  return Boolean(manual || status.ready);
}
