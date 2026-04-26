import { learnPaths, readJson, readJsonLines } from './store.js';

const HIGH_SEVERITIES = new Set(['high', 'critical']);

export async function learnStatus(config = {}) {
  const paths = learnPaths(config);
  const minEvents = config.learn?.trigger?.min_events ?? 20;
  const cooldownMinutes = config.learn?.trigger?.cooldown_minutes ?? 30;
  const events = await readJsonLines(paths.events);
  const riskyEvents = events.filter((event) => ['block', 'warn'].includes(event.decision));
  const highSeverityEvents = riskyEvents.filter((event) => {
    return (event.findings ?? []).some((finding) => HIGH_SEVERITIES.has(finding.severity));
  });
  const pending = await readJson(paths.pendingRules, { rules: [] });
  const shadow = await readJson(paths.shadowRules, { rules: [] });
  const state = await readJson(paths.learnState, {});
  const lastAnalyzedAt = state.lastAnalyzedAt ?? null;
  const lastAnalyzedMs = lastAnalyzedAt ? Date.parse(lastAnalyzedAt) : NaN;
  const cooldownMs = cooldownMinutes * 60 * 1000;
  const cooldownElapsed = !Number.isFinite(lastAnalyzedMs) || Date.now() - lastAnalyzedMs >= cooldownMs;
  const triggerReady = riskyEvents.length >= minEvents || highSeverityEvents.length > 0;

  return {
    events: riskyEvents.length,
    minEvents,
    cooldownMinutes,
    lastAnalyzedAt,
    cooldownElapsed,
    highSeverity: highSeverityEvents.length,
    ready: triggerReady && cooldownElapsed,
    pendingRules: (pending.rules ?? []).filter((rule) => rule.status !== 'rejected').length,
    shadowRules: (shadow.rules ?? []).length
  };
}

export function shouldAnalyze(status, { manual = false } = {}) {
  return Boolean(manual || status.ready);
}
