import { compileRule } from '../policy/rules.js';
import { appendJsonLine, learnPaths, readJson, readJsonLines, writeJson } from './store.js';

function targets(rule, type) {
  const appliesTo = Array.isArray(rule.appliesTo) ? rule.appliesTo : [rule.appliesTo];
  return appliesTo.includes(type) || appliesTo.includes('*');
}

function reportType(report = {}) {
  return report.event?.type ?? report.surface;
}

function reportText(report = {}) {
  return report.event?.text ?? report.text ?? '';
}

export async function saveShadowRules(rules, config = {}) {
  const paths = learnPaths(config);
  await writeJson(paths.shadowRules, {
    updatedAt: new Date().toISOString(),
    rules
  });
}

export async function evaluateShadowReport(report, config = {}) {
  const paths = learnPaths(config);
  const shadow = await readJson(paths.shadowRules, { rules: [] });
  const type = reportType(report);
  const text = reportText(report);
  const hits = [];

  for (const entry of shadow.rules ?? []) {
    const rule = entry.rule ?? entry;
    if (!targets(rule, type)) continue;
    const match = compileRule(rule).regex.exec(text);
    if (!match) continue;
    hits.push({
      timestamp: new Date().toISOString(),
      eventId: report.id,
      ruleId: rule.id,
      actualDecision: report.decision,
      wouldDecision: 'block',
      match: match[0],
      surface: type
    });
  }

  for (const hit of hits) {
    await appendJsonLine(paths.shadowEvents, hit);
  }
  return hits;
}

export async function shadowStatus(config = {}) {
  const paths = learnPaths(config);
  const shadow = await readJson(paths.shadowRules, { rules: [] });
  const events = await readJsonLines(paths.shadowEvents);
  return {
    rules: shadow.rules ?? [],
    eventCount: events.length,
    wouldBlock: events.filter((event) => event.wouldDecision === 'block').length,
    recent: events.slice(-10).reverse()
  };
}
