import { DEFAULT_BLOCK_SEVERITIES, compareSeverityDesc, highestSeverity, isValidSeverity } from './severity.js';
import { compileRule, getRules } from './rules.js';

export const VALID_EVENT_TYPES = new Set(['prompt', 'command', 'output', 'image', 'llm', 'vision_observation', 'os']);

function createEventId() {
  const random = Math.random().toString(36).slice(2, 10);
  return `evt_${Date.now().toString(36)}_${random}`;
}

function normalizeEvent(event = {}) {
  const type = event.type;
  if (!VALID_EVENT_TYPES.has(type)) {
    throw new Error(`Unsupported event type: ${type}`);
  }

  return {
    type,
    text: String(event.text ?? ''),
    source: event.source ?? 'cli',
    companyId: event.companyId ?? event.meta?.companyId,
    agentId: event.agentId ?? event.meta?.agentId,
    evidence: event.evidence ?? {},
    artifacts: Array.isArray(event.artifacts) ? event.artifacts : [],
    embeddings: event.embeddings ?? null,
    meta: event.meta ?? {}
  };
}

function appliesTo(rule, type) {
  const targets = Array.isArray(rule.appliesTo) ? rule.appliesTo : [rule.appliesTo ?? rule.surface];
  if ((type === 'image' || type === 'vision_observation') && targets.includes('prompt')) {
    return true;
  }
  if (type === 'llm' && targets.includes('prompt')) {
    return true;
  }
  return targets.includes(type) || targets.includes('*');
}

function toFinding(rule, match) {
  return {
    id: rule.id,
    severity: rule.severity,
    category: rule.category,
    rationale: rule.rationale,
    remediation: rule.remediation,
    match: match?.[0] ?? ''
  };
}

function normalizeFinding(finding) {
  return {
    id: String(finding.id ?? finding.ruleId ?? 'llm-finding'),
    severity: isValidSeverity(finding.severity) ? finding.severity : 'medium',
    category: String(finding.category ?? 'llm'),
    rationale: String(finding.rationale ?? finding.message ?? 'LLM reported a policy concern.'),
    remediation: String(finding.remediation ?? 'Review the finding and remove unsafe content.'),
    match: String(finding.match ?? '')
  };
}

function decide(findings, config = {}) {
  if (findings.length === 0) {
    return 'allow';
  }
  if (config.mode === 'observe') {
    return 'warn';
  }
  if (config.mode === 'lockdown') {
    return 'block';
  }
  const blockSeverities = config.blockSeverities ?? DEFAULT_BLOCK_SEVERITIES;
  return findings.some((finding) => blockSeverities.includes(finding.severity)) ? 'block' : 'warn';
}

export function analyzeEvent(event, config = {}) {
  const normalizedEvent = normalizeEvent(event);
  const findings = [];

  for (const rule of getRules(config)) {
    if (!appliesTo(rule, normalizedEvent.type)) {
      continue;
    }
    const regex = compileRule(rule).regex;
    const match = regex.exec(normalizedEvent.text);
    if (match) {
      findings.push(toFinding(rule, match));
    }
  }

  findings.sort(compareSeverityDesc);

  return {
    id: createEventId(),
    timestamp: new Date().toISOString(),
    event: normalizedEvent,
    decision: decide(findings, config),
    findings
  };
}

export function mergeReports(ruleReport, llmReport, config = {}) {
  if (!llmReport || llmReport.skipped) {
    return ruleReport;
  }

  const findings = [
    ...ruleReport.findings.map(normalizeFinding),
    ...asArray(llmReport.findings).map(normalizeFinding)
  ].sort(compareSeverityDesc);

  return {
    ...ruleReport,
    decision: decide(findings, config),
    findings
  };
}

function asArray(value) {
  if (!value) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

export function scanText({ surface, text = '', config = {}, ...eventFields }) {
  const report = analyzeEvent({ ...eventFields, type: surface, text }, config);
  return {
    ...report,
    surface,
    text: String(text ?? ''),
    severity: report.findings.length > 0 ? highestSeverity(report.findings) : 'low',
    scannedAt: report.timestamp
  };
}
