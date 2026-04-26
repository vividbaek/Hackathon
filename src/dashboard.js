#!/usr/bin/env node
import { createServer } from 'node:http';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { extname, join, resolve, sep } from 'node:path';
import { loadConfig } from './config.js';
import { createVisionProviderFromConfig } from './providers/vision-llm.js';
import { scanText, mergeReports } from './policy/engine.js';
import { highestSeverity } from './policy/severity.js';
import { recordReport } from './guard.js';
import { preprocessImage } from './image-preprocess.js';

const DEFAULT_PORT = 4040;
const MAX_PORT = 4050;

const agentDefinitions = [
  {
    id: 'vision-agent',
    label: 'Vision Agent',
    role: 'Image/VLM extraction',
    icon: '👁',
    x: 90,
    y: 155,
    types: ['image', 'vision_observation']
  },
  {
    id: 'policy-agent',
    label: 'Policy Agent',
    role: 'Rule-based detection',
    icon: '🛡',
    x: 300,
    y: 155,
    types: ['prompt', 'command', 'output', 'image', 'vision_observation', 'llm', 'os']
  },
  {
    id: 'llm-review-agent',
    label: 'LLM Review',
    role: 'Claude escalation',
    icon: '🤖',
    x: 510,
    y: 85,
    types: ['llm']
  },
  {
    id: 'forensic-agent',
    label: 'Forensic Agent',
    role: 'Evidence logging',
    icon: '🔍',
    x: 510,
    y: 235,
    types: ['prompt', 'command', 'output', 'image', 'vision_observation', 'llm', 'os']
  },
  {
    id: 'rule-agent',
    label: 'Rule Agent',
    role: 'Self-loop candidates',
    icon: '⚙',
    x: 720,
    y: 235,
    types: []
  },
  {
    id: 'supervisor-agent',
    label: 'Supervisor',
    role: 'Block/warn/allow',
    icon: '🎯',
    x: 720,
    y: 85,
    types: ['prompt', 'command', 'output', 'image', 'vision_observation', 'llm', 'os']
  }
];

const graphEdges = [
  ['vision-agent','policy-agent'],
  ['policy-agent','llm-review-agent'],
  ['policy-agent','forensic-agent'],
  ['llm-review-agent','supervisor-agent'],
  ['forensic-agent','rule-agent'],
  ['rule-agent','policy-agent'],
  ['supervisor-agent','policy-agent']
];

const RUNTIME_HOOK_AGENT_ID = 'claude-code-hook';
const AGENT_ALIASES = {
  runtime: RUNTIME_HOOK_AGENT_ID,
  hook: RUNTIME_HOOK_AGENT_ID,
  'claude-code-hook': RUNTIME_HOOK_AGENT_ID,
  qa: 'agent-qa',
  'agent-qa': 'agent-qa',
  backend: 'agent-backend',
  'agent-backend': 'agent-backend',
  security: 'agent-security',
  'agent-security': 'agent-security'
};

function normalizeDashboardAgentId(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return '';
  return AGENT_ALIASES[raw] ?? AGENT_ALIASES[raw.toLowerCase()] ?? raw;
}

function agentFromSource(source) {
  const match = String(source ?? '').match(/^agent:([^:]+):os$/);
  return match ? match[1] : null;
}

function dashboardAgentId(e) {
  return normalizeDashboardAgentId(
    e.event?.agentId ??
    e.event?.meta?.agent ??
    agentFromSource(e.event?.source) ??
    (e.event?.source === 'claude-code-hook' ? RUNTIME_HOOK_AGENT_ID : '')
  );
}

const threeAgentRunbook = [
  { id:'agent-vision-sentinel', label:'Agent 1 · Vision Sentinel', icon:'👁',
    objective:'Detect hidden prompt injections and suspicious regions in images, screenshots, and OCR results.',
    inputs:'image file, screenshot, OCR text, VLM regions',
    outputs:'extractedText, hiddenPrompts, regions, objects, confidence',
    command:'node src/cli.js scan-image --file <image-path>' },
  { id:'agent-policy-arbiter',  label:'Agent 2 · Policy Arbiter',  icon:'🛡',
    objective:'Evaluate text and evidence from Vision Sentinel with rule-based checks and Claude review.',
    inputs:'prompt, image, vision_observation, llm, command, output events',
    outputs:'allow / warn / block, findings, remediation',
    command:'node src/cli.js scan-image "<VLM extracted text>"' },
  { id:'agent-rule-steward',    label:'Agent 3 · Rule Steward',    icon:'⚙',
    objective:'Bundle blocked and warning logs into forensic evidence and generate 30-minute self-loop rule candidates.',
    inputs:'.404gent/events.jsonl, .404gent/vectors.jsonl',
    outputs:'rule-candidates.json, replay corpus, policy diff',
    command:'npm run self-loop' }
];

const rank = { idle:0, allow:1, warn:2, block:3 };

function statusFromDecision(d) {
  if (d === 'block') return 'block';
  if (d === 'warn') return 'warn';
  if (d === 'allow') return 'allow';
  return 'idle';
}
function maxStatus(a, b) { return rank[b] > rank[a] ? b : a; }

function parseJsonLines(raw) {
  return raw.split('\n').map(l => l.trim()).filter(Boolean).map(l => JSON.parse(l));
}
async function readJsonLines(path) {
  try { return parseJsonLines(await readFile(path, 'utf8')); }
  catch (e) { if (e.code === 'ENOENT') return []; throw e; }
}
async function readJson(path, fallback) {
  try { return JSON.parse(await readFile(path, 'utf8')); }
  catch (e) { if (e.code === 'ENOENT') return fallback; throw e; }
}

function eventType(e) { return e.event?.type ?? e.surface ?? 'unknown'; }
function eventTime(e) { return e.timestamp ?? e.recordedAt ?? e.scannedAt ?? null; }

function summarizeAgent(def, events, candidates) {
  const relevant = def.types.length === 0 ? [] : events.filter(e => def.types.includes(eventType(e)));
  let status = relevant.reduce((cur, e) => maxStatus(cur, statusFromDecision(e.decision)), 'idle');
  if (def.id === 'rule-agent' && candidates.length > 0) status = 'warn';
  if (def.id === 'supervisor-agent' && relevant.some(e => e.decision === 'block')) status = 'block';
  const last = relevant.at(-1);
  return { ...def, status,
    eventCount: def.id === 'rule-agent' ? candidates.length : relevant.length,
    lastSeen: last ? eventTime(last) : null,
    currentTask: agentTask(def.id, relevant, candidates),
    recentEvents: relevant.slice(-3).reverse()
  };
}

function agentTask(id, events, candidates) {
  const n = events.length;
  if (id === 'vision-agent') {
    const h = events.some(e => (e.event?.evidence?.hiddenPrompts ?? []).length > 0);
    if (h) return 'Hidden prompt injection found';
    return n > 0 ? 'Analyzing extracted image text' : 'Image scan idle';
  }
  if (id === 'policy-agent') return n > 0 ? 'Applying policy rules' : 'Guardrail events idle';
  if (id === 'llm-review-agent') return n > 0 ? 'Reviewing ambiguous context with Claude' : 'Escalation idle';
  if (id === 'forensic-agent') return n > 0 ? 'Recording audit logs and evidence' : 'No recent evidence';
  if (id === 'rule-agent') return candidates.length > 0 ? 'Generating policy rule candidates' : 'No active rule candidates';
  if (id === 'supervisor-agent') return events.some(e => e.decision === 'block') ? 'Blocking risky workflow' : 'Monitoring decisions';
  return 'Idle';
}

function collectAlerts(events) {
  return events.flatMap(e => (e.findings ?? []).map(f => ({
    eventId: e.id, timestamp: eventTime(e), type: eventType(e), decision: e.decision,
    severity: f.severity, category: f.category, ruleId: f.id, rationale: f.rationale, match: f.match
  }))).filter(a => a.decision === 'block' || a.decision === 'warn').slice(-20).reverse();
}

function collectImageFindings(events) {
  return events
    .filter(e => ['image','vision_observation'].includes(eventType(e)))
    .filter(e => (e.findings ?? []).length > 0 || (e.event?.evidence?.hiddenPrompts ?? []).length > 0)
    .slice(-8).reverse()
    .map(e => {
      const ev = e.event?.evidence ?? {};
      return { eventId: e.id, timestamp: eventTime(e), decision: e.decision,
        imageId: ev.imageId, imageHash: ev.imageHash, imagePath: ev.imagePath, imageUrl: ev.imageUrl,
        extractedText: ev.extractedText ?? e.event?.text ?? '', confidence: ev.confidence,
        regions: ev.regions ?? [], findings: e.findings ?? [],
        hiddenPrompts: ev.hiddenPrompts ?? [], objects: ev.objects ?? []
      };
    });
}

function collectHiddenPromptDiscoveries(events) {
  return events
    .filter(e => ['image','vision_observation'].includes(eventType(e)))
    .flatMap(e => {
      const ev = e.event?.evidence ?? {};
      return (ev.hiddenPrompts ?? []).map(p => ({
        eventId: e.id, timestamp: eventTime(e), decision: e.decision,
        imagePath: ev.imagePath, imageUrl: ev.imageUrl, imageHash: ev.imageHash, prompt: p
      }));
    }).slice(-10).reverse();
}

function computeSafetyScore(events, candidates) {
  if (events.length === 0) return { score: 100, level: 'safe', label: 'Safe' };
  const now = Date.now();
  const RECENCY = 5 * 60 * 1000;
  let penalty = 0;
  for (const e of events) {
    const recent = now - Date.parse(e.timestamp ?? e.scannedAt ?? '') < RECENCY;
    if (e.decision === 'block') penalty += recent ? 25 : 15;
    else if (e.decision === 'warn') penalty += recent ? 8 : 4;
    penalty += (e.event?.evidence?.hiddenPrompts?.length ?? 0) * 20;
  }
  penalty += (Array.isArray(candidates) ? candidates.length : 0) * 3;
  const score = Math.max(0, Math.min(100, 100 - penalty));
  const level = score >= 80 ? 'safe' : score >= 50 ? 'caution' : score >= 20 ? 'danger' : 'critical';
  const label = { safe: 'Safe', caution: 'Caution', danger: 'Danger', critical: 'Critical' }[level];
  return { score, level, label };
}

function computeAgentStats(events) {
  const ROLES = ['runtime', 'qa', 'backend', 'security'];
  return ROLES.map(role => {
    const agentId = role === 'runtime' ? RUNTIME_HOOK_AGENT_ID : `agent-${role}`;
    const agentEvents = events.filter(e => dashboardAgentId(e) === agentId);
    const blockEvents = agentEvents.filter(e => e.decision === 'block');
    const ruleFreq = {};
    for (const e of blockEvents) {
      for (const f of (e.findings ?? [])) { ruleFreq[f.id] = (ruleFreq[f.id] ?? 0) + 1; }
    }
    const surfCounts = {};
    for (const e of agentEvents) { const t = e.surface ?? e.event?.type ?? 'unknown'; surfCounts[t] = (surfCounts[t] ?? 0) + 1; }
    return {
      agentId, role,
      total: agentEvents.length,
      block: blockEvents.length,
      warn: agentEvents.filter(e => e.decision === 'warn').length,
      allow: agentEvents.filter(e => e.decision === 'allow').length,
      blockRate: agentEvents.length ? blockEvents.length / agentEvents.length : 0,
      topRules: Object.entries(ruleFreq).sort((a, b) => b[1] - a[1]).slice(0, 5),
      surfaces: surfCounts
    };
  });
}

function summarizeCounts(events, candidates) {
  return {
    total: events.length,
    block: events.filter(e => e.decision === 'block').length,
    warn: events.filter(e => e.decision === 'warn').length,
    allow: events.filter(e => e.decision === 'allow').length,
    candidates: candidates.length,
    hiddenPrompts: events.reduce((n, e) => n + (e.event?.evidence?.hiddenPrompts?.length ?? 0), 0)
  };
}

function summarizeSurfaces(events) {
  const c = {};
  for (const e of events) { const t = eventType(e); c[t] = (c[t] ?? 0) + 1; }
  return c;
}

const FIVE_LAYERS = [
  { id: 'prompt', label: 'Prompt Guard', icon: '📝', surfaces: ['prompt'] },
  { id: 'shell',  label: 'Shell Guard',  icon: '⚡', surfaces: ['command'] },
  { id: 'es',     label: 'ES Guard',     icon: '🔒', surfaces: ['os'] },
  { id: 'output', label: 'Output Guard', icon: '📤', surfaces: ['output'] },
  { id: 'screen', label: 'Screen Watch', icon: '🖼', surfaces: ['image', 'vision_observation'] }
];

function buildLayerOverview(events, candidates) {
  return FIVE_LAYERS.map(layer => {
    const layerEvents = events.filter(e => layer.surfaces.includes(eventType(e)));
    const block = layerEvents.filter(e => e.decision === 'block').length;
    const warn = layerEvents.filter(e => e.decision === 'warn').length;
    const ruleSet = new Set();
    for (const e of layerEvents) {
      for (const f of e.findings ?? []) { if (f.id) ruleSet.add(f.id); }
    }
    const layerCandidates = candidates.filter(c => {
      const cSurface = c.rule?.surface ?? c.surface ?? '';
      return layer.surfaces.includes(cSurface);
    });
    return {
      ...layer,
      total: layerEvents.length,
      block,
      warn,
      topRule: ruleSet.size > 0 ? [...ruleSet][0] : null,
      ruleCount: ruleSet.size,
      candidateCount: layerCandidates.length
    };
  });
}

function collectTimeline(events, candidates) {
  const eventItems = events.map((event) => ({
    kind: 'event',
    timestamp: eventTime(event),
    title: `${event.decision?.toUpperCase() ?? 'EVENT'} ${eventType(event)}`,
    detail: event.event?.text ?? event.text ?? '',
    decision: event.decision,
    sessionId: event.event?.meta?.sessionId,
    agentId: event.event?.agentId,
    findingCount: event.findings?.length ?? 0
  }));

  const candidateItems = candidates.map((candidate) => ({
    kind: 'candidate',
    timestamp: candidate.generatedAt,
    title: `RULE CANDIDATE ${candidate.priority ?? ''}`.trim(),
    detail: candidate.rule?.id ?? candidate.id,
    decision: 'warn',
    sessionId: null,
    agentId: 'rule-agent',
    findingCount: candidate.evidence?.length ?? 0
  }));

  return [...eventItems, ...candidateItems]
    .filter((item) => item.timestamp)
    .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))
    .slice(0, 50);
}

function guardLayerLabel(surface) {
  return {
    image: 'Screen Watch',
    vision_observation: 'Screen Watch',
    prompt: 'Prompt Guard',
    llm: 'LLM Review',
    command: 'Shell Guard',
    output: 'Output Guard',
    os: 'ES Guard'
  }[surface] ?? `${surface} Guard`;
}

const layerDefinitions = [
  { id: 'prompt', label: 'Prompt Guard', surfaces: ['prompt'] },
  { id: 'shell', label: 'Shell Guard', surfaces: ['command'] },
  { id: 'es', label: 'ES Guard', surfaces: ['os'] },
  { id: 'output', label: 'Output Guard', surfaces: ['output'] },
  { id: 'screen', label: 'Screen Watch', surfaces: ['image', 'vision_observation'] }
];

function layerForSurface(surface) {
  return layerDefinitions.find(layer => layer.surfaces.includes(surface)) ?? null;
}

function buildLayerOverview(events) {
  const overview = layerDefinitions.map(layer => ({
    id: layer.id,
    label: layer.label,
    surfaces: layer.surfaces,
    total: 0,
    block: 0,
    warn: 0,
    allow: 0,
    topRule: null,
    latest: null,
    status: 'idle'
  }));
  const byId = Object.fromEntries(overview.map(layer => [layer.id, layer]));
  const ruleCounts = Object.fromEntries(overview.map(layer => [layer.id, {}]));

  for (const ev of events) {
    const surface = ev.surface ?? ev.event?.type ?? 'unknown';
    const layer = layerForSurface(surface);
    if (!layer) continue;
    const item = byId[layer.id];
    const decision = ev.decision ?? 'allow';
    item.total += 1;
    if (decision === 'block') item.block += 1;
    else if (decision === 'warn') item.warn += 1;
    else if (decision === 'allow') item.allow += 1;

    const ts = eventTime(ev);
    if (ts && (!item.latest || Date.parse(ts) > Date.parse(item.latest))) item.latest = ts;
    for (const finding of ev.findings ?? []) {
      if (!finding.id) continue;
      ruleCounts[layer.id][finding.id] = (ruleCounts[layer.id][finding.id] ?? 0) + 1;
    }
  }

  for (const item of overview) {
    item.status = item.block > 0 ? 'block' : item.warn > 0 ? 'warn' : item.total > 0 ? 'allow' : 'idle';
    item.topRule = Object.entries(ruleCounts[item.id]).sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;
  }
  return overview;
}

function taskOperation(ev) {
  const event = ev.event ?? {};
  const meta = event.meta ?? {};
  const surface = ev.surface ?? event.type ?? 'unknown';
  if (surface === 'os') {
    if (meta.operation === 'open') return `open ${meta.path ?? ''}`.trim();
    if (meta.operation === 'unlink') return `unlink ${meta.path ?? ''}`.trim();
    if (meta.operation === 'exec') return (meta.argv ?? []).join(' ') || meta.executable || 'exec';
    return meta.operation ?? 'os event';
  }
  if (surface === 'command') return event.text ?? ev.text ?? 'command';
  if (surface === 'output') return `output: ${event.text ?? ev.text ?? ''}`;
  if (surface === 'prompt') return `prompt: ${event.text ?? ev.text ?? ''}`;
  if (surface === 'image' || surface === 'vision_observation') {
    return event.evidence?.imagePath ? `image ${event.evidence.imagePath}` : `image: ${event.text ?? ev.text ?? ''}`;
  }
  if (surface === 'llm') return `llm: ${event.text ?? ev.text ?? ''}`;
  return event.text ?? ev.text ?? surface;
}

function taskFromEvent(ev) {
  const event = ev.event ?? {};
  const surface = ev.surface ?? event.type ?? 'unknown';
  const findings = ev.findings ?? [];
  return {
    id: ev.id,
    timestamp: eventTime(ev),
    operation: taskOperation(ev),
    surface,
    layer: guardLayerLabel(surface),
    decision: ev.decision ?? 'allow',
    findings,
    ruleId: findings[0]?.id ?? '',
    severity: findings[0]?.severity ?? '',
    pid: event.meta?.pid,
    path: event.meta?.path,
    text: event.text ?? ev.text ?? ''
  };
}

function buildAgentFlows(events) {
  const ROLES = ['runtime', 'qa', 'backend', 'security'];
  const RECENT_MS = 5 * 60 * 1000;
  const now = Date.now();
  return ROLES.map(role => {
    const agentId = role === 'runtime' ? RUNTIME_HOOK_AGENT_ID : `agent-${role}`;
    const agentEvents = events
      .filter(e => dashboardAgentId(e) === agentId)
      .sort((a, b) => Date.parse(eventTime(b) ?? '') - Date.parse(eventTime(a) ?? ''));
    const bySession = {};
    for (const ev of agentEvents) {
      const sid = ev.event?.meta?.sessionId ?? 'default';
      if (!bySession[sid]) bySession[sid] = [];
      bySession[sid].push(ev);
    }
    const sessionCount = Object.keys(bySession).length;
    const recentSessionCount = Object.values(bySession).filter(evts =>
      evts.some(e => now - Date.parse(e.timestamp ?? e.scannedAt ?? '') < RECENT_MS)
    ).length;
    const tasks = agentEvents.slice(0, 8).map(taskFromEvent);
    const overallDecision = tasks.some(t => t.decision === 'block') ? 'block'
      : tasks.some(t => t.decision === 'warn') ? 'warn'
      : tasks.length > 0 ? 'allow' : 'idle';
    return { role, agentId, overallDecision, tasks,
      eventCount: agentEvents.length, lastSeen: agentEvents[0] ? eventTime(agentEvents[0]) : null,
      sessionCount, recentSessionCount };
  });
}

function buildVisionFlow(events) {
  const imgEvents = events.filter(e => ['image', 'vision_observation'].includes(e.surface ?? e.event?.type ?? ''));
  if (imgEvents.length === 0) return null;
  const latest = imgEvents.at(-1);
  const ev = latest.event?.evidence ?? {};
  return {
    imagePath: ev.imagePath ?? null, imageHash: ev.imageHash ?? null,
    extractedText: ev.extractedText ?? (latest.event?.text ?? ''),
    hiddenPrompts: ev.hiddenPrompts ?? [], confidence: ev.confidence ?? null,
    regions: ev.regions ?? [], objects: ev.objects ?? [],
    decision: latest.decision, findings: latest.findings ?? [],
    timestamp: latest.timestamp ?? latest.scannedAt
  };
}

function candidateId(entry = {}) {
  return entry.id ?? entry.rule?.id ?? '';
}

function candidateRule(entry = {}) {
  return entry.rule ?? entry;
}

function candidateLayer(entry = {}) {
  const rule = candidateRule(entry);
  return entry.layer ?? guardLayerLabel(rule.appliesTo?.[0] ?? rule.appliesTo ?? 'policy');
}

function candidateScore(entry = {}) {
  const score = entry.metrics?.score;
  return typeof score === 'number' ? Math.round(score * 100) : null;
}

function buildSelfHealingModel({ events = [], candidates = [], pending = {}, shadow = {}, shadowEvents = [], approved = {} } = {}) {
  const candidateList = Array.isArray(candidates) ? candidates : candidates.candidates ?? [];
  const pendingRules = pending.rules ?? candidateList;
  const shadowRules = shadow.rules ?? [];
  const approvedRules = approved.rules ?? [];
  const riskyEvents = events.filter((event) => ['block', 'warn'].includes(event.decision));
  const shadowByRule = shadowEvents.reduce((acc, event) => {
    const id = event.ruleId;
    if (!id) return acc;
    if (!acc[id]) acc[id] = { events: 0, wouldBlock: 0, falsePositive: 0, recent: null };
    acc[id].events += 1;
    if (event.wouldDecision === 'block') acc[id].wouldBlock += 1;
    if (event.actualDecision === 'allow' && event.wouldDecision === 'block') acc[id].falsePositive += 1;
    acc[id].recent = acc[id].recent && Date.parse(acc[id].recent) > Date.parse(event.timestamp ?? '')
      ? acc[id].recent
      : event.timestamp;
    return acc;
  }, {});

  return {
    headline: 'Guardrails get stronger over time.',
    note: 'Rules stay in shadow mode until a human approves them.',
    loop: [
      { id: 'collect', label: 'Collect', value: riskyEvents.length, detail: 'risky events' },
      { id: 'analyze', label: 'Analyze', value: candidateList.length, detail: 'candidates' },
      { id: 'shadow', label: 'Shadow', value: shadowRules.length, detail: 'would-block tests' },
      { id: 'pending', label: 'Pending', value: pendingRules.length, detail: 'awaiting approval' },
      { id: 'applied', label: 'Applied', value: approvedRules.length, detail: 'active rules' }
    ],
    pending: pendingRules.map((entry) => ({
      id: candidateId(entry),
      status: entry.status ?? 'pending',
      layer: candidateLayer(entry),
      score: candidateScore(entry),
      falsePositive: entry.metrics?.false_positive,
      blockRate: entry.metrics?.block_rate,
      evidenceCount: entry.evidence?.length ?? entry.evidenceCount ?? 0,
      source: entry.reason ?? `Learned from ${entry.evidence?.length ?? entry.evidenceCount ?? 0} event(s).`,
      rule: candidateRule(entry),
      shadow: shadowByRule[candidateId(entry)] ?? { events: 0, wouldBlock: 0, falsePositive: 0, recent: null }
    })).slice(0, 12),
    shadow: shadowRules.map((entry) => ({
      id: candidateId(entry),
      layer: candidateLayer(entry),
      score: candidateScore(entry),
      status: entry.status ?? 'shadow',
      rule: candidateRule(entry),
      stats: shadowByRule[candidateId(entry)] ?? { events: 0, wouldBlock: 0, falsePositive: 0, recent: null }
    })).slice(0, 12),
    applied: approvedRules.map((rule) => ({
      id: rule.id,
      layer: guardLayerLabel(rule.appliesTo?.[0] ?? rule.appliesTo ?? 'policy'),
      severity: rule.severity,
      category: rule.category,
      pattern: rule.pattern
    })).slice(0, 12)
  };
}

export function buildDashboardModel({ events = [], candidates = [], state = {}, pending = {}, shadow = {}, shadowEvents = [], approved = {} } = {}) {
  const recentEvents = events.slice(-100);
  const candidateList = Array.isArray(candidates) ? candidates : candidates.candidates ?? [];
  const agents = agentDefinitions.map(def => summarizeAgent(def, recentEvents, candidateList));
  return {
    generatedAt: new Date().toISOString(),
    state,
    counts: summarizeCounts(recentEvents, candidateList),
    safetyScore: computeSafetyScore(recentEvents, candidateList),
    layerOverview: buildLayerOverview(recentEvents),
    agentStats: computeAgentStats(recentEvents),
    agents,
    edges: graphEdges.map(([from, to]) => ({ from, to })),
    runbook: threeAgentRunbook,
    agentFlows: buildAgentFlows(recentEvents),
    visionFlow: buildVisionFlow(recentEvents),
    alerts: collectAlerts(recentEvents),
    imageFindings: collectImageFindings(recentEvents),
    hiddenPromptDiscoveries: collectHiddenPromptDiscoveries(recentEvents),
    candidates: candidateList.slice(0, 8),
    selfHealing: buildSelfHealingModel({ events: recentEvents, candidates, pending, shadow, shadowEvents, approved }),
    timeline: collectTimeline(recentEvents, candidateList),
    events: recentEvents.slice(-100).reverse(),
    surfaceCounts: summarizeSurfaces(recentEvents),
    layerOverview: buildLayerOverview(recentEvents, candidateList)
  };
}

export async function readDashboardModel({ dataDir = '.404gent' } = {}) {
  const [events, candidates, state, pending, shadow, shadowEvents, approved] = await Promise.all([
    readJsonLines(join(dataDir, 'events.jsonl')),
    readJson(join(dataDir, 'rule-candidates.json'), { candidates: [] }),
    readJson(join(dataDir, 'state.json'), {}),
    readJson(join(dataDir, 'pending-rules.json'), { rules: [] }),
    readJson(join(dataDir, 'shadow-rules.json'), { rules: [] }),
    readJsonLines(join(dataDir, 'shadow-events.jsonl')),
    readJson(join(dataDir, 'approved-rules.json'), { rules: [] })
  ]);
  return buildDashboardModel({ events, candidates, state, pending, shadow, shadowEvents, approved });
}

function sendJson(res, body) {
  res.writeHead(200, { 'content-type':'application/json; charset=utf-8', 'cache-control':'no-store' });
  res.end(JSON.stringify(body));
}
function sendHtml(res) {
  res.writeHead(200, { 'content-type':'text/html; charset=utf-8' });
  res.end(renderHtml());
}
function mimeType(p) {
  const x = extname(p).toLowerCase();
  return { '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.gif':'image/gif', '.webp':'image/webp', '.svg':'image/svg+xml' }[x] ?? 'application/octet-stream';
}
function resolveEvidencePath(p) {
  const root = resolve(process.cwd());
  const abs = resolve(root, p);
  if (abs !== root && !abs.startsWith(root + sep)) throw new Error('Image path outside workspace.');
  return abs;
}
async function sendEvidenceImage(res, p) {
  if (!p) { res.writeHead(400); res.end('Missing path'); return; }
  const body = await readFile(resolveEvidencePath(p));
  res.writeHead(200, { 'content-type':mimeType(p), 'cache-control':'no-store' });
  res.end(body);
}

const MAX_UPLOAD_SIZE = 10 * 1024 * 1024;
const ALLOWED_IMAGE_TYPES = { '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.gif':'image/gif', '.webp':'image/webp' };

async function readRawBody(req, maxSize = MAX_UPLOAD_SIZE) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxSize) throw new Error(`파일이 너무 큽니다. 최대 ${maxSize / 1024 / 1024}MB까지 가능합니다.`);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function parseMultipartFormData(contentType, body) {
  const match = contentType.match(/boundary=(?:"([^"]+)"|([^\s;]+))/);
  if (!match) throw new Error('Missing multipart boundary.');
  const boundary = match[1] || match[2];
  const boundaryBuf = Buffer.from(`--${boundary}`);
  const parts = [];
  let start = body.indexOf(boundaryBuf);
  if (start === -1) throw new Error('No multipart boundary found in body.');
  while (true) {
    start += boundaryBuf.length;
    if (body[start] === 0x2D && body[start + 1] === 0x2D) break;
    start += 2;
    const headerEnd = body.indexOf(Buffer.from('\r\n\r\n'), start);
    if (headerEnd === -1) break;
    const headerStr = body.subarray(start, headerEnd).toString('utf8');
    const dataStart = headerEnd + 4;
    const nextBoundary = body.indexOf(boundaryBuf, dataStart);
    if (nextBoundary === -1) break;
    const data = body.subarray(dataStart, nextBoundary - 2);
    const headers = {};
    for (const line of headerStr.split('\r\n')) {
      const ci = line.indexOf(':');
      if (ci > 0) headers[line.slice(0, ci).toLowerCase().trim()] = line.slice(ci + 1).trim();
    }
    const disposition = headers['content-disposition'] || '';
    const nameMatch = disposition.match(/name="([^"]+)"/);
    const filenameMatch = disposition.match(/filename="([^"]+)"/);
    parts.push({ name: nameMatch?.[1] ?? '', filename: filenameMatch?.[1] ?? null, contentType: headers['content-type'] ?? 'application/octet-stream', data });
    start = nextBoundary;
  }
  return parts;
}

function sendJsonError(res, status, msg) {
  res.writeHead(status, { 'content-type':'application/json; charset=utf-8' });
  res.end(JSON.stringify({ error: msg }));
}

export function createDashboardServer({ dataDir = '.404gent' } = {}) {
  let _config = null;
  async function getConfig() { if (!_config) _config = await loadConfig(); return _config; }

  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname === '/api/events') {
        res.writeHead(200, { 'content-type':'text/event-stream; charset=utf-8', 'cache-control':'no-cache', 'connection':'keep-alive', 'x-accel-buffering':'no' });
        const push = async () => {
          try { res.write('data: ' + JSON.stringify(await readDashboardModel({ dataDir })) + '\n\n'); }
          catch (e) { res.write('data: ' + JSON.stringify({ error: e.message }) + '\n\n'); }
        };
        await push();
        const iv = setInterval(push, 1000);
        req.on('close', () => clearInterval(iv));
        return;
      }
      if (url.pathname === '/api/status') { sendJson(res, await readDashboardModel({ dataDir })); return; }
      if (url.pathname === '/api/image') { await sendEvidenceImage(res, url.searchParams.get('path')); return; }

      // ── Image Upload Scan ─────────────────────────────────────────────────
      if (req.method === 'POST' && url.pathname === '/api/scan-image') {
        const ct = req.headers['content-type'] || '';
        if (!ct.includes('multipart/form-data')) { sendJsonError(res, 400, 'Expected multipart/form-data'); return; }
        const rawBody = await readRawBody(req);
        const parts = parseMultipartFormData(ct, rawBody);
        const filePart = parts.find(p => p.name === 'image' && p.filename);
        if (!filePart) { sendJsonError(res, 400, 'No image file found. Use field name "image".'); return; }
        const ext = (filePart.filename.match(/\.[^.]+$/) || ['.bin'])[0].toLowerCase();
        const mediaType = ALLOWED_IMAGE_TYPES[ext];
        if (!mediaType) { sendJsonError(res, 400, `지원하지 않는 이미지: ${ext}. PNG, JPG, GIF, WebP만 가능합니다.`); return; }

        const uploadDir = join(dataDir, 'uploads');
        await mkdir(uploadDir, { recursive: true });
        const safeFilename = filePart.filename.replace(/[^a-zA-Z0-9._-]/g, '_');
        const savedPath = join(uploadDir, `${Date.now()}-${safeFilename}`);
        await writeFile(savedPath, filePart.data);

        const config = await getConfig();

        // 1) OCR 멀티패스 (Tesseract: 극한대비, CLAHE, 엣지, 임계값) → 숨겨진 텍스트 추출
        let ocrHiddenTexts = [];
        let ocrAllTexts = [];
        let preprocessResult = null;
        try {
          preprocessResult = await preprocessImage(savedPath, config, { quiet: true });
          const detections = preprocessResult.preprocessed?.detections ?? [];
          ocrHiddenTexts = detections.filter(d => d.kind === 'hidden_text').map(d => d.text);
          ocrAllTexts = detections.map(d => d.text);
        } catch (ocrErr) {
          console.error('OCR preprocessing failed (continuing with Vision API):', ocrErr.message);
        }

        // 2) Vision API (Claude) → 이미지 직접 분석
        const visionProvider = createVisionProviderFromConfig(config);
        const base64 = filePart.data.toString('base64');
        const visionResult = await visionProvider.analyzeImage({ base64, mediaType });

        // 3) 모든 소스에서 추출된 텍스트 결합 (공백+줄바꿈 양쪽으로 결합하여 패턴 매칭 향상)
        const ocrHiddenSentence = ocrHiddenTexts.join(' ');
        const ocrAllSentence = ocrAllTexts.join(' ');
        const scanInput = [
          ...visionResult.hiddenPrompts,
          ...(visionResult.regions ?? []).map(r => r.text).filter(Boolean),
          ocrHiddenSentence,
          ocrAllSentence
        ].filter(Boolean).join('\n') || '';

        const allHiddenPrompts = [
          ...visionResult.hiddenPrompts,
          ...(ocrHiddenSentence ? [ocrHiddenSentence] : [])
        ].filter(Boolean);

        // 4) 룰엔진 스캔
        let result = scanText({ surface: 'image', text: scanInput, config, evidence: {
          hiddenPrompts: allHiddenPrompts, objects: visionResult.objects,
          regions: visionResult.regions, imagePath: savedPath,
          ocrDetections: preprocessResult?.preprocessed?.detections,
          normalizedImagePath: preprocessResult?.normalizedPath
        }});

        // 5) Vision 결과 병합
        if (!visionResult.skipped) {
          const merged = mergeReports(result, visionResult, config);
          result = { ...merged, surface: 'image', text: scanInput,
            severity: merged.findings.length > 0 ? highestSeverity(merged.findings) : 'low',
            scannedAt: result.scannedAt };
        }

        await recordReport(result, config);
        sendJson(res, result);
        return;
      }

      if (url.pathname === '/' || url.pathname === '/dashboard') { sendHtml(res); return; }
      res.writeHead(404); res.end('Not found');
    } catch (e) { res.writeHead(500); res.end(JSON.stringify({ error: e.message })); }
  });
}

export async function startDashboardServer({ port = DEFAULT_PORT, dataDir = '.404gent' } = {}) {
  for (let p = port; p <= MAX_PORT; p++) {
    const server = createDashboardServer({ dataDir });
    const result = await new Promise((resolve, reject) => {
      server.once('error', e => { if (e.code === 'EADDRINUSE') { resolve(null); return; } reject(e); });
      server.listen(p, '127.0.0.1', () => resolve({ server, port: p }));
    });
    if (result) return result;
  }
  throw new Error(`No available port between ${port} and ${MAX_PORT}.`);
}

// ─── HTML ──────────────────────────────────────────────────────────────────────
function renderHtml() {
  return `<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>404gent · Agent Runtime</title>
<style>
:root{
  --bg:#f0f2f7;--panel:#fff;--ink:#111827;--muted:#6b7280;--border:#e5e7eb;
  --hdr:#0f172a;--hdr-border:#1e293b;
  --allow:#059669;--warn:#d97706;--block:#dc2626;--idle:#94a3b8;--inject:#7c3aed;--accent:#4f46e5;
  --c-image:#7c3aed;--c-prompt:#2563eb;--c-command:#d97706;--c-os:#e11d48;--c-output:#059669;--c-llm:#0891b2;--c-vision_observation:#7c3aed;
  --r:10px;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:"Pretendard Variable",ui-sans-serif,system-ui,-apple-system,"Apple SD Gothic Neo","Noto Sans KR",sans-serif;background:var(--bg);color:var(--ink);font-size:14px;line-height:1.5;}

/* Header */
header{position:sticky;top:0;z-index:100;background:var(--hdr);display:flex;align-items:stretch;border-bottom:1px solid var(--hdr-border);height:58px;}
.brand{display:flex;align-items:center;gap:10px;padding:0 20px;border-right:1px solid var(--hdr-border);min-width:200px;}
.brand-icon{font-size:24px;line-height:1;}
.brand h1{font-size:16px;font-weight:800;color:#f1f5f9;letter-spacing:-.02em;}
.brand p{font-size:11px;color:#64748b;margin-top:1px;}
nav.tabs{display:flex;align-items:stretch;flex:1;padding:0 6px;}
.tab-btn{height:100%;padding:0 18px;border:none;background:none;color:#64748b;font-size:13px;font-weight:600;cursor:pointer;border-bottom:2px solid transparent;transition:color .15s,border-color .15s;white-space:nowrap;font-family:inherit;}
.tab-btn:hover{color:#cbd5e1;}
.tab-btn.active{color:#f1f5f9;border-bottom-color:var(--accent);}
.live-badge{display:flex;align-items:center;gap:8px;padding:0 20px;border-left:1px solid var(--hdr-border);color:#64748b;font-size:12px;white-space:nowrap;}
.dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;}
.dot.live{background:var(--allow);animation:blink 2s infinite;}
.dot.err{background:var(--block);}
@keyframes blink{0%,100%{opacity:1;}50%{opacity:.25;}}

/* Metrics bar */
#metrics-bar{display:flex;background:var(--panel);border-bottom:1px solid var(--border);overflow-x:auto;}
.metric{display:flex;flex-direction:column;align-items:center;padding:10px 22px;border-right:1px solid var(--border);min-width:96px;}
.metric:last-child{border-right:none;}
.metric strong{font-size:28px;font-weight:800;line-height:1.1;letter-spacing:-.03em;}
.metric span{font-size:11px;color:var(--muted);margin-top:2px;text-transform:uppercase;letter-spacing:.04em;}
.metric.m-block strong{color:var(--block);}
.metric.m-warn strong{color:var(--warn);}
.metric.m-allow strong{color:var(--allow);}
.metric.m-inject strong{color:var(--inject);}

/* Tab panels */
.tab-panel{display:none;}.tab-panel.active{display:block;}

/* Overview layout */
.ov-wrap{display:grid;grid-template-columns:1fr 370px;gap:16px;padding:16px;max-width:1620px;margin:0 auto;}
.ov-main{display:flex;flex-direction:column;gap:16px;}
.ov-side{display:flex;flex-direction:column;gap:14px;}

/* Panels */
.panel{background:var(--panel);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;}
.panel-hd{display:flex;align-items:center;justify-content:space-between;padding:14px 16px 0;margin-bottom:10px;}
.panel-hd h2{font-size:12px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);}
.panel-bd{padding:0 16px 16px;}

/* Agent graph */
.graph-scroll{overflow-x:auto;padding:0 16px 16px;}
svg.graph{display:block;width:100%;min-width:960px;height:310px;}

/* SVG edges */
.g-edge{stroke:#d1d5db;stroke-width:1.5;fill:none;marker-end:url(#arr);}
.g-edge.active{stroke:var(--accent);stroke-width:2;stroke-dasharray:7 4;animation:flow .9s linear infinite;}
.g-edge.block-e{stroke:var(--block);stroke-width:2.5;stroke-dasharray:6 3;animation:flow .55s linear infinite;}
.g-edge.warn-e{stroke:var(--warn);stroke-width:2;stroke-dasharray:6 4;animation:flow .75s linear infinite;}
@keyframes flow{from{stroke-dashoffset:22;}to{stroke-dashoffset:0;}}

/* SVG nodes */
.g-node rect{fill:var(--panel);stroke:#cbd5e1;stroke-width:1.5;rx:10;}
.g-node.allow rect{stroke:var(--allow);stroke-width:2.5;}
.g-node.warn rect{stroke:var(--warn);stroke-width:3;filter:drop-shadow(0 0 6px rgba(217,119,6,.35));}
.g-node.block rect{stroke:var(--block);stroke-width:3.5;filter:drop-shadow(0 0 8px rgba(220,38,38,.45));}
.g-node text{fill:var(--ink);font-size:12px;font-family:inherit;}
.g-node .g-role{fill:var(--muted);font-size:10px;}
.g-node .g-st{font-size:10px;font-weight:800;letter-spacing:.04em;}
.g-st.allow{fill:var(--allow)}.g-st.warn{fill:var(--warn)}.g-st.block{fill:var(--block)}.g-st.idle{fill:var(--idle)}
.g-ind{r:6;}
.g-ind.idle{fill:var(--idle)}.g-ind.allow{fill:var(--allow)}.g-ind.warn{fill:var(--warn)}.g-ind.block{fill:var(--block);}
.g-ind.warn,.g-ind.block{animation:ind-pulse 1.2s ease-in-out infinite;}
@keyframes ind-pulse{0%,100%{opacity:1;}50%{opacity:.3;}}

/* Agent cards */
.ag-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;padding:0 16px 16px;}
.ag-card{border:1px solid var(--border);border-radius:9px;padding:13px;display:flex;flex-direction:column;gap:4px;transition:border-color .2s,background .2s,box-shadow .2s;}
.ag-card.allow{border-color:var(--allow);background:#f0fdf4;}
.ag-card.warn{border-color:var(--warn);background:#fffbeb;box-shadow:0 0 0 3px rgba(217,119,6,.1);}
.ag-card.block{border-color:var(--block);background:#fef2f2;box-shadow:0 0 0 3px rgba(220,38,38,.12);}
.ag-card-top{display:flex;align-items:center;justify-content:space-between;}
.ag-icon{font-size:20px;line-height:1;}
.ag-name{font-size:13px;font-weight:800;margin-top:5px;}
.ag-role{font-size:11px;color:var(--muted);}
.ag-task{font-size:11px;color:var(--ink);margin-top:7px;line-height:1.4;min-height:30px;}
.ag-meta{font-size:10px;color:var(--muted);margin-top:5px;}
.ag-recents{display:flex;flex-direction:column;gap:3px;margin-top:7px;border-top:1px solid var(--border);padding-top:6px;}
.ag-rec{font-size:10px;color:var(--muted);display:flex;align-items:center;gap:4px;overflow:hidden;}
.ag-rec code{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;}

/* ── Pill / Badge ── */
.pill{border-radius:999px;padding:2px 8px;font-size:11px;font-weight:700;border:1px solid transparent;}
.pill.block{color:var(--block);border-color:var(--block);background:#fef2f2;}
.pill.warn{color:var(--warn);border-color:var(--warn);background:#fffbeb;}
.pill.allow{color:var(--allow);border-color:var(--allow);background:#f0fdf4;}
.pill.idle{color:var(--idle);border-color:var(--idle);}
.pill.inject{color:var(--inject);border-color:var(--inject);background:#f5f3ff;}
.pill.sm{font-size:10px;padding:1px 6px;}
.badge{border-radius:4px;padding:1px 6px;font-size:10px;font-weight:700;text-transform:uppercase;}
.badge-image,.badge-vision_observation{background:#ede9fe;color:#6d28d9;}
.badge-prompt{background:#dbeafe;color:#1d4ed8;}
.badge-command{background:#fef3c7;color:#92400e;}
.badge-os{background:#fee2e2;color:#991b1b;}
.badge-output{background:#d1fae5;color:#065f46;}
.badge-llm{background:#cffafe;color:#0e7490;}
.badge-os{background:#ffe4e6;color:#9f1239;}
.badge-unknown{background:#f3f4f6;color:#6b7280;}
.badge-agent{background:#fce7f3;color:#9d174d;}

/* Sidebar */
.side-sec{background:var(--panel);border:1px solid var(--border);border-radius:var(--r);}
.side-sec.inject-sec{border-color:var(--inject);}
.side-hd{padding:12px 14px 0;margin-bottom:8px;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);}
.side-hd.inject-hd{color:var(--inject);}
.side-bd{padding:0 14px 14px;display:flex;flex-direction:column;gap:8px;}

.alert-card{border-left:3px solid var(--border);padding:8px 10px;background:#f9fafb;border-radius:0 6px 6px 0;}
.alert-card.block{border-left-color:var(--block);background:#fef2f2;}
.alert-card.warn{border-left-color:var(--warn);background:#fffbeb;}
.alert-rule{font-size:12px;font-weight:700;}
.alert-meta{font-size:11px;color:var(--muted);margin-top:2px;display:flex;align-items:center;gap:5px;flex-wrap:wrap;}
.alert-match code{background:#f3f4f6;border-radius:3px;padding:1px 5px;font-size:11px;color:var(--inject);}

.disc-card{border:1.5px solid var(--inject);border-radius:8px;padding:10px 12px;background:#f5f3ff;}
.disc-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:5px;}
.disc-title{font-size:11px;font-weight:900;color:var(--inject);text-transform:uppercase;letter-spacing:.06em;}
.disc-meta{font-size:11px;color:var(--muted);margin-bottom:5px;}
.disc-text{background:#fff;border:1px solid #ddd6fe;border-radius:5px;padding:7px 9px;}
.disc-text code{color:var(--inject);font-size:11px;word-break:break-all;}

.feed-item{display:flex;align-items:flex-start;gap:8px;padding:7px 0;border-bottom:1px solid var(--border);}
.feed-item:last-child{border-bottom:none;}
.feed-dot{width:20px;height:20px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:800;color:#fff;flex-shrink:0;margin-top:2px;}
.feed-dot.block{background:var(--block)}.feed-dot.warn{background:var(--warn)}.feed-dot.allow{background:var(--allow)}.feed-dot.idle{background:var(--idle)}
.feed-body{flex:1;min-width:0;}
.feed-row{display:flex;align-items:center;gap:5px;flex-wrap:wrap;}
.feed-ts{font-size:10px;color:var(--muted);}
.feed-txt{font-size:11px;color:var(--muted);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}

/* History tab */
.hist-wrap{padding:16px;max-width:1300px;margin:0 auto;}
.hist-toolbar{display:flex;align-items:center;gap:12px;background:var(--panel);border:1px solid var(--border);border-radius:var(--r);padding:12px 16px;margin-bottom:14px;flex-wrap:wrap;}
.tb-grp{display:flex;align-items:center;gap:6px;}
.tb-grp label{font-size:11px;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.04em;}
select{border:1px solid var(--border);border-radius:6px;padding:5px 10px;font-size:13px;background:var(--panel);color:var(--ink);cursor:pointer;font-family:inherit;}
.tb-count{font-size:12px;color:var(--muted);margin-left:auto;}
.hist-list{display:flex;flex-direction:column;gap:6px;}

.tl-row{background:var(--panel);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;cursor:pointer;transition:border-color .15s;}
.tl-row:hover{border-color:var(--accent);}
.tl-row.warn{border-left:4px solid var(--warn);}
.tl-row.allow{border-left:4px solid var(--allow);}
.tl-head{display:flex;align-items:center;gap:10px;padding:10px 14px;flex-wrap:wrap;}
.tl-ts{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums;min-width:72px;flex-shrink:0;}
.tl-dec{font-size:11px;font-weight:900;text-transform:uppercase;min-width:48px;flex-shrink:0;}
.tl-dec.block{color:var(--block)}.tl-dec.warn{color:var(--warn)}.tl-dec.allow{color:var(--allow)}
.tl-txt{font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;min-width:0;color:var(--muted);}
.tl-cnt{font-size:11px;color:var(--muted);white-space:nowrap;flex-shrink:0;}
.tl-detail{display:none;padding:0 14px 13px;border-top:1px solid var(--border);background:#fafafa;}
.tl-row.open .tl-detail{display:block;}
.tl-detail-hd{font-size:11px;color:var(--muted);padding:10px 0 8px;}
.tl-finding{display:flex;align-items:baseline;gap:6px;font-size:11px;padding:5px 0;border-bottom:1px solid var(--border);}
.tl-finding:last-of-type{border-bottom:none;}
.sev{border-radius:3px;padding:1px 5px;font-size:10px;font-weight:800;text-transform:uppercase;}
.sev.critical{background:#fef2f2;color:var(--block)}.sev.high{background:#fef3c7;color:#b45309}.sev.medium{background:#f0fdf4;color:#065f46}.sev.low{background:#f3f4f6;color:var(--muted)}
.tl-inject{font-size:11px;margin-top:9px;padding:8px 10px;background:#f5f3ff;border:1px solid #ddd6fe;border-radius:6px;}
.tl-inject strong{color:var(--inject);font-size:10px;text-transform:uppercase;letter-spacing:.05em;display:block;margin-bottom:5px;}
.tl-inject code{color:var(--inject);word-break:break-all;}

/* Image Forensics tab */
.foren-wrap{padding:16px;max-width:1300px;margin:0 auto;display:flex;flex-direction:column;gap:16px;}
.img-card{background:var(--panel);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;}
.img-card-hd{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:8px;}
.img-card-bd{padding:16px;display:grid;grid-template-columns:1fr 1fr;gap:16px;align-items:start;}
.img-frame{position:relative;border:1px solid var(--border);border-radius:8px;overflow:hidden;background:#0f172a;}
.img-frame img{display:block;width:100%;max-height:260px;object-fit:contain;}
.img-missing{display:none;padding:28px;text-align:center;color:var(--muted);font-size:12px;}
.bbox{position:absolute;border:2px solid var(--block);background:rgba(220,38,38,.13);pointer-events:none;}
.bbox.obj{border-color:var(--warn);background:rgba(217,119,6,.1);}
.bbox-lbl{position:absolute;top:-19px;left:0;font-size:9px;font-weight:800;color:#fff;background:var(--block);padding:1px 6px;border-radius:3px;white-space:nowrap;}
.bbox.obj .bbox-lbl{background:var(--warn);}
.img-info{display:flex;flex-direction:column;gap:10px;}
.inj-banner{border:2px solid var(--inject);border-radius:8px;background:#f5f3ff;padding:12px 14px;}
.inj-banner-ttl{font-size:10px;font-weight:900;color:var(--inject);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px;}
.inj-item{background:#fff;border:1px solid #ddd6fe;border-radius:5px;padding:7px 9px;margin-top:6px;}
.inj-item code{color:var(--inject);font-size:11px;word-break:break-all;}
.ocr{border:1px solid var(--border);border-radius:6px;background:#f9fafb;padding:8px;max-height:100px;overflow:auto;}
.ocr code{font-size:11px;color:var(--muted);}
.finding-list{display:flex;flex-direction:column;gap:4px;}
.finding-row{display:flex;align-items:baseline;gap:6px;font-size:11px;padding:5px 0;border-bottom:1px solid var(--border);}
.finding-row:last-child{border-bottom:none;}

/* Rule Engine tab */
.rule-wrap{padding:16px;max-width:1400px;margin:0 auto;display:flex;flex-direction:column;gap:16px;}
.rb-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;}
.rb-card{background:var(--panel);border:1px solid var(--border);border-radius:var(--r);padding:16px;}
.rb-icon{font-size:30px;margin-bottom:8px;}
.rb-title{font-size:13px;font-weight:800;margin-bottom:4px;}
.rb-obj{font-size:12px;color:var(--muted);line-height:1.55;margin-bottom:10px;}
.rb-lbl{font-size:10px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-top:10px;margin-bottom:3px;}
.rb-cmd{display:block;background:#f1f3f7;border:1px solid var(--border);border-radius:6px;padding:6px 10px;font-size:11px;word-break:break-all;}
.cand-list{display:flex;flex-direction:column;gap:8px;}
.cand-card{background:var(--panel);border:1px solid var(--border);border-radius:var(--r);padding:12px 14px;}
.cand-id{font-size:12px;font-weight:700;margin-bottom:4px;}
.cand-reason{font-size:11px;color:var(--muted);margin-bottom:6px;}
.cand-pat{background:#f1f3f7;border:1px solid var(--border);border-radius:5px;padding:5px 8px;font-size:11px;word-break:break-all;}
.surf-grid{display:flex;flex-wrap:wrap;gap:8px;}
.surf-card{border:1px solid var(--border);border-radius:8px;padding:10px 16px;background:var(--panel);}
.surf-card strong{display:block;font-size:22px;font-weight:800;margin-top:6px;}
.surf-card span{font-size:11px;color:var(--muted);}

/* Self-healing tab */
.self-wrap{padding:16px;max-width:1400px;margin:0 auto;display:flex;flex-direction:column;gap:16px;}
.self-hero{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:18px 20px;background:linear-gradient(90deg,#f8fafc,#fff);border:1px solid var(--border);border-radius:var(--r);}
.self-hero h2{font-size:18px;font-weight:900;margin-bottom:4px;}
.self-hero p{font-size:12px;color:var(--muted);}
.self-badge{font-size:11px;font-weight:800;color:#065f46;background:#d1fae5;border:1px solid #6ee7b7;border-radius:999px;padding:6px 10px;white-space:nowrap;}
.self-loop{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;padding:16px;}
.self-step{position:relative;border:1px solid var(--border);border-radius:8px;background:#fff;padding:14px;min-height:92px;}
.self-step:not(:last-child)::after{content:'→';position:absolute;right:-14px;top:34px;color:#94a3b8;font-weight:900;z-index:2;}
.self-step.active{border-color:#6ee7b7;background:#f0fdf4;}
.self-step-label{font-size:11px;text-transform:uppercase;letter-spacing:.06em;font-weight:800;color:var(--muted);}
.self-step-value{font-size:30px;font-weight:900;line-height:1.1;margin-top:6px;color:var(--ink);}
.self-step-detail{font-size:11px;color:var(--muted);margin-top:2px;}
.self-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;}
.self-card{border:1px solid var(--border);border-radius:var(--r);background:#fff;padding:14px;display:flex;flex-direction:column;gap:12px;}
.self-card-top{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;}
.self-rule-id{font-size:13px;font-weight:900;word-break:break-all;}
.self-layer{font-size:10px;font-weight:800;text-transform:uppercase;color:#4338ca;background:#e0e7ff;border-radius:999px;padding:3px 7px;white-space:nowrap;}
.self-score{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;}
.self-score-box{border:1px solid var(--border);border-radius:7px;padding:8px;background:#f8fafc;}
.self-score-box strong{display:block;font-size:18px;line-height:1;color:var(--ink);}
.self-score-box span{display:block;font-size:10px;color:var(--muted);text-transform:uppercase;margin-top:4px;}
.self-pattern{border:1px solid var(--border);border-radius:7px;background:#f8fafc;padding:8px;}
.self-pattern code{font-size:11px;word-break:break-all;color:var(--ink);}
.self-source{font-size:11px;color:var(--muted);line-height:1.45;}
.self-actions{display:flex;gap:8px;margin-top:auto;}
.self-btn{border:1px solid var(--border);background:#fff;border-radius:6px;padding:7px 10px;font-size:11px;font-weight:800;cursor:pointer;font-family:inherit;}
.self-btn:hover{background:#f8fafc;}
.self-btn.approve{background:#dcfce7;border-color:#86efac;color:#166534;}
.self-btn.reject{background:#fee2e2;border-color:#fca5a5;color:#991b1b;}
.self-btn.test{background:#eef2ff;border-color:#c7d2fe;color:#4338ca;}
.self-table{width:100%;border-collapse:collapse;font-size:12px;}
.self-table th,.self-table td{padding:9px 10px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top;}
.self-table th{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:800;background:#f8fafc;}
.self-result{font-size:12px;color:var(--muted);padding:0 16px 16px;}
@media(max-width:900px){.self-loop{grid-template-columns:1fr;}.self-step:not(:last-child)::after{display:none;}.self-hero{align-items:flex-start;flex-direction:column;}}

/* Shared */
.empty{font-size:12px;color:var(--muted);padding:12px 0;}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;}
.lbl-sm{font-size:10px;font-weight:800;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px;display:block;}

@media(max-width:1100px){
  .ov-wrap{grid-template-columns:1fr;}
  .ag-grid{grid-template-columns:repeat(2,1fr);}
  .rb-grid,.img-card-bd{grid-template-columns:1fr;}
}
@media(max-width:680px){
  .ag-grid{grid-template-columns:1fr;}
  nav.tabs .tab-btn{padding:0 10px;font-size:12px;}
}

/* Updated overview layout */
.ov-new-wrap{padding:16px;display:flex;flex-direction:column;gap:16px;}
.ov-section{}
.afc-empty{padding:24px;text-align:center;color:var(--muted);font-size:13px;}

/* 3-agent parallel grid */
.agent-flows-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px;padding:16px;}
@media(max-width:900px){.agent-flows-grid{grid-template-columns:1fr;}}

/* Layer overview */
.layer-overview-grid{display:grid;grid-template-columns:repeat(5,minmax(150px,1fr));gap:12px;padding:0 16px 16px;}
.layer-card{border:1.5px solid var(--border);border-radius:8px;background:#fff;padding:12px;display:flex;flex-direction:column;gap:10px;min-width:0;}
.layer-card.block{border-color:#fca5a5;background:#fff1f2;}
.layer-card.warn{border-color:#fcd34d;background:#fffbeb;}
.layer-card.allow{border-color:#6ee7b7;background:#f0fdf4;}
.layer-card.idle{background:#f8fafc;color:var(--muted);}
.layer-card-top{display:flex;align-items:center;justify-content:space-between;gap:8px;}
.layer-name{font-size:13px;font-weight:800;color:var(--ink);}
.layer-card.idle .layer-name{color:var(--muted);}
.layer-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;}
.layer-stat{border:1px solid var(--border);border-radius:6px;background:rgba(255,255,255,.75);padding:6px;text-align:center;}
.layer-stat strong{display:block;font-size:18px;line-height:1.1;}
.layer-stat span{display:block;font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-top:2px;}
.layer-meta{display:flex;flex-direction:column;gap:4px;font-size:11px;color:var(--muted);min-width:0;}
.layer-meta code{font-size:10px;background:transparent;color:inherit;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:block;}
@media(max-width:1200px){.layer-overview-grid{grid-template-columns:repeat(auto-fit,minmax(180px,1fr));}}

/* Agent columns */
.afc-col{border:2px solid var(--border);border-radius:var(--r);overflow:hidden;background:#fff;}
.afc-col.warn{border-color:#fcd34d;}
.afc-col.allow{border-color:#6ee7b7;}
.afc-col.idle{border-color:var(--border);}
.afc-header{display:flex;align-items:center;gap:10px;padding:12px 14px;background:var(--bg);border-bottom:1px solid var(--border);}
.afc-icon{font-size:20px;line-height:1;}
.afc-name{font-size:13px;font-weight:700;color:var(--ink);}
.afc-sub{font-size:11px;color:var(--muted);margin-top:1px;}
.afc-status{margin-left:auto;flex-shrink:0;}
.afc-pipeline{padding:10px 10px;display:flex;flex-direction:column;align-items:stretch;gap:8px;max-height:300px;overflow:auto;}
.afc-meta{padding:8px 14px;font-size:11px;color:var(--muted);border-top:1px solid var(--border);background:var(--bg);}

/* Agent task logs */
.task-row{display:grid;grid-template-columns:56px minmax(0,1fr) auto;gap:8px;align-items:start;border:1px solid var(--border);border-left-width:4px;border-radius:8px;background:#fff;padding:8px 10px;}
.task-row.allow{border-left-color:var(--allow);}
.task-row.warn{border-left-color:var(--warn);background:#fffbeb;}
.task-row.block{border-left-color:var(--block);background:#fff1f2;}
.task-ts{font-size:11px;color:var(--muted);white-space:nowrap;padding-top:2px;}
.task-main{min-width:0;display:flex;flex-direction:column;gap:4px;}
.task-op code{font-size:11px;background:transparent;word-break:break-all;color:var(--ink);font-weight:700;}
.task-meta{display:flex;align-items:center;gap:6px;flex-wrap:wrap;font-size:10px;color:var(--muted);}
.task-pid{font-size:10px;color:var(--muted);}
.task-rule{display:flex;align-items:center;gap:6px;min-width:0;}
.task-rule code{font-size:10px;color:#991b1b;background:transparent;font-weight:700;word-break:break-all;}

/* Pipeline nodes */
.pf-node{border:1.5px solid var(--border);border-radius:8px;padding:10px 12px;background:#fff;position:relative;}
.pf-node.allow{border-color:#6ee7b7;background:#f0fdf4;}
.pf-node.warn{border-color:#fcd34d;background:#fffbeb;}
.pf-node.block{border-color:#fca5a5;background:#fff1f2;}
.pf-node.idle{border-color:var(--border);background:#f8fafc;opacity:.55;}
.pf-node-top{display:flex;align-items:center;gap:6px;margin-bottom:4px;}
.pf-node-icon{font-size:14px;}
.pf-node-label{font-size:12px;font-weight:600;color:var(--ink);flex:1;}
.pf-text{font-size:11px;color:var(--muted);margin-top:3px;word-break:break-all;}
.pf-text code{font-size:10px;background:transparent;}
.pf-block-detail{margin-top:6px;padding:6px 8px;background:#fee2e2;border-radius:5px;font-size:11px;}
.pf-block-detail code{font-size:10px;color:#b91c1c;font-weight:700;}
.pf-rationale{margin-top:2px;color:#991b1b;font-size:10px;line-height:1.4;}
.pf-arrow{text-align:center;color:#94a3b8;font-size:16px;line-height:1;padding:3px 0;}

/* Vision pipeline */
.vision-flow-wrap{display:flex;align-items:flex-start;gap:0;padding:16px;overflow-x:auto;}
.vf-stage{display:flex;flex-direction:column;align-items:center;min-width:150px;}
.vf-node{border:2px solid var(--border);border-radius:10px;padding:12px 14px;background:#fff;text-align:center;width:140px;}
.vf-node.block{border-color:#fca5a5;background:#fff1f2;}
.vf-node.allow{border-color:#6ee7b7;background:#f0fdf4;}
.vf-node-icon{font-size:22px;margin-bottom:4px;}
.vf-node-label{font-size:12px;font-weight:600;color:var(--ink);}
.vf-node-detail{font-size:10px;color:var(--muted);margin-top:3px;line-height:1.4;}
.vf-connector{display:flex;align-items:center;padding:0 4px;color:#94a3b8;font-size:18px;margin-top:20px;}
.vf-hidden-prompts{margin-top:12px;padding:10px 14px;background:#fdf2f8;border:1px solid #f0abfc;border-radius:8px;font-size:11px;}
.vf-hidden-prompts strong{color:#7c3aed;display:block;margin-bottom:4px;}
.vf-hidden-prompts code{font-size:10px;color:#6b21a8;display:block;margin-top:2px;word-break:break-all;}
.vf-empty{padding:20px 16px;color:var(--muted);font-size:12px;}

/* Alert rows */
.ov-alerts-row{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;}
@media(max-width:900px){.ov-alerts-row{grid-template-columns:1fr;}}
.ov-alerts-row .side-sec{background:var(--panel);border:1px solid var(--border);border-radius:var(--r);}
.ov-alerts-row .side-hd{font-size:12px;font-weight:700;padding:10px 14px;border-bottom:1px solid var(--border);}
.ov-alerts-row .side-bd{padding:8px;max-height:220px;overflow-y:auto;}

/* Safety score gauge */
.risk-gauge{display:flex;flex-direction:column;align-items:center;padding:8px 24px;border-right:2px solid var(--border);min-width:100px;}
.gauge-ring{width:52px;height:52px;border-radius:50%;display:flex;align-items:center;justify-content:center;position:relative;}
.gauge-ring::after{content:'';width:38px;height:38px;border-radius:50%;background:var(--panel);position:absolute;}
.gauge-score{position:relative;z-index:1;font-size:16px;font-weight:900;line-height:1;}
.gauge-label{font-size:10px;text-transform:uppercase;letter-spacing:.06em;margin-top:4px;font-weight:700;}
.gauge-safe{color:var(--allow);}.gauge-caution{color:var(--warn);}.gauge-danger{color:var(--block);}.gauge-critical{color:#7f1d1d;}

/* Toast alerts */
#toast-container{position:fixed;top:66px;right:16px;z-index:200;display:flex;flex-direction:column;gap:8px;pointer-events:none;max-width:400px;}
.toast{pointer-events:auto;background:#fff;border:2px solid var(--border);border-radius:10px;padding:14px 18px;box-shadow:0 8px 24px rgba(0,0,0,.12);animation:toast-in .3s ease-out,toast-out .3s ease-in 4.7s forwards;display:flex;align-items:flex-start;gap:12px;}
.toast.block{border-color:var(--block);background:linear-gradient(135deg,#fef2f2,#fff);}
.toast.warn{border-color:var(--warn);background:linear-gradient(135deg,#fffbeb,#fff);}
.toast-icon{font-size:24px;flex-shrink:0;}
.toast-body{flex:1;}
.toast-title{font-size:13px;font-weight:800;}
.toast-title.block{color:var(--block);}.toast-title.warn{color:var(--warn);}
.toast-detail{font-size:11px;color:var(--muted);margin-top:4px;line-height:1.4;}
.toast-severity{font-size:10px;font-weight:800;text-transform:uppercase;padding:2px 6px;border-radius:3px;margin-top:6px;display:inline-block;}
.toast-severity.critical{background:#fef2f2;color:var(--block);}.toast-severity.high{background:#fef3c7;color:#b45309;}
.toast-severity.medium{background:#f0fdf4;color:#065f46;}.toast-severity.low{background:#f3f4f6;color:var(--muted);}
@keyframes toast-in{from{opacity:0;transform:translateX(40px);}to{opacity:1;transform:translateX(0);}}
@keyframes toast-out{from{opacity:1;}to{opacity:0;transform:translateY(-10px);}}

/* Action banner */
.action-banner{display:flex;align-items:center;gap:14px;padding:14px 20px;border-radius:var(--r);font-size:13px;font-weight:600;}
.action-banner.critical{background:linear-gradient(90deg,#fef2f2,#fff1f2);border:2px solid var(--block);color:#991b1b;}
.action-banner.warning{background:linear-gradient(90deg,#fffbeb,#fef3c7);border:2px solid var(--warn);color:#92400e;}
.action-banner.safe{background:linear-gradient(90deg,#f0fdf4,#ecfdf5);border:1px solid var(--allow);color:#065f46;}
.action-banner-icon{font-size:24px;flex-shrink:0;}
.action-banner-text{flex:1;}
.action-banner-actions{display:flex;gap:8px;}
.action-banner-btn{padding:6px 14px;border-radius:6px;border:none;font-size:12px;font-weight:700;cursor:pointer;font-family:inherit;}
.action-banner-btn.primary{background:var(--block);color:#fff;}.action-banner-btn.primary:hover{background:#b91c1c;}
.action-banner-btn.secondary{background:#fff;border:1px solid var(--border);color:var(--ink);}

/* History agent subtabs */
.hist-agent-tabs{display:flex;gap:4px;background:var(--panel);border:1px solid var(--border);border-radius:var(--r);padding:6px;margin-bottom:12px;}
.hist-agent-tab{padding:8px 16px;border:none;background:none;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;color:var(--muted);transition:all .15s;font-family:inherit;}
.hist-agent-tab:hover{background:#f1f5f9;color:var(--ink);}
.hist-agent-tab.active{background:var(--accent);color:#fff;}
.hist-agent-summary{display:flex;align-items:center;gap:16px;background:var(--panel);border:1px solid var(--border);border-radius:var(--r);padding:16px 20px;margin-bottom:14px;}
.has-icon{font-size:32px;}
.has-info{flex:1;}
.has-name{font-size:16px;font-weight:800;}
.has-stats{display:flex;gap:20px;margin-top:8px;}
.has-stat{text-align:center;}
.has-stat-val{font-size:22px;font-weight:800;line-height:1;}
.has-stat-val.block{color:var(--block);}.has-stat-val.warn{color:var(--warn);}.has-stat-val.allow{color:var(--allow);}
.has-stat-lbl{font-size:10px;color:var(--muted);text-transform:uppercase;margin-top:2px;}
.has-rate{display:flex;flex-direction:column;align-items:center;padding:8px 16px;border-left:2px solid var(--border);margin-left:auto;}
.has-rate-val{font-size:28px;font-weight:900;}.has-rate-lbl{font-size:10px;color:var(--muted);text-transform:uppercase;}
.has-rules{margin-top:8px;font-size:11px;color:var(--muted);}
.has-rules code{font-size:10px;background:#f3f4f6;padding:1px 4px;border-radius:3px;}

/* Time groups */
.tl-group-header{display:flex;align-items:center;gap:10px;padding:8px 14px;margin:14px 0 6px;font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid var(--border);}
.tl-group-blocks{color:var(--block);font-weight:800;}
.tl-group-warns{color:var(--warn);font-weight:800;margin-left:4px;}

/* Block emphasis */
.tl-row.block{border-left:4px solid var(--block);background:#fef2f2;}
.tl-row.block .tl-head{background:linear-gradient(90deg,#fef2f2,transparent 60%);}
.tl-row.block.recent{animation:block-pulse 2s ease-in-out 3;}
@keyframes block-pulse{0%,100%{box-shadow:inset 0 0 0 1px rgba(220,38,38,.15);}50%{box-shadow:inset 0 0 0 2px rgba(220,38,38,.4),0 0 12px rgba(220,38,38,.1);}}

/* Agent detail expansion panel */
.agent-detail-panel{grid-column:1/-1;background:var(--panel);border:2px solid var(--accent);border-radius:var(--r);padding:20px;animation:adp-slide .25s ease-out;}
@keyframes adp-slide{from{opacity:0;max-height:0;}to{opacity:1;max-height:800px;}}
.adp-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;}
.adp-header h3{font-size:14px;font-weight:800;}
.adp-close{border:none;background:none;font-size:18px;cursor:pointer;color:var(--muted);padding:4px 8px;}
.adp-close:hover{color:var(--ink);}
.adp-stats-row{display:flex;gap:24px;margin-bottom:16px;padding:12px 0;border-bottom:1px solid var(--border);}
.adp-stat{text-align:center;min-width:60px;}
.adp-stat-val{font-size:28px;font-weight:800;}
.adp-stat-lbl{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;}
.adp-section{margin-top:16px;}
.adp-section h4{font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:8px;}
.rule-bar{display:flex;align-items:center;gap:8px;margin-bottom:6px;font-size:11px;}
.rule-bar-fill{height:14px;border-radius:3px;background:var(--block);min-width:4px;}
.rule-bar code{font-size:10px;color:var(--muted);}
.surf-bar-wrap{height:18px;border-radius:4px;overflow:hidden;display:flex;background:#f3f4f6;}
.surf-bar-seg{height:100%;display:flex;align-items:center;justify-content:center;font-size:9px;font-weight:700;color:#fff;min-width:20px;}
.adp-events{max-height:260px;overflow-y:auto;display:flex;flex-direction:column;gap:4px;margin-top:8px;}

/* Agent column block glow */
.afc-col.block{border-color:#fca5a5;animation:afc-block-glow 2s ease-in-out infinite;}
@keyframes afc-block-glow{0%,100%{box-shadow:0 0 0 0 rgba(220,38,38,0);}50%{box-shadow:0 0 16px 4px rgba(220,38,38,.15);}}
.afc-col{cursor:pointer;transition:transform .1s,box-shadow .15s;}
.afc-col:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.08);}
.afc-mini-stats{display:flex;gap:8px;font-size:11px;font-weight:800;margin-top:4px;}

/* History agent split layout */
.hist-agent-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;}
@media(max-width:1000px){.hist-agent-grid{grid-template-columns:1fr;}}
.hist-agent-col{background:var(--panel);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;display:flex;flex-direction:column;}
.hist-agent-col.has-block{border-color:#fca5a5;}
.hist-agent-col.has-warn{border-color:#fcd34d;}
.hac-header{padding:12px 14px;border-bottom:1px solid var(--border);background:var(--bg);display:flex;align-items:center;gap:10px;}
.hac-icon{font-size:22px;}
.hac-info{flex:1;}
.hac-name{font-size:13px;font-weight:800;}
.hac-sub{font-size:10px;color:var(--muted);}
.hac-stats{display:flex;gap:6px;align-items:center;}
.hac-stat{text-align:center;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:800;line-height:1.3;}
.hac-stat.block{background:#fef2f2;color:var(--block);}.hac-stat.warn{background:#fffbeb;color:var(--warn);}.hac-stat.allow{background:#f0fdf4;color:var(--allow);}
.hac-stat-n{font-size:16px;display:block;}
.hac-body{flex:1;overflow-y:auto;max-height:500px;padding:6px;}
.hac-body .tl-row{margin-bottom:4px;}
.hac-empty{padding:32px 16px;text-align:center;color:var(--muted);font-size:12px;}
.hac-footer{padding:8px 14px;border-top:1px solid var(--border);text-align:center;}
.hac-footer button{border:none;background:none;color:var(--accent);font-size:11px;font-weight:700;cursor:pointer;font-family:inherit;padding:4px 8px;border-radius:4px;}
.hac-footer button:hover{background:#eef2ff;}
</style>
</head>
<body>

<header>
  <div class="brand">
    <span class="brand-icon">⬡</span>
    <div>
      <h1>404gent</h1>
      <p>Multimodal AI Guardrail Runtime</p>
    </div>
  </div>
  <nav class="tabs" id="tab-nav">
    <button class="tab-btn active" data-tab="overview">Overview</button>
    <button class="tab-btn" data-tab="history">History</button>
    <button class="tab-btn" data-tab="forensics">Image Forensics</button>
    <button class="tab-btn" data-tab="self-healing">Self-Healing</button>
    <button class="tab-btn" data-tab="rules">Rule Engine</button>
  </nav>
  <div class="live-badge">
    <span class="dot live" id="live-dot"></span>
    <span id="updated">Connecting...</span>
  </div>
</header>

<div id="metrics-bar"></div>
<div id="toast-container"></div>

<!-- Overview -->
<div class="tab-panel active" id="panel-overview">
  <div class="ov-new-wrap">

    <div id="action-banner" style="display:none;"></div>

    <!-- Layer overview -->
    <div class="panel ov-section">
      <div class="panel-hd">
        <h2>5-Layer Defense Overview</h2>
      </div>
      <div id="layer-overview" class="layer-overview-grid"></div>
    </div>

    <!-- LLM agent pipeline -->
    <div class="panel ov-section">
      <div class="panel-hd">
        <h2>🤖 LLM Agent Pipeline <span style="font-size:12px;font-weight:400;color:var(--muted);">3 agents running in parallel</span></h2>
      </div>
      <div id="agent-flows" class="agent-flows-grid">
        <div class="afc-empty">Run an agent to display task logs here.</div>
      </div>
    </div>

    <!-- Vision detection pipeline -->
    <div class="panel ov-section">
      <div class="panel-hd">
        <h2>👁 Vision Image Detection Pipeline <span style="font-size:12px;font-weight:400;color:var(--muted);">Automatic detection on image input</span></h2>
      </div>
      <div id="vision-flow">
        <div class="afc-empty"><code>node src/cli.js scan-image --file &lt;image-path&gt;</code> to display detection results.</div>
      </div>
    </div>

    <!-- Side alerts -->
    <div class="ov-alerts-row">
      <div class="side-sec inject-sec" id="disc-sec">
        <div class="side-hd inject-hd">Prompt Injection Detection</div>
        <div class="side-bd" id="disc-list"></div>
      </div>
      <div class="side-sec">
        <div class="side-hd">Security Alerts</div>
        <div class="side-bd" id="alert-list"></div>
      </div>
      <div class="side-sec">
        <div class="side-hd">Recent Activity</div>
        <div class="side-bd" id="feed-list"></div>
      </div>
    </div>

  </div>
</div>

<!-- History -->
<div class="tab-panel" id="panel-history">
  <div class="hist-wrap">
    <div class="hist-agent-tabs" id="hist-agent-tabs">
      <button class="hist-agent-tab active" data-agent="">All Timeline</button>
      <button class="hist-agent-tab" data-agent="claude-code-hook">🧩 Runtime Hook</button>
      <button class="hist-agent-tab" data-agent="agent-qa">🔍 QA Agent</button>
      <button class="hist-agent-tab" data-agent="agent-backend">⚙️ Backend Agent</button>
      <button class="hist-agent-tab" data-agent="agent-security">🛡 Security Agent</button>
    </div>
    <div class="hist-agent-summary" id="hist-agent-summary" style="display:none;"></div>
    <div class="hist-toolbar">
      <div class="tb-grp">
        <label>Decision</label>
        <select id="f-dec">
          <option value="">All</option>
          <option value="block">Blocked</option>
          <option value="warn">Warning</option>
          <option value="allow">Allowed</option>
        </select>
      </div>
      <div class="tb-grp">
        <label>Surface</label>
        <select id="f-surf">
          <option value="">All</option>
          <option value="image">image</option>
          <option value="vision_observation">vision_observation</option>
          <option value="prompt">prompt</option>
          <option value="command">command</option>
          <option value="os">os</option>
          <option value="output">output</option>
          <option value="llm">llm</option>
        </select>
      </div>
      <div class="tb-grp">
        <label>Agent</label>
        <select id="f-agent">
          <option value="">All</option>
          <option value="claude-code-hook">Runtime Hook</option>
          <option value="agent-qa">QA Agent</option>
          <option value="agent-backend">Backend Agent</option>
          <option value="agent-security">Security Agent</option>
        </select>
      </div>
      <span class="tb-count" id="hist-count"></span>
    </div>
    <div class="hist-list" id="hist-list"></div>
  </div>
</div>

<!-- Image Forensics -->
<div class="tab-panel" id="panel-forensics">
  <div class="foren-wrap">
    <div class="panel" id="upload-panel">
      <div class="panel-hd"><h2>이미지 업로드 스캔</h2><span style="font-size:11px;color:var(--muted);">PNG, JPG, GIF, WebP (최대 10MB)</span></div>
      <div class="panel-bd" style="padding:16px;">
        <div id="drop-zone">
          <div style="font-size:36px;margin-bottom:8px;">📂</div>
          <div style="font-size:13px;font-weight:600;color:var(--ink);">이미지를 드래그하거나 클릭하여 업로드</div>
          <div style="font-size:11px;color:var(--muted);margin-top:4px;">Vision AI + 룰 엔진으로 보안 위협을 자동 탐지합니다</div>
          <input type="file" id="file-input" accept="image/png,image/jpeg,image/gif,image/webp" style="display:none;">
        </div>
        <div id="upload-status" style="margin-top:12px;display:none;">
          <div id="upload-progress" style="display:flex;align-items:center;gap:10px;padding:10px;background:#f8fafc;border-radius:8px;">
            <span class="upload-spinner"></span>
            <span id="upload-msg" style="font-size:12px;color:var(--muted);">이미지 분석 중...</span>
          </div>
        </div>
        <div id="upload-result" style="margin-top:12px;display:none;"></div>
      </div>
    </div>
    <div id="foren-content"></div>
  </div>
</div>

<!-- Self-Healing -->
<div class="tab-panel" id="panel-self-healing">
  <div class="self-wrap" id="self-content"></div>
</div>

<!-- Rule Engine -->
<div class="tab-panel" id="panel-rules">
  <div class="rule-wrap" id="rule-content"></div>
</div>

<script>
// ── State ─────────────────────────────────────────────────────────────────────
let lastModel = null;
let activeTab = 'overview';
let historyAgentFilter = '';
let seenEventIds = new Set();

const ST_LABEL = { idle:'Idle', allow:'Allowed', warn:'Warning', block:'Blocked' };
const ST_EN    = { idle:'IDLE', allow:'ALLOW', warn:'WARN', block:'BLOCK' };
const SEV_CLS  = { critical:'critical', high:'high', medium:'medium', low:'low' };
const AGENT_LABEL = {'claude-code-hook':'Runtime Hook','agent-qa':'QA','agent-backend':'Backend','agent-security':'Security'};
const SURF_COLORS = {prompt:'#2563eb',command:'#d97706',output:'#059669',llm:'#0891b2',image:'#7c3aed'};
const AGENT_ALIASES = {runtime:'claude-code-hook',hook:'claude-code-hook','claude-code-hook':'claude-code-hook',qa:'agent-qa','agent-qa':'agent-qa',backend:'agent-backend','agent-backend':'agent-backend',security:'agent-security','agent-security':'agent-security'};

function h(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function fmt(v){return v?new Date(v).toLocaleTimeString('ko-KR',{hour12:false}):'—';}
function fmtFull(v){return v?new Date(v).toLocaleString('ko-KR',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}):'—';}
function surf(e){return e.event?.type??e.surface??'unknown';}
function normalizeAgentId(v){const raw=String(v??'').trim();return raw?(AGENT_ALIASES[raw]||AGENT_ALIASES[raw.toLowerCase()]||raw):'';}
function agentFromSource(s){const m=String(s??'').match(/^agent:([^:]+):os$/);return m?m[1]:'';}
function agentIdFor(e){return normalizeAgentId(e.event?.agentId??e.event?.meta?.agent??agentFromSource(e.event?.source)??(e.event?.source==='claude-code-hook'?'claude-code-hook':''));}
function bdg(s){return '<span class="badge badge-'+h(s)+'">'+h(s)+'</span>';}
function sevPill(s){return '<span class="sev '+h(SEV_CLS[s]||'low')+'">'+h(s)+'</span>';}

// ── Tab switching ─────────────────────────────────────────────────────────────
function switchToTab(tab){
  activeTab=tab;
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.toggle('active',b.dataset.tab===activeTab));
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.toggle('active',p.id==='panel-'+activeTab));
  if(lastModel)renderAll(lastModel);
}
document.getElementById('tab-nav').addEventListener('click',e=>{
  const btn=e.target.closest('.tab-btn');
  if(!btn)return;
  switchToTab(btn.dataset.tab);
});

document.getElementById('f-dec').addEventListener('change',()=>{if(lastModel)renderHistory(lastModel);});
document.getElementById('f-surf').addEventListener('change',()=>{if(lastModel)renderHistory(lastModel);});
document.getElementById('f-agent').addEventListener('change',()=>{if(lastModel)renderHistory(lastModel);});
document.addEventListener('click',e=>{const r=e.target.closest('.tl-row');if(r)r.classList.toggle('open');});

// ── History agent subtabs ────────────────────────────────────────────────────
document.getElementById('hist-agent-tabs').addEventListener('click',e=>{
  const btn=e.target.closest('.hist-agent-tab');
  if(!btn)return;
  historyAgentFilter=btn.dataset.agent;
  document.querySelectorAll('.hist-agent-tab').forEach(b=>b.classList.toggle('active',b.dataset.agent===historyAgentFilter));
  document.getElementById('f-agent').value=historyAgentFilter;
  if(lastModel)renderHistory(lastModel);
});

// ── Agent detail click handling ──────────────────────────────────────────────
document.addEventListener('click',e=>{
  const selfBtn=e.target.closest('.self-btn[data-action][data-rule]');
  if(selfBtn){handleSelfHealingAction(selfBtn);return;}
  const col=e.target.closest('.afc-col[data-agent-id]');
  if(col){toggleAgentDetail(col.dataset.agentId);return;}
  const closeBtn=e.target.closest('.adp-close');
  if(closeBtn){const panel=closeBtn.closest('.agent-detail-panel');if(panel)panel.remove();return;}
  const bannerBtn=e.target.closest('.action-banner-btn');
  if(bannerBtn&&bannerBtn.dataset.tab){switchToTab(bannerBtn.dataset.tab);}
});

// ── Metrics and gauge ────────────────────────────────────────────────────────
function renderMetrics(c, ss){
  ss=ss||{score:100,level:'safe',label:'Safe'};
  const gaugeColor=ss.level==='safe'?'var(--allow)':ss.level==='caution'?'var(--warn)':'var(--block)';
  const gaugeHtml='<div class="risk-gauge gauge-'+ss.level+'" style="--gauge-pct:'+ss.score+'">'+
    '<div class="gauge-ring" style="background:conic-gradient('+gaugeColor+' '+ss.score+'%,#e5e7eb '+ss.score+'%);">'+
      '<span class="gauge-score" style="color:'+gaugeColor+'">'+ss.score+'</span>'+
    '</div>'+
    '<span class="gauge-label" style="color:'+gaugeColor+'">'+h(ss.label)+'</span>'+
  '</div>';
  const items=[['All',c.total,''],['Blocked',c.block,'m-block'],['Warning',c.warn,'m-warn'],['Allowed',c.allow,'m-allow'],['Rule Candidates',c.candidates,''],['Hidden Prompts',c.hiddenPrompts,'m-inject']];
  document.getElementById('metrics-bar').innerHTML=gaugeHtml+items.map(([l,v,cl])=>'<div class="metric '+cl+'"><strong>'+v+'</strong><span>'+l+'</span></div>').join('');
}

// ── 5-layer defense overview ────────────────────────────────────────────────
function renderLayerOverview(model){
  const layers=model.layerOverview||[];
  const el=document.getElementById('layer-overview');
  if(!el)return;
  el.innerHTML=layers.map(layer=>{
    const st=layer.status||'idle';
    const topRule=layer.topRule?'<code title="'+h(layer.topRule)+'">'+h(layer.topRule)+'</code>':'<span>None</span>';
    return '<div class="layer-card '+h(st)+'">'+
      '<div class="layer-card-top"><div class="layer-name">'+h(layer.label)+'</div><span class="pill sm '+h(st)+'">'+h(ST_EN[st]||st)+'</span></div>'+
      '<div class="layer-stats">'+
        '<div class="layer-stat"><strong>'+h(layer.total||0)+'</strong><span>Total</span></div>'+
        '<div class="layer-stat"><strong>'+h(layer.block||0)+'</strong><span>Block</span></div>'+
        '<div class="layer-stat"><strong>'+h(layer.warn||0)+'</strong><span>Warn</span></div>'+
      '</div>'+
      '<div class="layer-meta"><div>Top rule '+topRule+'</div><div>Latest '+h(fmt(layer.latest))+'</div></div>'+
    '</div>';
  }).join('')||'<div class="empty">No layer data.</div>';
}

// ── Parallel LLM agent task logs ─────────────────────────────────────────────
const ROLE_META={
  runtime: {label:'Runtime Hook',       icon:'🧩', sub:'Claude Code hook events'},
  qa:      {label:'Agent 1 · QA',       icon:'🔍', sub:'Frontend / Design QA'},
  backend: {label:'Agent 2 · Backend',   icon:'⚙️',  sub:'Backend / Integration'},
  security:{label:'Agent 3 · Security',  icon:'🛡',  sub:'Security / Analyst'}
};
const STAGE_META={
  image:             {icon:'🖼', label:'Image scanned'},
  vision_observation:{icon:'👁', label:'Vision Analysis'},
  prompt:            {icon:'📝', label:'Prompt Scan'},
  llm:               {icon:'🤖', label:'LLM Handoff'},
  command:           {icon:'⚡', label:'Command Execution'},
  output:            {icon:'📤', label:'Output Inspection'}
};
function renderAgentFlows(model){
  const flows=(model.agentFlows||[]).filter(f=>f.eventCount>0);
  const stats=model.agentStats||[];
  if(!flows.length){document.getElementById('agent-flows').innerHTML='<div class="afc-empty" style="padding:32px;font-size:13px;color:var(--muted);">실행 중인 에이전트가 없습니다.</div>';return;}
  document.getElementById('agent-flows').innerHTML=flows.map(flow=>{
    const m=ROLE_META[flow.role]||{label:flow.role,icon:'🤖',sub:''};
    const od=flow.overallDecision||'idle';
    const st=stats.find(s=>s.role===flow.role)||{block:0,warn:0};
    const miniStats=(st.block>0?'<span style="color:var(--block);">'+st.block+' Blocked</span>':'')+
                    (st.warn>0?'<span style="color:var(--warn);">'+st.warn+' Warning</span>':'');
    const tasksHtml=(flow.tasks||[]).map(task=>{
      const firstFinding=task.findings?.[0]||{};
      const decisionLabel=task.decision==='warn'?'Detected':ST_LABEL[task.decision]||task.decision;
      const ruleHtml=firstFinding.id
        ?'<div class="task-rule">'+sevPill(firstFinding.severity||'medium')+'<code>'+h(firstFinding.id)+'</code></div>'
        :'';
      const pidHtml=task.pid?'<span class="task-pid">pid '+h(task.pid)+'</span>':'';
      return '<div class="task-row '+h(task.decision)+'">'+
        '<div class="task-ts">'+fmt(task.timestamp)+'</div>'+
        '<div class="task-main">'+
          '<div class="task-op"><code>'+h((task.operation||'').slice(0,72))+'</code></div>'+
          '<div class="task-meta">'+bdg(task.surface)+'<span>'+h(task.layer)+'</span>'+pidHtml+'</div>'+
          ruleHtml+
        '</div>'+
        '<span class="pill sm '+h(task.decision)+'">'+h(decisionLabel)+'</span>'+
      '</div>';
    }).join('');
    const sessionBadge=flow.sessionCount>1
      ?'<span title="'+flow.sessionCount+' sessions with recent task logs" style="font-size:10px;background:#e0e7ff;color:#4338ca;border-radius:4px;padding:1px 5px;margin-left:4px;">Sessions '+flow.sessionCount+(flow.recentSessionCount>1?' · '+flow.recentSessionCount+' active':'')+'</span>'
      :'';
    return '<div class="afc-col '+od+'" data-agent-id="'+flow.agentId+'">'+
      '<div class="afc-header">'+
        '<span class="afc-icon">'+m.icon+'</span>'+
        '<div><div class="afc-name">'+label+recentDot+'</div><div class="afc-sub">'+sub+'</div>'+(miniStats?'<div class="afc-mini-stats">'+miniStats+'</div>':'')+'</div>'+
        '<span class="afc-status pill '+od+'">'+ST_LABEL[od]+'</span>'+
      '</div>'+
      '<div class="afc-pipeline">'+(tasksHtml||'<div class="afc-empty" style="padding:20px;font-size:12px;">No task logs</div>')+'</div>'+
      '<div class="afc-meta">Tasks '+flow.eventCount+' · '+(flow.lastSeen?fmt(flow.lastSeen):'Not run')+'</div>'+
    '</div>';
  }).join('');
}

// ── Vision Image Detection Pipeline ─────────────────────────────────────────────
function renderVisionFlow(model){
  const vf=model.visionFlow;
  const el=document.getElementById('vision-flow');
  if(!vf){el.innerHTML='<div class="vf-empty"><code>node src/cli.js scan-image --file &lt;image-path&gt;</code> to display detection results. Demo: <code>npm run demo:image</code> → <code>node src/cli.js scan-image --file examples/generated/attack-image.svg</code></div>';return;}
  const stages=[
    {icon:'🖼',label:'Image Upload',detail:vf.imagePath?vf.imagePath.split('/').at(-1):'No file',cls:''},
    {icon:'👁',label:'OCR / VLM Analysis',detail:'Confidence: '+(vf.confidence!=null?(vf.confidence*100).toFixed(0)+'%':'—')+(vf.hiddenPrompts.length?' · hidden text '+(vf.hiddenPrompts.length)+'':''),cls:vf.hiddenPrompts.length?'block':'allow'},
    {icon:'🛡',label:'Rule-based Check',detail:(vf.findings[0]?.id||'Rules applied'),cls:vf.decision},
    {icon:vf.decision==='block'?'🚫':'✅',label:vf.decision==='block'?'Blocked':'Allowed',detail:vf.findings[0]?.rationale?.slice(0,50)||'',cls:vf.decision}
  ];
  const stagesHtml=stages.map((s,i)=>
    (i>0?'<div class="vf-connector">→</div>':'')+
    '<div class="vf-stage">'+
      '<div class="vf-node '+s.cls+'">'+
        '<div class="vf-node-icon">'+s.icon+'</div>'+
        '<div class="vf-node-label">'+h(s.label)+'</div>'+
        '<div class="vf-node-detail">'+h(s.detail)+'</div>'+
      '</div>'+
    '</div>'
  ).join('');
  const promptsHtml=vf.hiddenPrompts.length?
    '<div class="vf-hidden-prompts"><strong>🔴 Hidden Prompt Injection ('+(vf.hiddenPrompts.length)+' found)</strong>'+
    vf.hiddenPrompts.map(p=>'<code>'+h(p.slice(0,80))+'</code>').join('')+'</div>':'';
  const extractedHtml=vf.extractedText?
    '<div style="padding:10px 16px 0;font-size:11px;color:var(--muted);">Extracted Text: <code style="font-size:10px;">'+h(vf.extractedText.slice(0,100))+'</code></div>':'';
  el.innerHTML='<div class="vision-flow-wrap">'+stagesHtml+'</div>'+promptsHtml+extractedHtml;
}

// ── Injection detection sidebar ──────────────────────────────────────────────
function renderDiscoveries(items){
  document.getElementById('disc-list').innerHTML=items.length
    ?items.map(d=>'<div class="disc-card"><div class="disc-top"><span class="disc-title">Injection found</span><span class="pill inject sm">Hidden Prompts</span></div><div class="disc-meta">'+fmt(d.timestamp)+(d.imagePath?' · '+h(d.imagePath.split('/').at(-1)):'')+'</div><div class="disc-text"><code>'+h(d.prompt)+'</code></div></div>').join('')
    :'<div class="empty">No prompt injections detected.</div>';
}

// ── Security alerts sidebar ──────────────────────────────────────────────────
function renderAlerts(alerts){
  document.getElementById('alert-list').innerHTML=alerts.length
    ?alerts.slice(0,8).map(a=>'<div class="alert-card '+a.decision+'"><div class="alert-rule">'+h(a.ruleId)+'</div><div class="alert-meta">'+bdg(a.type)+sevPill(a.severity)+'<span>'+fmt(a.timestamp)+'</span></div><div style="margin-top:4px;"><code>'+h((a.match||'').slice(0,80))+'</code></div></div>').join('')
    :'<div class="empty">No security alerts.</div>';
}

// ── Recent activity feed ─────────────────────────────────────────────────────
function renderFeed(events){
  const icons={block:'Blocked',warn:'Warning',allow:'Allowed',idle:'•'};
  document.getElementById('feed-list').innerHTML=events.slice(0,10).map(e=>{
    const d=e.decision||'idle';
    return '<div class="feed-item"><div class="feed-dot '+d+'">'+(d==='allow'?'✓':d==='block'?'✕':'!')+'</div><div class="feed-body"><div class="feed-row">'+bdg(surf(e))+'<span class="pill sm '+d+'">'+ST_LABEL[d]+'</span><span class="feed-ts">'+fmt(e.timestamp)+'</span></div><div class="feed-txt"><code>'+h((e.event?.text??e.text??'').slice(0,60))+'</code></div></div></div>';
  }).join('')||'<div class="empty">No events.</div>';
}

// ── History tab ──────────────────────────────────────────────────────────────
function groupByTimeWindow(events,windowMin){
  windowMin=windowMin||30;
  const groups=[];let cur=null;
  for(const e of events){
    const ts=Date.parse(e.timestamp??e.scannedAt??'');
    if(!cur||cur.start-ts>windowMin*60000){cur={start:ts,end:ts,events:[e]};groups.push(cur);}
    else{cur.events.push(e);cur.end=ts;}
  }
  return groups;
}

function renderAgentSummaryHeader(agentId,events){
  const el=document.getElementById('hist-agent-summary');
  if(!agentId){el.style.display='none';return;}
  const ae=events.filter(e=>agentIdFor(e)===agentId);
  const bk=ae.filter(e=>e.decision==='block').length;
  const wn=ae.filter(e=>e.decision==='warn').length;
  const al=ae.filter(e=>e.decision==='allow').length;
  const rate=ae.length?((bk/ae.length)*100).toFixed(0):'0';
  const ruleFreq={};
  for(const e of ae.filter(e=>e.decision==='block')){for(const f of(e.findings??[])){ruleFreq[f.id]=(ruleFreq[f.id]??0)+1;}}
  const topRules=Object.entries(ruleFreq).sort((a,b)=>b[1]-a[1]).slice(0,3);
  const role=agentId==='claude-code-hook'?'runtime':agentId.replace('agent-','');
  const m=ROLE_META[role]||{icon:'🤖',label:agentId,sub:''};
  el.style.display='flex';
  el.innerHTML='<div class="has-icon">'+m.icon+'</div>'+
    '<div class="has-info"><div class="has-name">'+h(m.label)+' <span style="font-size:12px;font-weight:400;color:var(--muted);">'+h(m.sub)+'</span></div>'+
      '<div class="has-stats">'+
        '<div class="has-stat"><div class="has-stat-val block">'+bk+'</div><div class="has-stat-lbl">Blocked</div></div>'+
        '<div class="has-stat"><div class="has-stat-val warn">'+wn+'</div><div class="has-stat-lbl">Warning</div></div>'+
        '<div class="has-stat"><div class="has-stat-val allow">'+al+'</div><div class="has-stat-lbl">Allowed</div></div>'+
      '</div>'+
      (topRules.length?'<div class="has-rules">Top rules: '+topRules.map(([r,n])=>'<code>'+h(r)+'</code>('+n+')').join(' · ')+'</div>':'')+
    '</div>'+
    '<div class="has-rate"><div class="has-rate-val" style="color:'+(bk>0?'var(--block)':'var(--allow)')+'">'+rate+'%</div><div class="has-rate-lbl">Block rate</div></div>';
}

function renderEventRow(e,now){
  const d=e.decision||'allow',s=surf(e);
  const aid=agentIdFor(e);
  const aLbl=AGENT_LABEL[aid]??aid;
  const agentBdg=aid?'<span class="badge badge-agent" title="'+h(aid)+'">'+h(aLbl)+'</span>':'';
  const recent=d==='block'&&(now-Date.parse(e.timestamp??''))<30000;
  const txt=(e.event?.text??e.text??'').slice(0,100);
  const findings=e.findings??[];
  const topSev=findings[0]?.severity;
  const sevBdg=topSev&&d==='block'?sevPill(topSev):'';
  const hPrompts=e.event?.evidence?.hiddenPrompts??[];
  const fRows=findings.map(f=>'<div class="tl-finding">'+sevPill(f.severity)+'<strong>'+h(f.id)+'</strong><span style="color:var(--muted);">'+h(f.rationale||'')+'</span></div>').join('');
  const injSec=hPrompts.length?'<div class="tl-inject"><strong>Hidden Prompt Source ('+hPrompts.length+')</strong>'+hPrompts.map(p=>'<code>'+h(p)+'</code>').join('<br>')+'</div>':'';
  return '<div class="tl-row '+d+(recent?' recent':'')+'"><div class="tl-head"><span class="tl-ts">'+fmt(e.timestamp??e.recordedAt)+'</span><span class="tl-dec '+d+'">'+ST_LABEL[d]+'</span>'+sevBdg+bdg(s)+agentBdg+'<span class="tl-txt"><code>'+h(txt)+'</code></span><span class="tl-cnt">found '+findings.length+'</span></div><div class="tl-detail"><div class="tl-detail-hd"><strong>Event ID:</strong> '+h(e.id||'—')+' · <strong>Agent:</strong> '+h(aid||'—')+' · <strong>Time:</strong> '+fmtFull(e.timestamp)+(e.event?.evidence?.imagePath?' · <strong>Image:</strong> '+h(e.event.evidence.imagePath):'')+'</div>'+(fRows?'<div class="finding-list">'+fRows+'</div>':'')+injSec+'</div></div>';
}

function renderAgentColumnInner(label,sub,icon,ae,now,maxRows){
  const bk=ae.filter(e=>e.decision==='block').length;
  const wn=ae.filter(e=>e.decision==='warn').length;
  const al=ae.filter(e=>e.decision==='allow').length;
  const borderCls=bk>0?'has-block':wn>0?'has-warn':'';
  const cap=maxRows||20;
  const shown=ae.slice(0,cap);
  let rowsHtml='';
  if(!shown.length){
    rowsHtml='<div class="hac-empty">No events for this agent.</div>';
  } else {
    const groups=groupByTimeWindow(shown,30);
    for(const g of groups){
      if(groups.length>1){
        const gBk=g.events.filter(e=>e.decision==='block').length;
        const gWn=g.events.filter(e=>e.decision==='warn').length;
        rowsHtml+='<div class="tl-group-header" style="font-size:10px;padding:3px 8px;">'+
          '<span>'+fmt(new Date(g.end).toISOString())+' ~ '+fmt(new Date(g.start).toISOString())+'</span>'+
          '<span>'+g.events.length+'</span>'+
          (gBk?'<span class="tl-group-blocks">'+gBk+' Blocked</span>':'')+
          (gWn?'<span class="tl-group-warns">'+gWn+' Warning</span>':'')+
        '</div>';
      }
      rowsHtml+=g.events.map(e=>renderEventRow(e,now)).join('');
    }
  }
  const moreBtn=ae.length>shown.length
    ?'<div class="hac-footer"><button onclick="document.querySelectorAll(\\'[data-agent=&quot;'+agentId+'&quot;]\\').forEach(b=>b.click())">+'+( ae.length-shown.length)+' more</button></div>':'';
  return '<div class="hist-agent-col '+borderCls+'">'+
    '<div class="hac-header">'+
      '<span class="hac-icon">'+icon+'</span>'+
      '<div class="hac-info"><div class="hac-name">'+h(label)+'</div><div class="hac-sub">'+h(sub)+'</div></div>'+
      '<div class="hac-stats">'+
        (bk?'<div class="hac-stat block"><span class="hac-stat-n">'+bk+'</span>Blocked</div>':'')+
        (wn?'<div class="hac-stat warn"><span class="hac-stat-n">'+wn+'</span>Warning</div>':'')+
        '<div class="hac-stat allow"><span class="hac-stat-n">'+al+'</span>Allowed</div>'+
      '</div>'+
    '</div>'+
    '<div class="hac-body">'+rowsHtml+'</div>'+
  '</div>';
}

function renderAgentColumn(agentId,events,now,maxRows){
  const role=agentId==='claude-code-hook'?'runtime':agentId.replace('agent-','');
  const m=ROLE_META[role]||{icon:'🤖',label:agentId,sub:''};
  const ae=events.filter(e=>agentIdFor(e)===agentId);
  return renderAgentColumnInner(m.label,m.sub,m.icon,ae,now,maxRows);
}

function renderAgentColumnForSession(agentId,sessionEvents,now,maxRows,shortSid){
  const m=ROLE_META.runtime;
  const label=m.label+' · '+shortSid;
  return renderAgentColumnInner(label,'세션 '+shortSid,m.icon,sessionEvents,now,maxRows);
}

function sessionIdFor(e){return e.event?.meta?.sessionId??'';}

function buildRuntimeSessionTabs(events){
  const tabsEl=document.getElementById('hist-agent-tabs');
  // Remove old dynamic runtime tabs
  tabsEl.querySelectorAll('.hist-agent-tab[data-rt-session]').forEach(b=>b.remove());
  // Collect runtime sessions
  const rtEvents=events.filter(e=>agentIdFor(e)==='claude-code-hook');
  const sessions={};
  for(const e of rtEvents){
    const sid=sessionIdFor(e)||'default';
    if(!sessions[sid])sessions[sid]={count:0,lastTs:''};
    sessions[sid].count++;
    const ts=e.timestamp??e.scannedAt??'';
    if(ts>sessions[sid].lastTs)sessions[sid].lastTs=ts;
  }
  const sorted=Object.entries(sessions).sort((a,b)=>b[1].lastTs.localeCompare(a[1].lastTs));
  // Insert runtime session tabs after "전체" button
  const allBtn=tabsEl.querySelector('[data-agent=""]');
  const qaBtn=tabsEl.querySelector('[data-agent="agent-qa"]');
  if(sorted.length<=1){
    // Single or no session: show classic single tab
    const btn=document.createElement('button');
    btn.className='hist-agent-tab'+(historyAgentFilter==='claude-code-hook'?' active':'');
    btn.dataset.agent='claude-code-hook';
    btn.dataset.rtSession='1';
    btn.textContent='🧩 Runtime Hook'+(sorted.length?(' ('+sorted[0][1].count+')'):'');
    tabsEl.insertBefore(btn,qaBtn);
  } else {
    for(const [sid,info] of sorted){
      const short=sid.length>8?sid.slice(0,8):sid;
      const filterId='rt:'+sid;
      const btn=document.createElement('button');
      btn.className='hist-agent-tab'+(historyAgentFilter===filterId?' active':'');
      btn.dataset.agent=filterId;
      btn.dataset.rtSession='1';
      btn.textContent='🧩 '+short+' ('+info.count+')';
      btn.title='Runtime Hook · 세션 '+sid;
      tabsEl.insertBefore(btn,qaBtn);
    }
  }
  // Also update the f-agent dropdown
  const sel=document.getElementById('f-agent');
  sel.querySelectorAll('option[data-rt-session]').forEach(o=>o.remove());
  const qaOpt=sel.querySelector('option[value="agent-qa"]');
  if(sorted.length<=1){
    const opt=document.createElement('option');
    opt.value='claude-code-hook';opt.dataset.rtSession='1';
    opt.textContent='Runtime Hook'+(sorted.length?(' ('+sorted[0][1].count+')'):'');
    sel.insertBefore(opt,qaOpt);
  } else {
    for(const [sid,info] of sorted){
      const short=sid.length>8?sid.slice(0,8):sid;
      const opt=document.createElement('option');
      opt.value='rt:'+sid;opt.dataset.rtSession='1';
      opt.textContent='Runtime · '+short+' ('+info.count+')';
      sel.insertBefore(opt,qaOpt);
    }
  }
}

function filterEventsByAgent(events,fa){
  if(fa.startsWith('rt:')){
    const sid=fa.slice(3);
    return events.filter(e=>agentIdFor(e)==='claude-code-hook'&&sessionIdFor(e)===sid);
  }
  return events.filter(e=>agentIdFor(e)===fa);
}

function renderHistory(model){
  const events=model.events||[];
  const fd=document.getElementById('f-dec').value;
  const fs=document.getElementById('f-surf').value;
  const fa=document.getElementById('f-agent').value||historyAgentFilter;
  const now=Date.now();

  buildRuntimeSessionTabs(events);

  const preFiltered=events.filter(e=>(!fd||e.decision===fd)&&(!fs||surf(e)===fs));

  // ── All mode: split by agent columns ───────────────────────────────────────
  if(!fa){
    renderAgentSummaryHeader('',events);
    document.getElementById('hist-count').textContent='Total '+preFiltered.length;
    const agents=['claude-code-hook','agent-qa','agent-backend','agent-security'];
    const unassigned=preFiltered.filter(e=>!agents.includes(agentIdFor(e)));
    let html='<div class="hist-agent-grid">'+
      agents.map(aid=>renderAgentColumn(aid,preFiltered,now,20)).join('')+
    '</div>';
    if(unassigned.length){
      html+='<div style="margin-top:16px;"><div class="tl-group-header"><span>Unassigned Events</span><span>'+unassigned.length+'</span></div>';
      html+=unassigned.map(e=>renderEventRow(e,now)).join('');
      html+='</div>';
    }
    if(!preFiltered.length){
      html='<div style="text-align:center;padding:48px;color:var(--muted);font-size:13px;">No events match the filters.</div>';
    }
    document.getElementById('hist-list').innerHTML=html;
    return;
  }

  // ── Single agent mode: summary header and grouped timeline ────────────────
  renderAgentSummaryHeader(fa,events);
  const filtered=preFiltered.filter(e=>agentIdFor(e)===fa);
  document.getElementById('hist-count').textContent='Total '+filtered.length;

  if(!filtered.length){
    document.getElementById('hist-list').innerHTML='<div style="text-align:center;padding:48px;color:var(--muted);font-size:13px;">No events for this agent.</div>';
    return;
  }

  const groups=groupByTimeWindow(filtered,30);
  let html='';
  for(const g of groups){
    const gBlocks=g.events.filter(e=>e.decision==='block').length;
    const gWarns=g.events.filter(e=>e.decision==='warn').length;
    html+='<div class="tl-group-header"><span>'+fmt(new Date(g.end).toISOString())+' ~ '+fmt(new Date(g.start).toISOString())+'</span>'+
      '<span>'+g.events.length+'</span>'+
      (gBlocks?'<span class="tl-group-blocks">'+gBlocks+' Blocked</span>':'')+
      (gWarns?'<span class="tl-group-warns">'+gWarns+' Warning</span>':'')+
    '</div>';
    for(const e of g.events){ html+=renderEventRow(e,now); }
  }
  document.getElementById('hist-list').innerHTML=html;
}

// ── Image forensics tab ──────────────────────────────────────────────────────
function renderForensics(model){
  const disc=model.hiddenPromptDiscoveries||[];
  const imgs=model.imageFindings||[];
  let html='';
  html+='<div class="panel"><div class="panel-hd"><h2>Prompt Injection Detection</h2><span class="pill inject">'+disc.length+' found</span></div><div class="panel-bd">';
  html+=disc.length
    ?disc.map(d=>'<div class="disc-card" style="margin-bottom:10px;"><div class="disc-top"><span class="disc-title">Injection found</span><span class="pill inject sm">Hidden Prompts</span></div><div class="disc-meta">'+fmtFull(d.timestamp)+(d.imagePath?' · '+h(d.imagePath):'')+'</div><div class="disc-text"><code>'+h(d.prompt)+'</code></div></div>').join('')
    :'<div class="empty">No prompt injections were found in analyzed images.<br><code style="font-size:11px;">scan-image --file &lt;image&gt;</code> to analyze an image.</div>';
  html+='</div></div>';
  if(imgs.length){
    html+=imgs.map(item=>{
      const iSrc=item.imageUrl||(item.imagePath?'/api/image?path='+encodeURIComponent(item.imagePath):'');
      const rBoxes=(item.regions||[]).filter(r=>r.threat).map(r=>'<div class="bbox" style="left:'+((r.x||0)*100)+'%;top:'+((r.y||0)*100)+'%;width:'+((r.width||.1)*100)+'%;height:'+((r.height||.05)*100)+'%;"><span class="bbox-lbl">'+h(r.label||'hidden')+'</span></div>').join('');
      const oBoxes=(item.objects||[]).map(o=>'<div class="bbox obj" style="left:'+((o.x||0)*100)+'%;top:'+((o.y||0)*100)+'%;width:'+((o.width||.1)*100)+'%;height:'+((o.height||.1)*100)+'%;"><span class="bbox-lbl">'+h(o.label||'object')+'</span></div>').join('');
      const injHtml=item.hiddenPrompts?.length?'<div class="inj-banner"><div class="inj-banner-ttl">Hidden Prompts ('+item.hiddenPrompts.length+' found)</div>'+item.hiddenPrompts.map(p=>'<div class="inj-item"><code>'+h(p)+'</code></div>').join('')+'</div>':'';
      const fHtml=item.findings.map(f=>'<div class="finding-row">'+sevPill(f.severity)+'<strong>'+h(f.id)+'</strong><span style="color:var(--muted);">'+h(f.rationale||'')+'</span></div>').join('');
      return '<div class="img-card"><div class="img-card-hd"><div style="display:flex;align-items:center;gap:8px;">'+bdg('image')+'<strong>'+h(item.imageId||item.eventId||'Image Event')+'</strong></div><div style="display:flex;align-items:center;gap:8px;"><span class="pill '+item.decision+'">'+ST_LABEL[item.decision]+'</span><span style="font-size:11px;color:var(--muted);">'+fmtFull(item.timestamp)+'</span></div></div><div class="img-card-bd">'+(iSrc?'<div class="img-frame"><img src="'+h(iSrc)+'" alt="Evidence image" onerror="this.style.display=\\'none\\';this.nextElementSibling.style.display=\\'block\\'"><div class="img-missing">Image file unavailable — showing extracted text</div>'+rBoxes+oBoxes+'</div>':'<div class="img-frame"><div class="img-missing" style="display:block;">No image path</div></div>')+'<div class="img-info">'+injHtml+(item.extractedText?'<div><span class="lbl-sm">Extracted Text</span><div class="ocr"><code>'+h(item.extractedText)+'</code></div></div>':'')+(fHtml?'<div><span class="lbl-sm">Findings</span><div class="finding-list">'+fHtml+'</div></div>':'')+'<div style="font-size:11px;color:var(--muted);">Hash: <code>'+h((item.imageHash||'').slice(0,16))+'</code> · Confidence: '+h(item.confidence??'n/a')+'</div></div></div></div>';
    }).join('');
  } else {
    html+='<div class="panel"><div class="panel-bd" style="padding:16px;"><div class="empty">No image analysis results. Run <code>scan-image --file &lt;path&gt;</code> to analyze an image.</div></div></div>';
  }
  document.getElementById('foren-content').innerHTML=html;
}

// ── Self-healing tab ─────────────────────────────────────────────────────────
function pct(v){
  return typeof v==='number' ? Math.round(v*100)+'%' : 'n/a';
}

function renderSelfHealing(model){
  const sh=model.selfHealing||{loop:[],pending:[],shadow:[],applied:[]};
  let html='';
  html+='<div class="self-hero"><div><h2>'+h(sh.headline||'Guardrails get stronger over time.')+'</h2><p>'+h(sh.note||'Rules stay in shadow mode until a human approves them.')+'</p></div><span class="self-badge">Human approval required</span></div>';
  html+='<div class="panel"><div class="panel-hd"><h2>Self-Healing Loop</h2><span style="font-size:12px;color:var(--muted);">Collect → Analyze → Shadow → Pending → Applied</span></div><div class="self-loop">'+
    (sh.loop||[]).map(step=>'<div class="self-step '+(step.value>0?'active':'')+'"><div class="self-step-label">'+h(step.label)+'</div><div class="self-step-value">'+h(step.value)+'</div><div class="self-step-detail">'+h(step.detail)+'</div></div>').join('')+
  '</div></div>';

  html+='<div class="panel"><div class="panel-hd"><h2>Pending Rules</h2><span style="font-size:12px;color:var(--muted);">'+(sh.pending||[]).length+' awaiting approval</span></div><div class="panel-bd">';
  if((sh.pending||[]).length){
    html+='<div class="self-grid">'+sh.pending.map(c=>{
      const rule=c.rule||{};
      return '<div class="self-card">'+
        '<div class="self-card-top"><div class="self-rule-id">'+h(c.id||rule.id||'candidate')+'</div><span class="self-layer">'+h(c.layer)+'</span></div>'+
        '<div class="self-score">'+
          '<div class="self-score-box"><strong>'+(c.score==null?'n/a':h(c.score)+'%')+'</strong><span>Score</span></div>'+
          '<div class="self-score-box"><strong>'+pct(c.blockRate)+'</strong><span>Block</span></div>'+
          '<div class="self-score-box"><strong>'+pct(c.falsePositive)+'</strong><span>FP</span></div>'+
        '</div>'+
        '<div class="self-pattern"><span class="lbl-sm">Pattern</span><code>'+h(rule.pattern||'')+'</code></div>'+
        '<div class="self-source">Source: '+h(c.source||'Self-healing analysis')+'<br>Shadow: '+h(c.shadow?.wouldBlock??0)+' would-block · '+h(c.shadow?.falsePositive??0)+' false positive</div>'+
        '<div class="self-actions">'+
          '<button class="self-btn approve" data-action="approve" data-rule="'+h(c.id)+'">Approve</button>'+
          '<button class="self-btn reject" data-action="reject" data-rule="'+h(c.id)+'">Reject</button>'+
          '<button class="self-btn test" data-action="test" data-rule="'+h(c.id)+'">Test More</button>'+
        '</div>'+
      '</div>';
    }).join('')+'</div>';
  } else {
    html+='<div class="empty">No pending rules. Run <code>npm run self-loop</code> or <code>node src/cli.js learn analyze</code> after risky events are collected.</div>';
  }
  html+='</div><div class="self-result" id="self-action-result"></div></div>';

  html+='<div class="panel"><div class="panel-hd"><h2>Shadow Tests</h2><span style="font-size:12px;color:var(--muted);">'+(sh.shadow||[]).length+' rules running safely</span></div><div class="panel-bd">';
  if((sh.shadow||[]).length){
    html+='<table class="self-table"><thead><tr><th>Rule</th><th>Layer</th><th>Score</th><th>Would Block</th><th>False Positive</th><th>Recent</th></tr></thead><tbody>'+
      sh.shadow.map(s=>'<tr><td><code>'+h(s.id)+'</code></td><td>'+h(s.layer)+'</td><td>'+(s.score==null?'n/a':h(s.score)+'%')+'</td><td>'+h(s.stats?.wouldBlock??0)+'</td><td>'+h(s.stats?.falsePositive??0)+'</td><td>'+(s.stats?.recent?fmtFull(s.stats.recent):'—')+'</td></tr>').join('')+
    '</tbody></table>';
  } else {
    html+='<div class="empty">No shadow rules are running.</div>';
  }
  html+='</div></div>';

  html+='<div class="panel"><div class="panel-hd"><h2>Applied Rules</h2><span style="font-size:12px;color:var(--muted);">'+(sh.applied||[]).length+' active learned rules</span></div><div class="panel-bd">';
  if((sh.applied||[]).length){
    html+='<table class="self-table"><thead><tr><th>Rule</th><th>Layer</th><th>Severity</th><th>Category</th><th>Pattern</th></tr></thead><tbody>'+
      sh.applied.map(r=>'<tr><td><code>'+h(r.id)+'</code></td><td>'+h(r.layer)+'</td><td>'+h(r.severity||'')+'</td><td>'+h(r.category||'')+'</td><td><code>'+h(r.pattern||'')+'</code></td></tr>').join('')+
    '</tbody></table>';
  } else {
    html+='<div class="empty">No learned rules have been approved yet.</div>';
  }
  html+='</div></div>';

  document.getElementById('self-content').innerHTML=html;
}

async function handleSelfHealingAction(btn){
  const action=btn.dataset.action;
  const rule=btn.dataset.rule;
  const result=document.getElementById('self-action-result');
  btn.disabled=true;
  if(result)result.textContent='Running '+action+' for '+rule+'...';
  try{
    const res=await fetch('/api/learn/'+action+'?rule='+encodeURIComponent(rule),{method:'POST'});
    const body=await res.json();
    if(!res.ok)throw new Error(body.error||'Request failed');
    if(result)result.textContent=action==='test'
      ?'Test complete: '+JSON.stringify(body.metrics||body)
      :'Rule '+rule+' '+(action==='approve'?'approved.':'rejected.');
    const model=await (await fetch('/api/status')).json();
    renderAll(model);
  }catch(error){
    if(result)result.textContent='Action failed: '+error.message;
  }finally{
    btn.disabled=false;
  }
}

// ── Rule engine tab ──────────────────────────────────────────────────────────
function renderRules(model){
  const rb=model.runbook||[];
  const cands=model.candidates||[];
  const sc=model.surfaceCounts||{};
  let html='';
  html+='<div class="panel"><div class="panel-hd"><h2>3-Agent Runbook</h2></div><div class="panel-bd"><div class="rb-grid">'+
    rb.map(r=>'<div class="rb-card"><div class="rb-icon">'+h(r.icon)+'</div><div class="rb-title">'+h(r.label)+'</div><div class="rb-obj">'+h(r.objective)+'</div><div class="rb-lbl">Inputs</div><div style="font-size:12px;color:var(--muted);">'+h(r.inputs)+'</div><div class="rb-lbl">Outputs</div><div style="font-size:12px;color:var(--muted);">'+h(r.outputs)+'</div><div class="rb-lbl">Command</div><code class="rb-cmd">'+h(r.command)+'</code></div>').join('')+
  '</div></div></div>';
  const scItems=Object.entries(sc).sort((a,b)=>b[1]-a[1]);
  if(scItems.length){
    html+='<div class="panel"><div class="panel-hd"><h2>Scanned Count by Surface</h2></div><div class="panel-bd"><div class="surf-grid">'+
      scItems.map(([s,n])=>'<div class="surf-card">'+bdg(s)+'<strong>'+n+'</strong><span> scanned</span></div>').join('')+
    '</div></div></div>';
  }
  html+='<div class="panel"><div class="panel-hd"><h2>Auto-Generated Rule Candidates</h2><span style="font-size:12px;color:var(--muted);">'+cands.length+' pending review</span></div><div class="panel-bd">';
  html+=cands.length
    ?'<div class="cand-list">'+cands.map(c=>'<div class="cand-card"><div class="cand-id">'+h(c.rule?.id??c.id)+'</div><div class="cand-reason">'+h(c.reason??'Policy candidate')+'</div><code class="cand-pat">'+h(c.rule?.pattern??'')+'</code></div>').join('')+'</div>'
    :'<div class="empty">No rule candidates. Run <code>npm run self-loop</code> to generate candidates from recent blocked events.</div>';
  html+='</div></div>';
  document.getElementById('rule-content').innerHTML=html;
}

// ── Toast alerts ─────────────────────────────────────────────────────────────
function showToast(event){
  const container=document.getElementById('toast-container');
  const d=event.decision;
  const ruleId=event.findings?.[0]?.id??'';
  const rationale=event.findings?.[0]?.rationale??'';
  const severity=event.findings?.[0]?.severity??'';
  const aid=event.event?.agentId??'';
  const aLbl=AGENT_LABEL[aid]??aid;
  const toast=document.createElement('div');
  toast.className='toast '+d;
  toast.innerHTML='<span class="toast-icon">'+(d==='block'?'🚫':'⚠️')+'</span>'+
    '<div class="toast-body">'+
      '<div class="toast-title '+d+'">'+(d==='block'?'Blocked':'Warning')+': '+h(ruleId)+'</div>'+
      '<div class="toast-detail">'+h(rationale.slice(0,80))+(aLbl?' · '+h(aLbl):'')+'</div>'+
      (severity?'<span class="toast-severity '+h(severity)+'">'+h(severity)+'</span>':'')+
    '</div>';
  container.appendChild(toast);
  setTimeout(()=>toast.remove(),5000);
}

function checkNewBlocks(model){
  for(const e of(model.events||[])){
    if(seenEventIds.has(e.id))continue;
    seenEventIds.add(e.id);
    if(e.decision==='block'||(e.decision==='warn'&&(e.findings??[]).some(f=>f.severity==='critical'||f.severity==='high'))){
      showToast(e);
    }
  }
}

// ── Action banner ────────────────────────────────────────────────────────────
function renderActionBanner(model){
  const el=document.getElementById('action-banner');
  const ss=model.safetyScore||{score:100,level:'safe'};
  const recentBlocks=(model.events||[]).filter(e=>e.decision==='block'&&Date.now()-Date.parse(e.timestamp??'')<300000);
  if(recentBlocks.length>0){
    const agents=[...new Set(recentBlocks.map(e=>agentIdFor(e)).filter(Boolean))];
    el.style.display='flex';
    el.className='action-banner critical';
    el.innerHTML='<span class="action-banner-icon">🚨</span>'+
      '<div class="action-banner-text"><strong>'+recentBlocks.length+' blocked events</strong> occurred in the last 5 minutes.'+
      (agents.length?' Detected Agent: '+agents.map(a=>h(AGENT_LABEL[a]||a)).join(', '):'')+
      '</div><div class="action-banner-actions"><button class="action-banner-btn primary" data-tab="history">View History</button></div>';
  } else if(ss.level==='caution'){
    el.style.display='flex';el.className='action-banner warning';
    el.innerHTML='<span class="action-banner-icon">⚠️</span><div class="action-banner-text">Security score <strong>'+ss.score+'pts</strong> — review warning events.</div>';
  } else if(ss.score<100){
    el.style.display='flex';el.className='action-banner safe';
    el.innerHTML='<span class="action-banner-icon">✅</span><div class="action-banner-text">System is currently safe. Security score '+ss.score+'pts.</div>';
  } else {
    el.style.display='none';
  }
}

// ── Agent detail expansion panel ─────────────────────────────────────────────
function toggleAgentDetail(agentId){
  const existing=document.querySelector('.agent-detail-panel[data-for="'+agentId+'"]');
  if(existing){existing.remove();return;}
  document.querySelectorAll('.agent-detail-panel').forEach(p=>p.remove());
  if(!lastModel)return;
  const stats=(lastModel.agentStats||[]).find(s=>s.agentId===agentId);
  const events=(lastModel.events||[]).filter(e=>agentIdFor(e)===agentId);
  if(!stats)return;
  const role=agentId==='claude-code-hook'?'runtime':agentId.replace('agent-','');
  const m=ROLE_META[role]||{icon:'🤖',label:agentId,sub:''};
  const rate=stats.total?((stats.blockRate)*100).toFixed(0):'0';

  const ruleBarsHtml=stats.topRules.length
    ?stats.topRules.map(([r,n])=>{
      const maxN=stats.topRules[0][1];
      const pct=maxN?(n/maxN*100):0;
      return '<div class="rule-bar"><div class="rule-bar-fill" style="width:'+pct+'%;"></div><code>'+h(r)+'</code><span>'+n+'</span></div>';
    }).join('')
    :'<div style="font-size:11px;color:var(--muted);">No blocked rules.</div>';

  const surfTotal=Object.values(stats.surfaces).reduce((a,b)=>a+b,0)||1;
  const surfBarHtml='<div class="surf-bar-wrap">'+
    Object.entries(stats.surfaces).map(([s,n])=>{
      const pct=((n/surfTotal)*100).toFixed(1);
      const c=SURF_COLORS[s]||'#94a3b8';
      return '<div class="surf-bar-seg" style="width:'+pct+'%;background:'+c+';" title="'+h(s)+': '+n+'">'+h(s.slice(0,3))+'</div>';
    }).join('')+'</div>';

  const recentHtml=events.slice(0,8).map(e=>{
    const d=e.decision||'allow';
    return '<div class="tl-row '+d+'" style="margin-bottom:2px;"><div class="tl-head"><span class="tl-ts">'+fmt(e.timestamp)+'</span><span class="tl-dec '+d+'">'+ST_LABEL[d]+'</span>'+bdg(surf(e))+'<span class="tl-txt"><code>'+h((e.event?.text??e.text??'').slice(0,60))+'</code></span></div></div>';
  }).join('');

  const panel=document.createElement('div');
  panel.className='agent-detail-panel';
  panel.dataset.for=agentId;
  panel.innerHTML='<div class="adp-header"><h3>'+m.icon+' '+h(m.label)+' — Detailed Analysis</h3><button class="adp-close">✕</button></div>'+
    '<div class="adp-stats-row">'+
      '<div class="adp-stat"><div class="adp-stat-val" style="color:var(--block);">'+stats.block+'</div><div class="adp-stat-lbl">Blocked</div></div>'+
      '<div class="adp-stat"><div class="adp-stat-val" style="color:var(--warn);">'+stats.warn+'</div><div class="adp-stat-lbl">Warning</div></div>'+
      '<div class="adp-stat"><div class="adp-stat-val" style="color:var(--allow);">'+stats.allow+'</div><div class="adp-stat-lbl">Allowed</div></div>'+
      '<div class="adp-stat"><div class="adp-stat-val">'+rate+'%</div><div class="adp-stat-lbl">Block rate</div></div>'+
      '<div class="adp-stat"><div class="adp-stat-val">'+stats.total+'</div><div class="adp-stat-lbl">Total events</div></div>'+
    '</div>'+
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">'+
      '<div class="adp-section"><h4>Top Trigger Rules</h4>'+ruleBarsHtml+'</div>'+
      '<div class="adp-section"><h4>Surface Distribution</h4>'+surfBarHtml+'</div>'+
    '</div>'+
    '<div class="adp-section"><h4>Recent Events</h4><div class="adp-events">'+recentHtml+'</div></div>';

  const grid=document.getElementById('agent-flows');
  const col=grid.querySelector('[data-agent-id="'+agentId+'"]');
  if(col&&col.nextSibling)grid.insertBefore(panel,col.nextSibling);
  else grid.appendChild(panel);
}

// ── Render all ───────────────────────────────────────────────────────────────
function renderAll(model){
  lastModel=model;
  checkNewBlocks(model);
  renderMetrics(model.counts,model.safetyScore);
  if(activeTab==='overview'){
    renderActionBanner(model);
    renderLayerOverview(model);
    renderAgentFlows(model);
    renderVisionFlow(model);
    renderDiscoveries(model.hiddenPromptDiscoveries||[]);
    renderAlerts(model.alerts);
    renderFeed(model.events);
  } else if(activeTab==='history'){
    renderHistory(model);
  } else if(activeTab==='forensics'){
    renderForensics(model);
  } else if(activeTab==='self-healing'){
    renderSelfHealing(model);
  } else if(activeTab==='rules'){
    renderRules(model);
  }
  document.getElementById('updated').textContent=new Date(model.generatedAt).toLocaleTimeString('ko-KR',{hour12:false});
}

// ── SSE connection ───────────────────────────────────────────────────────────
const sse=new EventSource('/api/events');
sse.onmessage=e=>{
  try{
    const data=JSON.parse(e.data);
    if(data.error){
      document.getElementById('updated').textContent='오류: '+data.error.slice(0,60);
      return;
    }
    renderAll(data);
  }catch(err){
    document.getElementById('updated').textContent='렌더 오류: '+String(err).slice(0,60);
  }
};
sse.onopen=()=>{ document.getElementById('live-dot').className='dot live'; };
sse.onerror=()=>{
  document.getElementById('live-dot').className='dot err';
  document.getElementById('updated').textContent='Reconnecting...';
};

// ── Image Upload ──────────────────────────────────────────────────────────────
(function(){
  const dropZone=document.getElementById('drop-zone');
  const fileInput=document.getElementById('file-input');
  const statusEl=document.getElementById('upload-status');
  const progressEl=document.getElementById('upload-progress');
  const msgEl=document.getElementById('upload-msg');
  const resultEl=document.getElementById('upload-result');
  if(!dropZone)return;

  dropZone.addEventListener('click',()=>fileInput.click());
  fileInput.addEventListener('change',()=>{if(fileInput.files.length>0)uploadFile(fileInput.files[0]);});
  dropZone.addEventListener('dragover',e=>{e.preventDefault();dropZone.classList.add('dragover');});
  dropZone.addEventListener('dragleave',()=>dropZone.classList.remove('dragover'));
  dropZone.addEventListener('drop',e=>{e.preventDefault();dropZone.classList.remove('dragover');const f=e.dataTransfer.files[0];if(f)uploadFile(f);});

  async function uploadFile(file){
    const ALLOWED=['image/png','image/jpeg','image/gif','image/webp'];
    if(!ALLOWED.includes(file.type)){alert('지원하지 않는 파일 형식입니다. PNG, JPG, GIF, WebP만 가능합니다.');return;}
    if(file.size>10*1024*1024){alert('파일이 너무 큽니다. 최대 10MB까지 가능합니다.');return;}

    dropZone.classList.add('uploading');
    statusEl.style.display='block';
    progressEl.style.display='flex';
    msgEl.textContent='이미지 업로드 중... ('+(file.size/1024).toFixed(0)+' KB)';
    resultEl.style.display='none';

    try{
      const fd=new FormData();
      fd.append('image',file);
      msgEl.textContent='Vision AI 분석 중... (최대 30초 소요)';

      const resp=await fetch('/api/scan-image',{method:'POST',body:fd});
      const data=await resp.json();
      if(!resp.ok)throw new Error(data.error||'Upload failed');

      progressEl.style.display='none';
      resultEl.style.display='block';
      const d=data.decision||'allow';
      const findings=data.findings||[];
      const hPrompts=data.event?.evidence?.hiddenPrompts||[];

      let html='<div class="upload-result-card '+d+'">';
      html+='<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">';
      html+='<span class="pill '+d+'">'+ST_LABEL[d]+'</span>';
      html+='<strong>'+h(file.name)+'</strong>';
      if(data.severity)html+=sevPill(data.severity);
      html+='</div>';

      if(hPrompts.length){
        html+='<div style="margin-bottom:8px;padding:8px;background:#f5f3ff;border:1px solid #ddd6fe;border-radius:6px;">';
        html+='<strong style="color:#7c3aed;font-size:10px;text-transform:uppercase;">숨겨진 프롬프트 '+hPrompts.length+'건</strong>';
        hPrompts.forEach(p=>{html+='<div style="margin-top:4px;"><code style="color:#7c3aed;font-size:11px;">'+h(p)+'</code></div>';});
        html+='</div>';
      }

      if(findings.length){
        html+='<div style="display:flex;flex-direction:column;gap:4px;">';
        findings.forEach(f=>{html+='<div style="display:flex;align-items:center;gap:6px;font-size:12px;">'+sevPill(f.severity)+'<strong>'+h(f.id)+'</strong><span style="color:var(--muted);">'+h(f.rationale||'')+'</span></div>';});
        html+='</div>';
      } else {
        html+='<div style="font-size:12px;color:var(--muted);">위협이 감지되지 않았습니다.</div>';
      }

      html+='</div>';
      resultEl.innerHTML=html;
    }catch(err){
      progressEl.style.display='none';
      resultEl.style.display='block';
      resultEl.innerHTML='<div style="padding:10px;background:#fef2f2;border:1px solid var(--block);border-radius:6px;font-size:12px;color:var(--block);">오류: '+h(err.message)+'</div>';
    }finally{
      dropZone.classList.remove('uploading');
      fileInput.value='';
    }
  }
})();
</script>
</body>
</html>`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? DEFAULT_PORT);
  const dataDir = process.env.FOUR04GENT_DATA_DIR ?? '.404gent';
  const { port: actualPort } = await startDashboardServer({ port, dataDir });
  console.log(`404gent dashboard: http://127.0.0.1:${actualPort}`);
}
