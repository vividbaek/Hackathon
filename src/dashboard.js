#!/usr/bin/env node
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, resolve, sep } from 'node:path';

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

const threeAgentRunbook = [
  { id:'agent-vision-sentinel', label:'Agent 1 · Vision Sentinel', icon:'👁',
    objective:'이미지·스크린샷·OCR 결과에서 숨겨진 prompt injection과 의심 영역을 탐지합니다.',
    inputs:'image file, screenshot, OCR text, VLM regions',
    outputs:'extractedText, hiddenPrompts, regions, objects, confidence',
    command:'node src/cli.js scan-image --file <image-path>' },
  { id:'agent-policy-arbiter',  label:'Agent 2 · Policy Arbiter',  icon:'🛡',
    objective:'Vision Sentinel이 넘긴 텍스트와 증거를 룰베이스와 Claude review로 판정합니다.',
    inputs:'prompt, image, vision_observation, llm, command, output events',
    outputs:'allow / warn / block, findings, remediation',
    command:'node src/cli.js scan-image "<VLM extracted text>"' },
  { id:'agent-rule-steward',    label:'Agent 3 · Rule Steward',    icon:'⚙',
    objective:'차단·경고 로그를 포렌식 증거로 묶고 30분 self-loop 룰 후보를 생성합니다.',
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
    if (h) return '숨겨진 프롬프트 인젝션 발견';
    return n > 0 ? '이미지 추출 텍스트 분석 중' : '이미지 스캔 대기 중';
  }
  if (id === 'policy-agent') return n > 0 ? '정책 룰 적용 중' : '가드레일 이벤트 대기 중';
  if (id === 'llm-review-agent') return n > 0 ? '모호한 컨텍스트 Claude 검토 중' : '에스컬레이션 대기 중';
  if (id === 'forensic-agent') return n > 0 ? '감사 로그 및 증거 기록 중' : '최근 증거 없음';
  if (id === 'rule-agent') return candidates.length > 0 ? '정책 룰 후보 생성 중' : '대기 중인 룰 후보 없음';
  if (id === 'supervisor-agent') return events.some(e => e.decision === 'block') ? '위험 워크플로우 차단 중' : '판정 모니터링 중';
  return '대기 중';
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

export function buildDashboardModel({ events = [], candidates = [], state = {} } = {}) {
  const recentEvents = events.slice(-100);
  const candidateList = Array.isArray(candidates) ? candidates : candidates.candidates ?? [];
  const agents = agentDefinitions.map(def => summarizeAgent(def, recentEvents, candidateList));
  return {
    generatedAt: new Date().toISOString(),
    state,
    counts: summarizeCounts(recentEvents, candidateList),
    agents,
    edges: graphEdges.map(([from, to]) => ({ from, to })),
    runbook: threeAgentRunbook,
    alerts: collectAlerts(recentEvents),
    imageFindings: collectImageFindings(recentEvents),
    hiddenPromptDiscoveries: collectHiddenPromptDiscoveries(recentEvents),
    candidates: candidateList.slice(0, 8),
    timeline: collectTimeline(recentEvents, candidateList),
    events: recentEvents.slice(-100).reverse(),
    surfaceCounts: summarizeSurfaces(recentEvents)
  };
}

export async function readDashboardModel({ dataDir = '.404gent' } = {}) {
  const [events, candidates, state] = await Promise.all([
    readJsonLines(join(dataDir, 'events.jsonl')),
    readJson(join(dataDir, 'rule-candidates.json'), { candidates: [] }),
    readJson(join(dataDir, 'state.json'), {})
  ]);
  return buildDashboardModel({ events, candidates, state });
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

export function createDashboardServer({ dataDir = '.404gent' } = {}) {
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
  throw new Error(`포트 ${port}–${MAX_PORT} 사이에 사용 가능한 포트가 없습니다.`);
}

// ─── HTML ──────────────────────────────────────────────────────────────────────
function renderHtml() {
  return `<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>404gent · 에이전트 런타임</title>
<style>
:root{
  --bg:#f0f2f7;--panel:#fff;--ink:#111827;--muted:#6b7280;--border:#e5e7eb;
  --hdr:#0f172a;--hdr-border:#1e293b;
  --allow:#059669;--warn:#d97706;--block:#dc2626;--idle:#94a3b8;--inject:#7c3aed;--accent:#4f46e5;
  --c-image:#7c3aed;--c-prompt:#2563eb;--c-command:#d97706;--c-output:#059669;--c-llm:#0891b2;--c-vision_observation:#7c3aed;
  --r:10px;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:"Pretendard Variable",ui-sans-serif,system-ui,-apple-system,"Apple SD Gothic Neo","Noto Sans KR",sans-serif;background:var(--bg);color:var(--ink);font-size:14px;line-height:1.5;}

/* ── 헤더 ── */
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

/* ── 지표 바 ── */
#metrics-bar{display:flex;background:var(--panel);border-bottom:1px solid var(--border);overflow-x:auto;}
.metric{display:flex;flex-direction:column;align-items:center;padding:10px 22px;border-right:1px solid var(--border);min-width:96px;}
.metric:last-child{border-right:none;}
.metric strong{font-size:28px;font-weight:800;line-height:1.1;letter-spacing:-.03em;}
.metric span{font-size:11px;color:var(--muted);margin-top:2px;text-transform:uppercase;letter-spacing:.04em;}
.metric.m-block strong{color:var(--block);}
.metric.m-warn strong{color:var(--warn);}
.metric.m-allow strong{color:var(--allow);}
.metric.m-inject strong{color:var(--inject);}

/* ── 탭 패널 ── */
.tab-panel{display:none;}.tab-panel.active{display:block;}

/* ── 개요 레이아웃 ── */
.ov-wrap{display:grid;grid-template-columns:1fr 370px;gap:16px;padding:16px;max-width:1620px;margin:0 auto;}
.ov-main{display:flex;flex-direction:column;gap:16px;}
.ov-side{display:flex;flex-direction:column;gap:14px;}

/* ── 패널 ── */
.panel{background:var(--panel);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;}
.panel-hd{display:flex;align-items:center;justify-content:space-between;padding:14px 16px 0;margin-bottom:10px;}
.panel-hd h2{font-size:12px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);}
.panel-bd{padding:0 16px 16px;}

/* ── 에이전트 그래프 ── */
.graph-scroll{overflow-x:auto;padding:0 16px 16px;}
svg.graph{display:block;width:100%;min-width:960px;height:310px;}

/* SVG 에지 */
.g-edge{stroke:#d1d5db;stroke-width:1.5;fill:none;marker-end:url(#arr);}
.g-edge.active{stroke:var(--accent);stroke-width:2;stroke-dasharray:7 4;animation:flow .9s linear infinite;}
.g-edge.block-e{stroke:var(--block);stroke-width:2.5;stroke-dasharray:6 3;animation:flow .55s linear infinite;}
.g-edge.warn-e{stroke:var(--warn);stroke-width:2;stroke-dasharray:6 4;animation:flow .75s linear infinite;}
@keyframes flow{from{stroke-dashoffset:22;}to{stroke-dashoffset:0;}}

/* SVG 노드 */
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

/* ── 에이전트 카드 ── */
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
.badge-output{background:#d1fae5;color:#065f46;}
.badge-llm{background:#cffafe;color:#0e7490;}
.badge-unknown{background:#f3f4f6;color:#6b7280;}

/* ── 사이드바 ── */
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

/* ── 히스토리 탭 ── */
.hist-wrap{padding:16px;max-width:1300px;margin:0 auto;}
.hist-toolbar{display:flex;align-items:center;gap:12px;background:var(--panel);border:1px solid var(--border);border-radius:var(--r);padding:12px 16px;margin-bottom:14px;flex-wrap:wrap;}
.tb-grp{display:flex;align-items:center;gap:6px;}
.tb-grp label{font-size:11px;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:.04em;}
select{border:1px solid var(--border);border-radius:6px;padding:5px 10px;font-size:13px;background:var(--panel);color:var(--ink);cursor:pointer;font-family:inherit;}
.tb-count{font-size:12px;color:var(--muted);margin-left:auto;}
.hist-list{display:flex;flex-direction:column;gap:6px;}

.tl-row{background:var(--panel);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;cursor:pointer;transition:border-color .15s;}
.tl-row:hover{border-color:var(--accent);}
.tl-row.block{border-left:4px solid var(--block);}
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

/* ── 이미지 포렌식 탭 ── */
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

/* ── 룰 엔진 탭 ── */
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

/* ── 공통 ── */
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
</style>
</head>
<body>

<header>
  <div class="brand">
    <span class="brand-icon">⬡</span>
    <div>
      <h1>404gent</h1>
      <p>멀티모달 AI 가드레일 런타임</p>
    </div>
  </div>
  <nav class="tabs" id="tab-nav">
    <button class="tab-btn active" data-tab="overview">개요</button>
    <button class="tab-btn" data-tab="history">히스토리</button>
    <button class="tab-btn" data-tab="forensics">이미지 포렌식</button>
    <button class="tab-btn" data-tab="rules">룰 엔진</button>
  </nav>
  <div class="live-badge">
    <span class="dot live" id="live-dot"></span>
    <span id="updated">연결 중...</span>
  </div>
</header>

<div id="metrics-bar"></div>

<!-- 개요 -->
<div class="tab-panel active" id="panel-overview">
  <div class="ov-wrap">
    <div class="ov-main">
      <div class="panel">
        <div class="panel-hd"><h2>에이전트 파이프라인</h2></div>
        <div class="graph-scroll">
          <svg class="graph" viewBox="0 0 960 310" aria-label="에이전트 파이프라인 그래프">
            <defs>
              <marker id="arr" markerWidth="9" markerHeight="9" refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
                <path d="M0,0 L0,6 L9,3 z" fill="#cbd5e1"/>
              </marker>
            </defs>
            <g id="g-edges"></g>
            <g id="g-nodes"></g>
          </svg>
        </div>
        <div class="ag-grid" id="ag-cards"></div>
      </div>
    </div>
    <div class="ov-side">
      <div class="side-sec inject-sec" id="disc-sec">
        <div class="side-hd inject-hd">프롬프트 인젝션 탐지</div>
        <div class="side-bd" id="disc-list"></div>
      </div>
      <div class="side-sec">
        <div class="side-hd">보안 알림</div>
        <div class="side-bd" id="alert-list"></div>
      </div>
      <div class="side-sec">
        <div class="side-hd">최근 활동</div>
        <div class="side-bd" id="feed-list"></div>
      </div>
    </div>
  </div>
</div>

<!-- 히스토리 -->
<div class="tab-panel" id="panel-history">
  <div class="hist-wrap">
    <div class="hist-toolbar">
      <div class="tb-grp">
        <label>판정</label>
        <select id="f-dec">
          <option value="">전체</option>
          <option value="block">차단</option>
          <option value="warn">경고</option>
          <option value="allow">허용</option>
        </select>
      </div>
      <div class="tb-grp">
        <label>서피스</label>
        <select id="f-surf">
          <option value="">전체</option>
          <option value="image">image</option>
          <option value="prompt">prompt</option>
          <option value="command">command</option>
          <option value="output">output</option>
          <option value="llm">llm</option>
        </select>
      </div>
      <span class="tb-count" id="hist-count"></span>
    </div>
    <div class="hist-list" id="hist-list"></div>
  </div>
</div>

<!-- 이미지 포렌식 -->
<div class="tab-panel" id="panel-forensics">
  <div class="foren-wrap" id="foren-content"></div>
</div>

<!-- 룰 엔진 -->
<div class="tab-panel" id="panel-rules">
  <div class="rule-wrap" id="rule-content"></div>
</div>

<script>
// ── 상태 ──────────────────────────────────────────────────────────────────────
let lastModel = null;
let activeTab = 'overview';

const ST_LABEL = { idle:'대기', allow:'허용', warn:'경고', block:'차단' };
const ST_EN    = { idle:'IDLE', allow:'ALLOW', warn:'WARN', block:'BLOCK' };
const SEV_CLS  = { critical:'critical', high:'high', medium:'medium', low:'low' };

function h(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function fmt(v){return v?new Date(v).toLocaleTimeString('ko-KR',{hour12:false}):'—';}
function fmtFull(v){return v?new Date(v).toLocaleString('ko-KR',{month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}):'—';}
function surf(e){return e.event?.type??e.surface??'unknown';}
function bdg(s){return '<span class="badge badge-'+h(s)+'">'+h(s)+'</span>';}
function sevPill(s){return '<span class="sev '+h(SEV_CLS[s]||'low')+'">'+h(s)+'</span>';}

// ── 탭 전환 ───────────────────────────────────────────────────────────────────
document.getElementById('tab-nav').addEventListener('click',e=>{
  const btn=e.target.closest('.tab-btn');
  if(!btn)return;
  activeTab=btn.dataset.tab;
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.toggle('active',b.dataset.tab===activeTab));
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.toggle('active',p.id==='panel-'+activeTab));
  if(lastModel)renderAll(lastModel);
});

document.getElementById('f-dec').addEventListener('change',()=>{if(lastModel)renderHistory(lastModel.events);});
document.getElementById('f-surf').addEventListener('change',()=>{if(lastModel)renderHistory(lastModel.events);});
document.addEventListener('click',e=>{const r=e.target.closest('.tl-row');if(r)r.classList.toggle('open');});

// ── 지표 ─────────────────────────────────────────────────────────────────────
function renderMetrics(c){
  const items=[['전체',c.total,''],['차단',c.block,'m-block'],['경고',c.warn,'m-warn'],['허용',c.allow,'m-allow'],['룰 후보',c.candidates,''],['숨겨진 프롬프트',c.hiddenPrompts,'m-inject']];
  document.getElementById('metrics-bar').innerHTML=items.map(([l,v,cl])=>'<div class="metric '+cl+'"><strong>'+v+'</strong><span>'+l+'</span></div>').join('');
}

// ── 에이전트 그래프 ───────────────────────────────────────────────────────────
function renderGraph(model){
  const byId=new Map(model.agents.map(a=>[a.id,a]));
  const W=165,H=90;
  document.getElementById('g-edges').innerHTML=model.edges.map(({from:fId,to:tId})=>{
    const from=byId.get(fId),to=byId.get(tId);
    const x1=from.x+W,y1=from.y+H/2,x2=to.x,y2=to.y+H/2;
    const cx1=x1+45,cx2=x2-45;
    const st=from.status;
    const cls=st==='block'?'g-edge block-e':st==='warn'?'g-edge warn-e':st!=='idle'?'g-edge active':'g-edge';
    return '<path class="'+cls+'" d="M'+x1+','+y1+' C'+cx1+','+y1+' '+cx2+','+y2+' '+x2+','+y2+'"/>';
  }).join('');
  document.getElementById('g-nodes').innerHTML=model.agents.map(a=>{
    const st=a.status;
    return '<g class="g-node '+st+'" transform="translate('+a.x+','+a.y+')">' +
      '<rect width="'+W+'" height="'+H+'" rx="10"/>' +
      '<circle class="g-ind '+st+'" cx="'+(W-14)+'" cy="14" r="6"/>' +
      '<text x="13" y="32" font-size="16">'+h(a.icon)+'</text>' +
      '<text x="36" y="31" font-size="13" font-weight="800">'+h(a.label)+'</text>' +
      '<text class="g-role" x="13" y="50">'+h(a.role)+'</text>' +
      '<text class="g-st '+st+'" x="13" y="68">'+ST_EN[st]+' · '+a.eventCount+'건</text>' +
      '<text x="13" y="83" font-size="10" fill="#94a3b8">'+h((a.currentTask||'').slice(0,22))+'</text>' +
    '</g>';
  }).join('');
}

// ── 에이전트 카드 ─────────────────────────────────────────────────────────────
function renderAgentCards(agents){
  document.getElementById('ag-cards').innerHTML=agents.map(a=>{
    const recHtml=(a.recentEvents||[]).map(e=>
      '<div class="ag-rec">'+bdg(surf(e))+
      '<span class="pill sm '+e.decision+'">'+ST_LABEL[e.decision]||e.decision+'</span>'+
      '<code>'+h((e.event?.text??e.text??'').slice(0,28))+'</code></div>'
    ).join('');
    return '<div class="ag-card '+a.status+'">' +
      '<div class="ag-card-top"><span class="ag-icon">'+h(a.icon)+'</span><span class="pill '+a.status+'">'+ST_LABEL[a.status]+'</span></div>' +
      '<div class="ag-name">'+h(a.label)+'</div>' +
      '<div class="ag-role">'+h(a.role)+'</div>' +
      '<div class="ag-task">'+h(a.currentTask)+'</div>' +
      '<div class="ag-meta">처리: '+a.eventCount+'건 · 최근: '+fmt(a.lastSeen)+'</div>' +
      (recHtml?'<div class="ag-recents">'+recHtml+'</div>':'') +
    '</div>';
  }).join('');
}

// ── 인젝션 탐지 사이드바 ──────────────────────────────────────────────────────
function renderDiscoveries(items){
  document.getElementById('disc-list').innerHTML=items.length
    ?items.map(d=>'<div class="disc-card"><div class="disc-top"><span class="disc-title">인젝션 발견</span><span class="pill inject sm">숨겨진 프롬프트</span></div><div class="disc-meta">'+fmt(d.timestamp)+(d.imagePath?' · '+h(d.imagePath.split('/').at(-1)):'')+'</div><div class="disc-text"><code>'+h(d.prompt)+'</code></div></div>').join('')
    :'<div class="empty">감지된 프롬프트 인젝션이 없습니다.</div>';
}

// ── 보안 알림 사이드바 ────────────────────────────────────────────────────────
function renderAlerts(alerts){
  document.getElementById('alert-list').innerHTML=alerts.length
    ?alerts.slice(0,8).map(a=>'<div class="alert-card '+a.decision+'"><div class="alert-rule">'+h(a.ruleId)+'</div><div class="alert-meta">'+bdg(a.type)+sevPill(a.severity)+'<span>'+fmt(a.timestamp)+'</span></div><div style="margin-top:4px;"><code>'+h((a.match||'').slice(0,80))+'</code></div></div>').join('')
    :'<div class="empty">보안 알림 없음.</div>';
}

// ── 최근 활동 피드 ────────────────────────────────────────────────────────────
function renderFeed(events){
  const icons={block:'차단',warn:'경고',allow:'허용',idle:'•'};
  document.getElementById('feed-list').innerHTML=events.slice(0,10).map(e=>{
    const d=e.decision||'idle';
    return '<div class="feed-item"><div class="feed-dot '+d+'">'+(d==='allow'?'✓':d==='block'?'✕':'!')+'</div><div class="feed-body"><div class="feed-row">'+bdg(surf(e))+'<span class="pill sm '+d+'">'+ST_LABEL[d]+'</span><span class="feed-ts">'+fmt(e.timestamp)+'</span></div><div class="feed-txt"><code>'+h((e.event?.text??e.text??'').slice(0,60))+'</code></div></div></div>';
  }).join('')||'<div class="empty">이벤트 없음.</div>';
}

// ── 히스토리 탭 ───────────────────────────────────────────────────────────────
function renderHistory(events){
  const fd=document.getElementById('f-dec').value;
  const fs=document.getElementById('f-surf').value;
  const filtered=events.filter(e=>(!fd||e.decision===fd)&&(!fs||surf(e)===fs));
  document.getElementById('hist-count').textContent='총 '+filtered.length+'건';
  document.getElementById('hist-list').innerHTML=filtered.length
    ?filtered.map(e=>{
        const d=e.decision||'allow',s=surf(e);
        const txt=(e.event?.text??e.text??'').slice(0,100);
        const findings=e.findings??[];
        const hPrompts=e.event?.evidence?.hiddenPrompts??[];
        const fRows=findings.map(f=>'<div class="tl-finding">'+sevPill(f.severity)+'<strong>'+h(f.id)+'</strong><span style="color:var(--muted);">'+h(f.rationale||'')+'</span></div>').join('');
        const injSec=hPrompts.length?'<div class="tl-inject"><strong>숨겨진 프롬프트 원문 ('+hPrompts.length+'건)</strong>'+hPrompts.map(p=>'<code>'+h(p)+'</code>').join('<br>')+'</div>':'';
        return '<div class="tl-row '+d+'"><div class="tl-head"><span class="tl-ts">'+fmt(e.timestamp??e.recordedAt)+'</span><span class="tl-dec '+d+'">'+ST_LABEL[d]+'</span>'+bdg(s)+'<span class="tl-txt"><code>'+h(txt)+'</code></span><span class="tl-cnt">발견 '+findings.length+'건</span></div><div class="tl-detail"><div class="tl-detail-hd"><strong>이벤트 ID:</strong> '+h(e.id||'—')+' · <strong>시각:</strong> '+fmtFull(e.timestamp)+(e.event?.evidence?.imagePath?' · <strong>이미지:</strong> '+h(e.event.evidence.imagePath):'')+'</div>'+(fRows?'<div class="finding-list">'+fRows+'</div>':'')+injSec+'</div></div>';
      }).join('')
    :'<div style="text-align:center;padding:48px;color:var(--muted);font-size:13px;">조건에 맞는 이벤트가 없습니다.</div>';
}

// ── 이미지 포렌식 탭 ──────────────────────────────────────────────────────────
function renderForensics(model){
  const disc=model.hiddenPromptDiscoveries||[];
  const imgs=model.imageFindings||[];
  let html='';
  html+='<div class="panel"><div class="panel-hd"><h2>프롬프트 인젝션 탐지</h2><span class="pill inject">'+disc.length+'건 발견</span></div><div class="panel-bd">';
  html+=disc.length
    ?disc.map(d=>'<div class="disc-card" style="margin-bottom:10px;"><div class="disc-top"><span class="disc-title">인젝션 발견</span><span class="pill inject sm">숨겨진 프롬프트</span></div><div class="disc-meta">'+fmtFull(d.timestamp)+(d.imagePath?' · '+h(d.imagePath):'')+'</div><div class="disc-text"><code>'+h(d.prompt)+'</code></div></div>').join('')
    :'<div class="empty">분석된 이미지에서 프롬프트 인젝션이 발견되지 않았습니다.<br><code style="font-size:11px;">scan-image --file &lt;이미지&gt;</code> 명령으로 분석하세요.</div>';
  html+='</div></div>';
  if(imgs.length){
    html+=imgs.map(item=>{
      const iSrc=item.imageUrl||(item.imagePath?'/api/image?path='+encodeURIComponent(item.imagePath):'');
      const rBoxes=(item.regions||[]).filter(r=>r.threat).map(r=>'<div class="bbox" style="left:'+((r.x||0)*100)+'%;top:'+((r.y||0)*100)+'%;width:'+((r.width||.1)*100)+'%;height:'+((r.height||.05)*100)+'%;"><span class="bbox-lbl">'+h(r.label||'hidden')+'</span></div>').join('');
      const oBoxes=(item.objects||[]).map(o=>'<div class="bbox obj" style="left:'+((o.x||0)*100)+'%;top:'+((o.y||0)*100)+'%;width:'+((o.width||.1)*100)+'%;height:'+((o.height||.1)*100)+'%;"><span class="bbox-lbl">'+h(o.label||'object')+'</span></div>').join('');
      const injHtml=item.hiddenPrompts?.length?'<div class="inj-banner"><div class="inj-banner-ttl">숨겨진 프롬프트 ('+item.hiddenPrompts.length+'건 발견)</div>'+item.hiddenPrompts.map(p=>'<div class="inj-item"><code>'+h(p)+'</code></div>').join('')+'</div>':'';
      const fHtml=item.findings.map(f=>'<div class="finding-row">'+sevPill(f.severity)+'<strong>'+h(f.id)+'</strong><span style="color:var(--muted);">'+h(f.rationale||'')+'</span></div>').join('');
      return '<div class="img-card"><div class="img-card-hd"><div style="display:flex;align-items:center;gap:8px;">'+bdg('image')+'<strong>'+h(item.imageId||item.eventId||'이미지 이벤트')+'</strong></div><div style="display:flex;align-items:center;gap:8px;"><span class="pill '+item.decision+'">'+ST_LABEL[item.decision]+'</span><span style="font-size:11px;color:var(--muted);">'+fmtFull(item.timestamp)+'</span></div></div><div class="img-card-bd">'+(iSrc?'<div class="img-frame"><img src="'+h(iSrc)+'" alt="증거 이미지" onerror="this.style.display=\'none\';this.nextElementSibling.style.display=\'block\'"><div class="img-missing">이미지 파일 없음 — 추출 텍스트로 표시</div>'+rBoxes+oBoxes+'</div>':'<div class="img-frame"><div class="img-missing" style="display:block;">이미지 경로 없음</div></div>')+'<div class="img-info">'+injHtml+(item.extractedText?'<div><span class="lbl-sm">추출 텍스트</span><div class="ocr"><code>'+h(item.extractedText)+'</code></div></div>':'')+(fHtml?'<div><span class="lbl-sm">탐지 결과</span><div class="finding-list">'+fHtml+'</div></div>':'')+'<div style="font-size:11px;color:var(--muted);">해시: <code>'+h((item.imageHash||'').slice(0,16))+'</code> · 신뢰도: '+h(item.confidence??'n/a')+'</div></div></div></div>';
    }).join('');
  } else {
    html+='<div class="panel"><div class="panel-bd" style="padding:16px;"><div class="empty">이미지 분석 결과가 없습니다. <code>scan-image --file &lt;경로&gt;</code> 명령으로 이미지를 분석하세요.</div></div></div>';
  }
  document.getElementById('foren-content').innerHTML=html;
}

// ── 룰 엔진 탭 ───────────────────────────────────────────────────────────────
function renderRules(model){
  const rb=model.runbook||[];
  const cands=model.candidates||[];
  const sc=model.surfaceCounts||{};
  let html='';
  html+='<div class="panel"><div class="panel-hd"><h2>3-에이전트 런북</h2></div><div class="panel-bd"><div class="rb-grid">'+
    rb.map(r=>'<div class="rb-card"><div class="rb-icon">'+h(r.icon)+'</div><div class="rb-title">'+h(r.label)+'</div><div class="rb-obj">'+h(r.objective)+'</div><div class="rb-lbl">입력</div><div style="font-size:12px;color:var(--muted);">'+h(r.inputs)+'</div><div class="rb-lbl">출력</div><div style="font-size:12px;color:var(--muted);">'+h(r.outputs)+'</div><div class="rb-lbl">명령어</div><code class="rb-cmd">'+h(r.command)+'</code></div>').join('')+
  '</div></div></div>';
  const scItems=Object.entries(sc).sort((a,b)=>b[1]-a[1]);
  if(scItems.length){
    html+='<div class="panel"><div class="panel-hd"><h2>서피스별 스캔 통계</h2></div><div class="panel-bd"><div class="surf-grid">'+
      scItems.map(([s,n])=>'<div class="surf-card">'+bdg(s)+'<strong>'+n+'</strong><span>건 스캔</span></div>').join('')+
    '</div></div></div>';
  }
  html+='<div class="panel"><div class="panel-hd"><h2>자동 생성 룰 후보</h2><span style="font-size:12px;color:var(--muted);">'+cands.length+'건 검토 대기</span></div><div class="panel-bd">';
  html+=cands.length
    ?'<div class="cand-list">'+cands.map(c=>'<div class="cand-card"><div class="cand-id">'+h(c.rule?.id??c.id)+'</div><div class="cand-reason">'+h(c.reason??'정책 후보')+'</div><code class="cand-pat">'+h(c.rule?.pattern??'')+'</code></div>').join('')+'</div>'
    :'<div class="empty">룰 후보가 없습니다. <code>npm run self-loop</code> 로 최근 차단 이벤트에서 후보를 생성하세요.</div>';
  html+='</div></div>';
  document.getElementById('rule-content').innerHTML=html;
}

// ── 전체 렌더 ─────────────────────────────────────────────────────────────────
function renderAll(model){
  lastModel=model;
  renderMetrics(model.counts);
  if(activeTab==='overview'){
    renderGraph(model);
    renderAgentCards(model.agents);
    renderDiscoveries(model.hiddenPromptDiscoveries||[]);
    renderAlerts(model.alerts);
    renderFeed(model.events);
  } else if(activeTab==='history'){
    renderHistory(model.events);
  } else if(activeTab==='forensics'){
    renderForensics(model);
  } else if(activeTab==='rules'){
    renderRules(model);
  }
  document.getElementById('updated').textContent=new Date(model.generatedAt).toLocaleTimeString('ko-KR',{hour12:false});
}

// ── SSE 연결 ──────────────────────────────────────────────────────────────────
const sse=new EventSource('/api/events');
sse.onmessage=e=>{
  try{renderAll(JSON.parse(e.data));}catch{}
};
sse.onopen=()=>{ document.getElementById('live-dot').className='dot live'; };
sse.onerror=()=>{
  document.getElementById('live-dot').className='dot err';
  document.getElementById('updated').textContent='재연결 중...';
};
</script>
</body>
</html>`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? DEFAULT_PORT);
  const dataDir = process.env.FOUR04GENT_DATA_DIR ?? '.404gent';
  const { port: actualPort } = await startDashboardServer({ port, dataDir });
  console.log(`404gent 대시보드: http://127.0.0.1:${actualPort}`);
}
