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
    x: 90,
    y: 155,
    types: ['image', 'vision_observation']
  },
  {
    id: 'policy-agent',
    label: 'Policy Agent',
    role: 'Rule-based detection',
    x: 300,
    y: 155,
    types: ['prompt', 'command', 'output', 'image', 'vision_observation', 'llm']
  },
  {
    id: 'llm-review-agent',
    label: 'LLM Review',
    role: 'Claude escalation',
    x: 510,
    y: 85,
    types: ['llm']
  },
  {
    id: 'forensic-agent',
    label: 'Forensic Agent',
    role: 'Evidence logging',
    x: 510,
    y: 235,
    types: ['prompt', 'command', 'output', 'image', 'vision_observation', 'llm']
  },
  {
    id: 'rule-agent',
    label: 'Rule Agent',
    role: 'Self-loop candidates',
    x: 720,
    y: 235,
    types: []
  },
  {
    id: 'supervisor-agent',
    label: 'Supervisor',
    role: 'Block/warn/allow',
    x: 720,
    y: 85,
    types: ['prompt', 'command', 'output', 'image', 'vision_observation', 'llm']
  }
];

const graphEdges = [
  ['vision-agent', 'policy-agent'],
  ['policy-agent', 'llm-review-agent'],
  ['policy-agent', 'forensic-agent'],
  ['llm-review-agent', 'supervisor-agent'],
  ['forensic-agent', 'rule-agent'],
  ['rule-agent', 'policy-agent'],
  ['supervisor-agent', 'policy-agent']
];

const threeAgentRunbook = [
  {
    id: 'agent-vision-sentinel',
    label: 'Agent 1 · Vision Sentinel',
    objective: '이미지, 스크린샷, OCR/VLM 결과에서 숨겨진 prompt injection과 의심 영역을 찾습니다.',
    inputs: 'image file, screenshot, OCR text, VLM regions',
    outputs: 'extractedText, hiddenPrompts, regions, objects, confidence',
    command: 'node src/cli.js scan-image --file <image-path>'
  },
  {
    id: 'agent-policy-arbiter',
    label: 'Agent 2 · Policy Arbiter',
    objective: 'Vision Sentinel이 넘긴 텍스트와 증거를 룰베이스와 Claude review로 판정합니다.',
    inputs: 'prompt, image, vision_observation, llm, command, output events',
    outputs: 'allow/warn/block, findings, remediation',
    command: 'node src/cli.js scan-image "<VLM extracted text>"'
  },
  {
    id: 'agent-rule-steward',
    label: 'Agent 3 · Rule Steward',
    objective: '차단/경고 로그를 포렌식 증거로 묶고 30분 self-loop 룰 후보를 생성합니다.',
    inputs: '.404gent/events.jsonl, .404gent/vectors.jsonl',
    outputs: 'rule-candidates.json, replay corpus, policy diff',
    command: 'npm run self-loop'
  }
];

const rank = {
  idle: 0,
  allow: 1,
  warn: 2,
  block: 3
};

function statusFromDecision(decision) {
  if (decision === 'block') return 'block';
  if (decision === 'warn') return 'warn';
  if (decision === 'allow') return 'allow';
  return 'idle';
}

function maxStatus(current, next) {
  return rank[next] > rank[current] ? next : current;
}

function parseJsonLines(raw) {
  return raw
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

async function readJsonLines(path) {
  try {
    return parseJsonLines(await readFile(path, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

async function readJson(path, fallback) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return fallback;
    throw error;
  }
}

function eventType(event) {
  return event.event?.type ?? event.surface ?? 'unknown';
}

function eventTime(event) {
  return event.timestamp ?? event.recordedAt ?? event.scannedAt ?? null;
}

function summarizeAgent(definition, events, candidates) {
  const relevant = definition.types.length === 0
    ? []
    : events.filter((event) => definition.types.includes(eventType(event)));
  let status = relevant.reduce((current, event) => {
    return maxStatus(current, statusFromDecision(event.decision));
  }, 'idle');

  if (definition.id === 'rule-agent' && candidates.length > 0) {
    status = 'warn';
  }
  if (definition.id === 'supervisor-agent' && relevant.some((event) => event.decision === 'block')) {
    status = 'block';
  }

  const lastEvent = relevant.at(-1);
  return {
    ...definition,
    status,
    eventCount: definition.id === 'rule-agent' ? candidates.length : relevant.length,
    lastSeen: lastEvent ? eventTime(lastEvent) : null,
    currentTask: currentTask(definition.id, relevant, candidates)
  };
}

function currentTask(agentId, events, candidates) {
  if (agentId === 'vision-agent') {
    const hasHidden = events.some((e) => (e.event?.evidence?.hiddenPrompts ?? []).length > 0);
    if (hasHidden) return 'Hidden prompt injection uncovered';
    return events.length > 0 ? 'Inspecting image-derived text' : 'Waiting for image observations';
  }
  if (agentId === 'policy-agent') {
    return events.length > 0 ? 'Applying active policy rules' : 'Waiting for guardrail events';
  }
  if (agentId === 'llm-review-agent') {
    return events.length > 0 ? 'Reviewing ambiguous model context' : 'Standing by for escalation';
  }
  if (agentId === 'forensic-agent') {
    return events.length > 0 ? 'Writing audit and vector evidence' : 'No recent evidence';
  }
  if (agentId === 'rule-agent') {
    return candidates.length > 0 ? 'Preparing policy diff candidates' : 'No pending self-loop candidates';
  }
  if (agentId === 'supervisor-agent') {
    return events.some((event) => event.decision === 'block') ? 'Blocking critical workflow' : 'Monitoring decisions';
  }
  return 'Idle';
}

function collectAlerts(events) {
  return events
    .flatMap((event) => {
      return (event.findings ?? []).map((finding) => ({
        eventId: event.id,
        timestamp: eventTime(event),
        type: eventType(event),
        decision: event.decision,
        severity: finding.severity,
        category: finding.category,
        ruleId: finding.id,
        rationale: finding.rationale,
        match: finding.match
      }));
    })
    .filter((alert) => alert.decision === 'block' || alert.decision === 'warn')
    .slice(-12)
    .reverse();
}

function collectImageFindings(events) {
  return events
    .filter((event) => ['image', 'vision_observation'].includes(eventType(event)))
    .filter((event) => (event.findings ?? []).length > 0 || (event.event?.evidence?.hiddenPrompts ?? []).length > 0)
    .slice(-8)
    .reverse()
    .map((event) => {
      const evidence = event.event?.evidence ?? {};
      return {
        eventId: event.id,
        timestamp: eventTime(event),
        decision: event.decision,
        imageId: evidence.imageId,
        imageHash: evidence.imageHash,
        imagePath: evidence.imagePath,
        imageUrl: evidence.imageUrl,
        extractedText: evidence.extractedText ?? event.event?.text ?? event.text ?? '',
        confidence: evidence.confidence,
        visualSignals: evidence.visualSignals ?? [],
        regions: evidence.regions ?? [],
        findings: event.findings ?? [],
        hiddenPrompts: evidence.hiddenPrompts ?? [],
        objects: evidence.objects ?? []
      };
    });
}

function collectHiddenPromptDiscoveries(events) {
  return events
    .filter((event) => ['image', 'vision_observation'].includes(eventType(event)))
    .flatMap((event) => {
      const evidence = event.event?.evidence ?? {};
      return (evidence.hiddenPrompts ?? []).map((prompt) => ({
        eventId: event.id,
        timestamp: eventTime(event),
        decision: event.decision,
        imagePath: evidence.imagePath,
        imageUrl: evidence.imageUrl,
        imageHash: evidence.imageHash,
        prompt
      }));
    })
    .slice(-10)
    .reverse();
}

function summarizeCounts(events, candidates) {
  return {
    total: events.length,
    block: events.filter((event) => event.decision === 'block').length,
    warn: events.filter((event) => event.decision === 'warn').length,
    allow: events.filter((event) => event.decision === 'allow').length,
    candidates: candidates.length,
    hiddenPrompts: events.reduce((n, e) => n + (e.event?.evidence?.hiddenPrompts?.length ?? 0), 0)
  };
}

export function buildDashboardModel({ events = [], candidates = [], state = {} } = {}) {
  const recentEvents = events.slice(-100);
  const candidateList = Array.isArray(candidates) ? candidates : candidates.candidates ?? [];
  const agents = agentDefinitions.map((definition) => summarizeAgent(definition, recentEvents, candidateList));

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
    events: recentEvents.slice(-20).reverse()
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

function sendJson(response, body) {
  response.writeHead(200, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store'
  });
  response.end(JSON.stringify(body));
}

function sendHtml(response) {
  response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  response.end(renderHtml());
}

function contentType(path) {
  const extension = extname(path).toLowerCase();
  if (extension === '.png') return 'image/png';
  if (extension === '.jpg' || extension === '.jpeg') return 'image/jpeg';
  if (extension === '.gif') return 'image/gif';
  if (extension === '.webp') return 'image/webp';
  return 'application/octet-stream';
}

function resolveEvidencePath(path) {
  const root = resolve(process.cwd());
  const absolutePath = resolve(root, path);
  if (absolutePath !== root && !absolutePath.startsWith(`${root}${sep}`)) {
    throw new Error('Image path is outside the workspace.');
  }
  return absolutePath;
}

async function sendEvidenceImage(response, path) {
  if (!path) {
    response.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' });
    response.end('Missing image path');
    return;
  }

  const absolutePath = resolveEvidencePath(path);
  const body = await readFile(absolutePath);
  response.writeHead(200, {
    'content-type': contentType(absolutePath),
    'cache-control': 'no-store'
  });
  response.end(body);
}

export function createDashboardServer({ dataDir = '.404gent' } = {}) {
  return createServer(async (request, response) => {
    try {
      const url = new URL(request.url, 'http://localhost');

      if (url.pathname === '/api/events') {
        response.writeHead(200, {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-cache',
          'connection': 'keep-alive',
          'x-accel-buffering': 'no'
        });

        const push = async () => {
          try {
            const model = await readDashboardModel({ dataDir });
            response.write(`data: ${JSON.stringify(model)}\n\n`);
          } catch (err) {
            response.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
          }
        };

        await push();
        const interval = setInterval(push, 1000);
        request.on('close', () => clearInterval(interval));
        return;
      }

      if (url.pathname === '/api/status') {
        sendJson(response, await readDashboardModel({ dataDir }));
        return;
      }
      if (url.pathname === '/api/image') {
        await sendEvidenceImage(response, url.searchParams.get('path'));
        return;
      }
      if (url.pathname === '/' || url.pathname === '/dashboard') {
        sendHtml(response);
        return;
      }
      response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      response.end('Not found');
    } catch (error) {
      response.writeHead(500, { 'content-type': 'application/json; charset=utf-8' });
      response.end(JSON.stringify({ error: error.message }));
    }
  });
}

export async function startDashboardServer({ port = DEFAULT_PORT, dataDir = '.404gent' } = {}) {
  for (let candidatePort = port; candidatePort <= MAX_PORT; candidatePort += 1) {
    const server = createDashboardServer({ dataDir });
    const result = await new Promise((resolve, reject) => {
      server.once('error', (error) => {
        if (error.code === 'EADDRINUSE') { resolve(null); return; }
        reject(error);
      });
      server.listen(candidatePort, '127.0.0.1', () => {
        resolve({ server, port: candidatePort });
      });
    });
    if (result) return result;
  }
  throw new Error(`No available dashboard port between ${port} and ${MAX_PORT}.`);
}

function renderHtml() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>404gent Agent Runtime</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --ink: #17202a;
      --muted: #667085;
      --line: #d6dbe1;
      --allow: #177245;
      --warn: #9a5b00;
      --block: #b42318;
      --idle: #667085;
      --accent: #2457c5;
      --inject: #7c1fae;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--ink);
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 24px;
      padding: 18px 24px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
    }
    h1, h2, h3, p { margin: 0; }
    h1 { font-size: 20px; font-weight: 720; }
    h2 { font-size: 15px; margin-bottom: 12px; }
    .subtitle { color: var(--muted); font-size: 13px; margin-top: 4px; }
    .status-line { color: var(--muted); font-size: 13px; text-align: right; }
    .sse-dot {
      display: inline-block;
      width: 8px; height: 8px;
      border-radius: 50%;
      background: var(--allow);
      margin-right: 5px;
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.3; }
    }
    main {
      display: grid;
      grid-template-columns: minmax(620px, 1fr) 420px;
      gap: 18px;
      padding: 18px;
      max-width: 1520px;
      margin: 0 auto;
    }
    section {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
    }
    .metrics {
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 18px;
    }
    .metric {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      background: #fbfcfd;
    }
    .metric.inject { border-color: var(--inject); background: #faf5ff; }
    .metric strong { display: block; font-size: 24px; line-height: 1.1; }
    .metric.inject strong { color: var(--inject); }
    .metric span { display: block; color: var(--muted); font-size: 12px; margin-top: 4px; }
    .graph-wrap { overflow-x: auto; }
    svg { min-width: 900px; width: 100%; height: 360px; display: block; }
    .edge { stroke: #9aa5b1; stroke-width: 2; fill: none; marker-end: url(#arrow); }
    .node rect { fill: #fff; stroke: #aeb7c2; stroke-width: 1.5; rx: 8; }
    .node.allow rect { stroke: var(--allow); }
    .node.warn rect { stroke: var(--warn); }
    .node.block rect { stroke: var(--block); stroke-width: 2.5; }
    .node text { fill: var(--ink); font-size: 13px; }
    .node .role { fill: var(--muted); font-size: 11px; }
    .node .state { font-size: 11px; font-weight: 700; }
    .state.allow { fill: var(--allow); }
    .state.warn { fill: var(--warn); }
    .state.block { fill: var(--block); }
    .state.idle { fill: var(--idle); }
    .agent-list {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin-top: 12px;
    }
    .agent-row {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      min-height: 86px;
    }
    .agent-row.block { border-color: var(--block); background: #fff7f5; }
    .agent-row.warn { border-color: var(--warn); background: #fffbeb; }
    .agent-row.allow { border-color: var(--allow); background: #f6fef9; }
    .row-head { display: flex; justify-content: space-between; gap: 10px; align-items: baseline; }
    .pill {
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 11px;
      font-weight: 700;
      border: 1px solid var(--line);
    }
    .pill.block { color: var(--block); border-color: var(--block); }
    .pill.warn { color: var(--warn); border-color: var(--warn); }
    .pill.allow { color: var(--allow); border-color: var(--allow); }
    .pill.idle { color: var(--idle); }
    .pill.inject { color: var(--inject); border-color: var(--inject); background: #faf5ff; }
    .task { color: var(--muted); font-size: 12px; margin-top: 8px; line-height: 1.35; }
    .side { display: flex; flex-direction: column; gap: 18px; }
    .list { display: flex; flex-direction: column; gap: 10px; }
    .runbook {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 18px;
    }
    .run-card {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      padding: 13px;
      min-height: 184px;
    }
    .run-card strong {
      display: block;
      font-size: 14px;
      margin-bottom: 8px;
    }
    .run-card .label {
      color: var(--muted);
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      margin-top: 10px;
    }
    .run-card code {
      display: block;
      margin-top: 5px;
      padding: 6px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fbfcfd;
    }
    .alert {
      border-left: 4px solid var(--line);
      padding: 10px 10px 10px 12px;
      background: #fbfcfd;
      border-radius: 6px;
    }
    .alert.block { border-left-color: var(--block); background: #fff7f5; }
    .alert.warn { border-left-color: var(--warn); background: #fffbeb; }
    .alert-title { font-size: 13px; font-weight: 720; }
    .alert-meta, .small { color: var(--muted); font-size: 12px; margin-top: 5px; line-height: 1.4; }
    .candidate {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      background: #fbfcfd;
    }
    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      word-break: break-word;
    }
    /* Image analysis */
    .image-frame {
      position: relative;
      margin-top: 10px;
      min-height: 120px;
      background: #eef1f5;
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }
    .image-frame img {
      display: block;
      width: 100%;
      max-height: 220px;
      object-fit: contain;
      background: #0f1720;
    }
    .image-missing {
      display: none;
      padding: 18px;
      color: var(--muted);
      font-size: 12px;
    }
    .image-box {
      position: absolute;
      border: 2px solid var(--block);
      background: rgba(180, 35, 24, 0.14);
      box-shadow: 0 0 0 1px #fff inset;
      pointer-events: none;
    }
    .image-box.object { border-color: var(--warn); background: rgba(154, 91, 0, 0.12); }
    .image-box-label {
      position: absolute;
      top: -18px;
      left: 0;
      font-size: 10px;
      font-weight: 700;
      color: #fff;
      background: var(--block);
      padding: 1px 5px;
      border-radius: 3px;
      white-space: nowrap;
    }
    .image-box.object .image-box-label { background: var(--warn); }
    .ocr-text {
      margin-top: 6px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      padding: 8px;
      max-height: 80px;
      overflow: auto;
    }
    /* Hidden prompt banner */
    .hidden-prompt-banner {
      margin-top: 10px;
      border: 2px solid var(--inject);
      border-radius: 8px;
      background: #faf5ff;
      padding: 10px 12px;
    }
    .hidden-prompt-title {
      font-size: 12px;
      font-weight: 800;
      color: var(--inject);
      letter-spacing: 0.05em;
      text-transform: uppercase;
      margin-bottom: 6px;
    }
    .hidden-prompt-text {
      background: #fff;
      border: 1px solid #e0d0f0;
      border-radius: 5px;
      padding: 6px 8px;
      margin-top: 5px;
    }
    .hidden-prompt-text code {
      color: var(--inject);
      font-size: 12px;
    }
    /* Discovery card */
    .discovery-card {
      border: 2px solid var(--inject);
      border-radius: 8px;
      padding: 10px 12px;
      background: #faf5ff;
    }
    .discovery-card .row-head { margin-bottom: 6px; }
    .discovery-prompt {
      background: #fff;
      border: 1px solid #e0d0f0;
      border-radius: 5px;
      padding: 7px 10px;
      margin-top: 6px;
    }
    .discovery-prompt code { color: var(--inject); }
    @media (max-width: 1100px) {
      main { grid-template-columns: 1fr; }
      .metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .runbook { grid-template-columns: 1fr; }
      .agent-list { grid-template-columns: 1fr; }
      header { align-items: flex-start; flex-direction: column; }
      .status-line { text-align: left; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>404gent Agent Runtime</h1>
      <p class="subtitle">Multimodal guardrail — image injection, object detection, LLM &amp; command scanning.</p>
    </div>
    <div class="status-line">
      <div id="updated"><span class="sse-dot"></span>Connecting...</div>
      <div>Live via <code>/api/events</code></div>
    </div>
  </header>
  <main>
    <div>
      <div class="metrics" id="metrics"></div>
      <section style="margin-bottom:18px;">
        <h2>3-Agent Runbook</h2>
        <div class="runbook" id="runbook"></div>
      </section>
      <section>
        <h2>Agent Graph</h2>
        <div class="graph-wrap">
          <svg viewBox="0 0 900 360" role="img" aria-label="404gent agent graph">
            <defs>
              <marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
                <path d="M0,0 L0,6 L9,3 z" fill="#9aa5b1"></path>
              </marker>
            </defs>
            <g id="edges"></g>
            <g id="nodes"></g>
          </svg>
        </div>
        <div class="agent-list" id="agents"></div>
      </section>
    </div>
    <div class="side">
      <section>
        <h2>Hidden Prompt Discoveries</h2>
        <div class="list" id="hiddenPromptDiscoveries"></div>
      </section>
      <section>
        <h2>Security Alerts</h2>
        <div class="list" id="alerts"></div>
      </section>
      <section>
        <h2>Image Findings</h2>
        <div class="list" id="imageFindings"></div>
      </section>
      <section>
        <h2>Self-Loop Rule Candidates</h2>
        <div class="list" id="candidates"></div>
      </section>
      <section>
        <h2>Recent Events</h2>
        <div class="list" id="events"></div>
      </section>
    </div>
  </main>
  <script>
    const statusLabel = { idle: 'IDLE', allow: 'ALLOW', warn: 'WARN', block: 'BLOCK' };

    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }

    function formatTime(value) {
      if (!value) return 'no events';
      return new Date(value).toLocaleTimeString();
    }

    function renderMetrics(counts) {
      const metrics = [
        ['Total', counts.total, ''],
        ['Blocked', counts.block, ''],
        ['Warned', counts.warn, ''],
        ['Allowed', counts.allow, ''],
        ['Candidates', counts.candidates, ''],
        ['Hidden Prompts', counts.hiddenPrompts, 'inject']
      ];
      document.getElementById('metrics').innerHTML = metrics.map(([label, value, cls]) =>
        '<div class="metric ' + cls + '"><strong>' + value + '</strong><span>' + label + '</span></div>'
      ).join('');
    }

    function renderGraph(model) {
      const byId = new Map(model.agents.map((a) => [a.id, a]));
      document.getElementById('edges').innerHTML = model.edges.map((edge) => {
        const from = byId.get(edge.from);
        const to = byId.get(edge.to);
        return '<path class="edge" d="M' + (from.x+150) + ',' + (from.y+38) + ' C' + (from.x+185) + ',' + (from.y+38) + ' ' + (to.x-35) + ',' + (to.y+38) + ' ' + to.x + ',' + (to.y+38) + '"></path>';
      }).join('');
      document.getElementById('nodes').innerHTML = model.agents.map((agent) =>
        '<g class="node ' + agent.status + '" transform="translate(' + agent.x + ' ' + agent.y + ')">' +
          '<rect width="150" height="76"></rect>' +
          '<text x="12" y="22">' + escapeHtml(agent.label) + '</text>' +
          '<text class="role" x="12" y="42">' + escapeHtml(agent.role) + '</text>' +
          '<text class="state ' + agent.status + '" x="12" y="62">' + statusLabel[agent.status] + ' · ' + agent.eventCount + '</text>' +
        '</g>'
      ).join('');
    }

    function renderAgents(agents) {
      document.getElementById('agents').innerHTML = agents.map((agent) =>
        '<div class="agent-row ' + agent.status + '">' +
          '<div class="row-head"><strong>' + escapeHtml(agent.label) + '</strong><span class="pill ' + agent.status + '">' + statusLabel[agent.status] + '</span></div>' +
          '<div class="task">' + escapeHtml(agent.currentTask) + '</div>' +
          '<div class="small">events: ' + agent.eventCount + ' · last seen: ' + formatTime(agent.lastSeen) + '</div>' +
        '</div>'
      ).join('');
    }

    function renderRunbook(items) {
      document.getElementById('runbook').innerHTML = items.map((item) =>
        '<div class="run-card">' +
          '<strong>' + escapeHtml(item.label) + '</strong>' +
          '<div class="small">' + escapeHtml(item.objective) + '</div>' +
          '<div class="label">Inputs</div>' +
          '<div class="small">' + escapeHtml(item.inputs) + '</div>' +
          '<div class="label">Outputs</div>' +
          '<div class="small">' + escapeHtml(item.outputs) + '</div>' +
          '<code>' + escapeHtml(item.command) + '</code>' +
        '</div>'
      ).join('');
    }

    function renderAlerts(alerts) {
      document.getElementById('alerts').innerHTML = alerts.length ? alerts.map((alert) =>
        '<div class="alert ' + alert.decision + '">' +
          '<div class="alert-title">' + escapeHtml(alert.ruleId) + '</div>' +
          '<div class="alert-meta">' + escapeHtml(alert.type) + ' · ' + escapeHtml(alert.severity) + ' · ' + formatTime(alert.timestamp) + '</div>' +
          '<div class="small">' + escapeHtml(alert.rationale) + '</div>' +
          '<div class="small"><code>' + escapeHtml(alert.match) + '</code></div>' +
        '</div>'
      ).join('') : '<p class="small">No active alerts.</p>';
    }

    function renderHiddenPromptDiscoveries(items) {
      document.getElementById('hiddenPromptDiscoveries').innerHTML = items.length ? items.map((item) =>
        '<div class="discovery-card">' +
          '<div class="row-head">' +
            '<strong style="color:var(--inject)">Injection Found</strong>' +
            '<span class="pill inject">HIDDEN PROMPT</span>' +
          '</div>' +
          '<div class="small">' + formatTime(item.timestamp) + (item.imagePath ? ' · ' + escapeHtml(item.imagePath.split('/').at(-1)) : '') + '</div>' +
          '<div class="discovery-prompt"><code>' + escapeHtml(item.prompt) + '</code></div>' +
        '</div>'
      ).join('') : '<p class="small">No hidden prompt injections detected.</p>';
    }

    function renderImageFindings(items) {
      document.getElementById('imageFindings').innerHTML = items.length ? items.map((item) => {
        const imageSrc = item.imageUrl || (item.imagePath ? '/api/image?path=' + encodeURIComponent(item.imagePath) : '');

        // Bounding boxes for hidden text regions (red)
        const regionBoxes = (item.regions || []).filter((r) => r.threat).map((region) =>
          '<div class="image-box" style="left:' + ((region.x||0)*100) + '%;top:' + ((region.y||0)*100) + '%;width:' + ((region.width||0.1)*100) + '%;height:' + ((region.height||0.05)*100) + '%;">' +
            '<div class="image-box-label">' + escapeHtml(region.label || 'hidden text') + '</div>' +
          '</div>'
        ).join('');

        // Bounding boxes for detected objects (orange)
        const objectBoxes = (item.objects || []).map((obj) =>
          '<div class="image-box object" style="left:' + ((obj.x||0)*100) + '%;top:' + ((obj.y||0)*100) + '%;width:' + ((obj.width||0.1)*100) + '%;height:' + ((obj.height||0.1)*100) + '%;">' +
            '<div class="image-box-label">' + escapeHtml(obj.label || 'object') + '</div>' +
          '</div>'
        ).join('');

        const hiddenPromptsHtml = item.hiddenPrompts && item.hiddenPrompts.length
          ? '<div class="hidden-prompt-banner">' +
              '<div class="hidden-prompt-title">Hidden Prompt Injection Revealed (' + item.hiddenPrompts.length + ')</div>' +
              item.hiddenPrompts.map((p) =>
                '<div class="hidden-prompt-text"><code>' + escapeHtml(p) + '</code></div>'
              ).join('') +
            '</div>'
          : '';

        return '<div class="candidate">' +
          '<div class="row-head"><strong>' + escapeHtml(item.imageId || item.eventId) + '</strong><span class="pill ' + item.decision + '">' + escapeHtml(item.decision) + '</span></div>' +
          (imageSrc ? '<div class="image-frame"><img src="' + escapeHtml(imageSrc) + '" alt="flagged image evidence" onerror="this.style.display=\\'none\\'; this.nextElementSibling.style.display=\\'block\\';"><div class="image-missing">Image not served; showing OCR evidence only.</div>' + regionBoxes + objectBoxes + '</div>' : '') +
          hiddenPromptsHtml +
          '<div class="small" style="margin-top:8px;">confidence: ' + escapeHtml(item.confidence ?? 'n/a') + ' · hash: <code>' + escapeHtml((item.imageHash || '').slice(0, 16)) + '</code></div>' +
          (item.extractedText ? '<div class="ocr-text"><code>' + escapeHtml(item.extractedText) + '</code></div>' : '') +
        '</div>';
      }).join('') : '<p class="small">No image security findings.</p>';
    }

    function renderCandidates(candidates) {
      document.getElementById('candidates').innerHTML = candidates.length ? candidates.map((candidate) =>
        '<div class="candidate">' +
          '<div class="alert-title">' + escapeHtml(candidate.rule?.id ?? candidate.id) + '</div>' +
          '<div class="small">' + escapeHtml(candidate.reason ?? 'Policy candidate') + '</div>' +
          '<div class="small"><code>' + escapeHtml(candidate.rule?.pattern ?? '') + '</code></div>' +
        '</div>'
      ).join('') : '<p class="small">No generated rule candidates.</p>';
    }

    function renderEvents(events) {
      document.getElementById('events').innerHTML = events.length ? events.slice(0, 8).map((event) =>
        '<div class="candidate">' +
          '<div class="row-head"><strong>' + escapeHtml(event.event?.type ?? event.surface) + '</strong><span class="pill ' + event.decision + '">' + escapeHtml(event.decision) + '</span></div>' +
          '<div class="small">' + formatTime(event.timestamp ?? event.recordedAt) + '</div>' +
          '<div class="small"><code>' + escapeHtml((event.event?.text ?? event.text ?? '').slice(0, 120)) + '</code></div>' +
        '</div>'
      ).join('') : '<p class="small">No events recorded yet.</p>';
    }

    function renderAll(model) {
      renderMetrics(model.counts);
      renderRunbook(model.runbook || []);
      renderGraph(model);
      renderAgents(model.agents);
      renderAlerts(model.alerts);
      renderHiddenPromptDiscoveries(model.hiddenPromptDiscoveries || []);
      renderImageFindings(model.imageFindings);
      renderCandidates(model.candidates);
      renderEvents(model.events);
      document.getElementById('updated').innerHTML = '<span class="sse-dot"></span>Updated ' + new Date(model.generatedAt).toLocaleTimeString();
    }

    // Use SSE for real-time updates
    const source = new EventSource('/api/events');
    source.onmessage = (e) => {
      try {
        renderAll(JSON.parse(e.data));
      } catch (err) {
        console.error('Dashboard parse error:', err);
      }
    };
    source.onerror = () => {
      document.getElementById('updated').innerHTML = '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--block);margin-right:5px;"></span>Disconnected — reconnecting...';
    };
    source.onopen = () => {
      document.getElementById('updated').innerHTML = '<span class="sse-dot"></span>Connected';
    };
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
