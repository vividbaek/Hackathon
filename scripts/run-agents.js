#!/usr/bin/env node
/**
 * 404gent Multi-Agent Orchestrator
 *
 * 하나의 태스크를 입력하면 qa/backend/security 3개 Claude Code 에이전트를
 * 병렬로 실행합니다. 모든 Bash 도구 호출은 hooks로 실시간 차단되며,
 * 에이전트 간 출력은 pipe 스캔으로 오염 여부를 검증합니다.
 *
 * Usage:
 *   node scripts/run-agents.js "태스크 설명"
 *   node scripts/run-agents.js --model haiku "태스크 설명"
 *   node scripts/run-agents.js --timeout 90 "태스크 설명"
 *   node scripts/run-agents.js --roles qa,security "태스크 설명"
 */

import { spawn } from 'node:child_process';
import { watch } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createAgentHandoff, saveAgentHandoff, pipeToAgent } from '../src/harness.js';
import { appendAuditEvent } from '../src/audit.js';
import { updateState } from '../src/state.js';
import { appendVectorDocument } from '../src/vector-store.js';
import { startPolicyServer } from '../src/server.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..');

// ── CLI arg parse ─────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
let model     = 'sonnet';
let timeoutMs = 120_000;
let roles     = ['qa', 'backend', 'security'];
let noServer  = false;
const taskParts = [];

for (let i = 0; i < argv.length; i++) {
  if      (argv[i] === '--model')     { model = argv[++i]; }
  else if (argv[i] === '--timeout')   { timeoutMs = Number(argv[++i]) * 1000; }
  else if (argv[i] === '--roles')     { roles = argv[++i].split(',').map(r => r.trim()); }
  else if (argv[i] === '--no-server') { noServer = true; }
  else                                { taskParts.push(argv[i]); }
}

const task = taskParts.join(' ') || '404gent 프로젝트의 현재 코드와 보안 이벤트를 각 역할에 맞게 검토해줘';

// ── ANSI ─────────────────────────────────────────────────────────────────────
const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', yellow: '\x1b[33m', green: '\x1b[32m',
  cyan: '\x1b[36m', magenta: '\x1b[35m', white: '\x1b[37m'
};
const ROLE_COLOR = { qa: C.cyan, backend: C.magenta, security: C.yellow };

function tag(role) { return `${ROLE_COLOR[role] ?? C.white}[${role}]${C.reset}`; }
function prefixLines(role, text) {
  return text.split('\n').filter(l => l.trim()).map(l => `${tag(role)} ${l}`).join('\n');
}

// ── Config ────────────────────────────────────────────────────────────────────
const config = { dataDir: '.404gent', companyId: 'multi-agent-run' };
const eventsPath = resolve(PROJECT_ROOT, config.dataDir, 'events.jsonl');

async function record(report) {
  await appendAuditEvent(report, config);
  await appendVectorDocument(report, config);
  await updateState(report, config);
}

// ── Safety tail — prints new block/warn events while agents are running ────────
const DECISION_COLOR = { block: C.red, warn: C.yellow, allow: C.green };

function safetyLine(event) {
  const d   = event.decision ?? 'allow';
  const col = DECISION_COLOR[d] ?? C.dim;
  const suf = d === 'block' ? ' 🚫' : d === 'warn' ? ' ⚠️' : '';
  const surface = event.surface ?? event.event?.type ?? '?';
  const rule = event.findings?.[0]?.id ?? '—';
  const agent = (event.event?.agentId ?? event.agentId ?? '').replace(/^agent-/, '');
  const agentPart = agent ? `${C.dim}[${agent}]${C.reset} ` : '';
  return `${col}${C.bold}[SAFETY]${C.reset} ${agentPart}${col}${d.toUpperCase()}${C.reset}  ${surface}  ${rule}${suf}`;
}

function startSafetyTail(knownSize) {
  let size = knownSize;
  let buf  = '';

  async function check() {
    try {
      const info = await stat(eventsPath);
      if (info.size <= size) return;
      const raw  = await readFile(eventsPath, 'utf8');
      const newChunk = raw.slice(size);
      size = info.size;
      buf += newChunk;
      const lines = buf.split('\n');
      buf = lines.pop() ?? '';
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const ev = JSON.parse(line);
          if (ev.decision === 'block' || ev.decision === 'warn') {
            process.stdout.write(safetyLine(ev) + '\n');
          }
        } catch { /* skip malformed */ }
      }
    } catch { /* file may not exist yet */ }
  }

  let watcher = null;
  let debounce = null;
  try {
    watcher = watch(eventsPath, () => {
      clearTimeout(debounce);
      debounce = setTimeout(check, 80);
    });
    watcher.on('error', () => {});
  } catch { /* file doesn't exist yet, fallback to polling */ }

  const poll = setInterval(check, 500);
  return () => { clearTimeout(debounce); clearInterval(poll); watcher?.close(); };
}

// ── OS Guard policy server ─────────────────────────────────────────────────────
async function maybeStartPolicyServer() {
  if (noServer) return null;
  try {
    const { server, host, port } = await startPolicyServer({ configPath: undefined });
    process.stdout.write(`${C.dim}  OS Guard server listening on ${host}:${port}${C.reset}\n`);
    return server;
  } catch (err) {
    // Port in use or sandboxed — not fatal
    process.stdout.write(`${C.dim}  OS Guard server skipped (${err.code ?? err.message})${C.reset}\n`);
    return null;
  }
}

// ── Spawn one agent ───────────────────────────────────────────────────────────
function spawnAgent(role, brief) {
  return new Promise((resolve) => {
    const proc = spawn(
      'claude',
      ['-p', task, '--system-prompt', brief, '--model', model],
      {
        cwd: PROJECT_ROOT,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env }
      }
    );

    let stdout = '';
    let stderr = '';
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      proc.kill('SIGTERM');
      console.log(`\n${C.yellow}[${role}] timeout after ${timeoutMs / 1000}s — killed${C.reset}`);
    }, timeoutMs);

    proc.stdout.on('data', (chunk) => {
      const text = chunk.toString();
      stdout += text;
      process.stdout.write(prefixLines(role, text) + '\n');
    });

    proc.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

    proc.on('close', (code) => {
      clearTimeout(timer);
      resolve({ role, stdout, stderr, code: code ?? 0, timedOut });
    });

    proc.on('error', (err) => {
      clearTimeout(timer);
      resolve({ role, stdout, stderr: err.message, code: -1, timedOut: false });
    });
  });
}

// ── Main ──────────────────────────────────────────────────────────────────────
const W = process.stdout.columns ?? 72;

console.log(`\n${C.bold}${C.cyan}404gent Multi-Agent Orchestrator${C.reset}`);
console.log('─'.repeat(W));
console.log(`  Task   : ${C.white}"${task}"${C.reset}`);
console.log(`  Agents : ${roles.map(r => tag(r)).join('  ')}`);
console.log(`  Model  : ${model}   Timeout: ${timeoutMs / 1000}s`);
console.log('─'.repeat(W));

// ── Phase 1: Intake scan ──────────────────────────────────────────────────────
console.log(`\n${C.bold}Phase 1 · Safety intake scan${C.reset}`);

const handoffs = {};
for (const role of roles) {
  const handoff = createAgentHandoff({ role, task, config });
  await saveAgentHandoff(handoff, config);
  await record(handoff.promptReport);
  await record(handoff.handoffReport);

  if (handoff.promptReport.decision === 'block') {
    const ruleIds = handoff.promptReport.findings.map(f => f.id).join(', ');
    console.error(`\n${C.red}🚫 BLOCKED at intake (${role}): ${ruleIds}${C.reset}`);
    console.error('  Task contains unsafe content. Aborting all agents.');
    process.exit(1);
  }

  handoffs[role] = handoff;
  console.log(`  ${C.green}✓${C.reset} ${tag(role)} brief ready  (session: ${handoff.sessionId})`);
}

// ── Phase 2: Parallel launch ──────────────────────────────────────────────────
console.log(`\n${C.bold}Phase 2 · Launching ${roles.length} agents in parallel (hooks active)${C.reset}`);

const policyServer = await maybeStartPolicyServer();

// Get current event file size so safety tail only shows NEW events
let initialSize = 0;
try { initialSize = (await stat(eventsPath)).size; } catch { /* not yet created */ }

console.log('─'.repeat(W));
const stopTail = startSafetyTail(initialSize);

const results = await Promise.all(roles.map(role => spawnAgent(role, handoffs[role].brief)));

stopTail();
if (policyServer) policyServer.close();
console.log('─'.repeat(W));

// ── Phase 3: Cross-agent pipe scan ────────────────────────────────────────────
console.log(`\n${C.bold}Phase 3 · Cross-agent pipe scan${C.reset}`);

for (let i = 0; i < results.length - 1; i++) {
  const from   = results[i];
  const toRole = roles[i + 1];

  if (!from.stdout.trim()) {
    console.log(`  ${C.dim}${from.role} → ${toRole}: no output${C.reset}`);
    continue;
  }

  const pipeResult = pipeToAgent({
    fromRole: from.role,
    toRole,
    outputText: from.stdout,
    config
  });
  await record(pipeResult.pipeReport);

  if (pipeResult.blocked) {
    const ids = pipeResult.pipeReport.findings.map(f => f.id).join(', ');
    console.log(`  ${C.red}🚫 ${from.role} → ${toRole}: BLOCKED  [${ids}]${C.reset}`);
  } else {
    console.log(`  ${C.green}✓${C.reset}  ${from.role} → ${toRole}: clean`);
  }
}

// ── Phase 4: Summary ──────────────────────────────────────────────────────────
console.log(`\n${C.bold}Phase 4 · Summary${C.reset}`);
console.log('─'.repeat(W));

for (const r of results) {
  const status = r.timedOut ? `${C.yellow}TIMEOUT${C.reset}`
    : r.code === 0          ? `${C.green}OK${C.reset}`
    :                         `${C.red}exit ${r.code}${C.reset}`;
  console.log(`  ${tag(r.role).padEnd(30)}  ${status}  (${r.stdout.length} chars output)`);
}

console.log('─'.repeat(W));
console.log(`\n${C.bold}✅ Done.${C.reset}  Run ${C.cyan}npm run tower${C.reset} to review all agent events.\n`);
