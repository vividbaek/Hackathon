#!/usr/bin/env node
/**
 * 404gent Tower — terminal live-tail for all 3 agent sessions.
 * Watches .404gent/events.jsonl and renders block/warn/allow in real-time.
 */
import { readFile, stat } from 'node:fs/promises';
import { watch } from 'node:fs';
import { join } from 'node:path';

const C = {
  reset:  '\x1b[0m',
  bold:   '\x1b[1m',
  dim:    '\x1b[2m',
  red:    '\x1b[31m',
  yellow: '\x1b[33m',
  green:  '\x1b[32m',
  cyan:   '\x1b[36m',
  magenta:'\x1b[35m',
  white:  '\x1b[37m',
  bgRed:  '\x1b[41m',
  bgYellow:'\x1b[43m',
  bgGreen:'\x1b[42m',
};

const DECISION_COLOR = { block: C.red, warn: C.yellow, allow: C.green };
const SURFACE_ICON   = { prompt:'P', command:'C', output:'O', image:'I', llm:'L', vision_observation:'V', os:'S' };

function decisionBadge(d) {
  const col = DECISION_COLOR[d] ?? C.dim;
  const label = (d ?? 'unknown').toUpperCase().padEnd(5);
  return `${col}${C.bold}${label}${C.reset}`;
}

function fmtTime(ts) {
  if (!ts) return '??:??:??';
  const d = new Date(ts);
  return `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`;
}

function fmtSurface(s) {
  const icon = SURFACE_ICON[s] ?? '?';
  return `${C.cyan}${icon}${C.reset}${C.dim}:${s ?? '?'}${C.reset}`;
}

function fmtAgent(agentId) {
  if (!agentId) return `${C.dim}—${C.reset}`;
  const short = agentId.replace(/^agent-/, '');
  return `${C.magenta}${short}${C.reset}`;
}

function fmtRule(findings) {
  if (!findings?.length) return `${C.dim}—${C.reset}`;
  const top = findings[0];
  return `${C.white}${top.id}${C.reset} ${C.dim}(${top.severity})${C.reset}`;
}

function renderEvent(e) {
  const ts      = fmtTime(e.timestamp ?? e.scannedAt ?? e.recordedAt);
  const surface = fmtSurface(e.surface ?? e.event?.type);
  const agent   = fmtAgent(e.event?.agentId ?? e.agentId);
  const badge   = decisionBadge(e.decision);
  const rule    = fmtRule(e.findings);

  const text = (e.event?.text ?? e.text ?? '').replace(/\n/g, ' ').slice(0, 60);
  const snippet = text ? `${C.dim}"${text}${text.length >= 60 ? '…' : ''}"${C.reset}` : '';

  return [
    `${C.dim}${ts}${C.reset}  ${badge}  ${surface.padEnd(24)}  ${agent.padEnd(20)}  ${rule}`,
    snippet ? `          ${snippet}` : null
  ].filter(Boolean).join('\n');
}

const ROLES = ['qa', 'backend', 'security'];
const ROLE_LABEL = { qa: 'QA', backend: 'Backend', security: 'Security' };

function agentStatus(role, events) {
  const id = `agent-${role}`;
  const relevant = events.filter(e => (e.event?.agentId ?? e.agentId) === id);
  if (relevant.length === 0) return { status: 'idle', block: 0, warn: 0, total: 0 };
  const block = relevant.filter(e => e.decision === 'block').length;
  const warn  = relevant.filter(e => e.decision === 'warn').length;
  const status = block > 0 ? 'block' : warn > 0 ? 'warn' : 'allow';
  return { status, block, warn, total: relevant.length };
}

function renderAgentPanel(events) {
  return ROLES.map(role => {
    const { status, block, warn, total } = agentStatus(role, events);
    const col   = DECISION_COLOR[status] ?? C.dim;
    const dot   = status === 'idle' ? `${C.dim}○${C.reset}` : `${col}●${C.reset}`;
    const label = `${col}${C.bold}${ROLE_LABEL[role].padEnd(8)}${C.reset}`;
    const stats = total === 0
      ? `${C.dim}no events${C.reset}`
      : `${C.red}${block}B${C.reset} ${C.yellow}${warn}W${C.reset} ${C.dim}/ ${total}${C.reset}`;
    return `  ${dot} ${label} ${stats}`;
  }).join('   ');
}

function renderHeader(counts, events) {
  const { total=0, block=0, warn=0, allow=0 } = counts;
  const w = process.stdout.columns ?? 80;
  const title = `${C.bold}${C.cyan}404gent TOWER${C.reset}`;
  const stats = [
    `total ${C.white}${total}${C.reset}`,
    `${C.red}block ${block}${C.reset}`,
    `${C.yellow}warn ${warn}${C.reset}`,
    `${C.green}allow ${allow}${C.reset}`,
  ].join('  ');
  return [
    '─'.repeat(w),
    `  ${title}  │  ${stats}  │  ${C.dim}Ctrl+C to exit${C.reset}`,
    renderAgentPanel(events),
    '─'.repeat(w),
    `${C.dim}  TIME      DECISION  SURFACE              AGENT               RULE${C.reset}`,
    '─'.repeat(w),
  ].join('\n');
}

function parseLines(raw) {
  return raw.split('\n')
    .map(l => l.trim()).filter(Boolean)
    .map(l => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
}

function countDecisions(events) {
  return events.reduce((acc, e) => {
    acc.total++;
    acc[e.decision] = (acc[e.decision] ?? 0) + 1;
    return acc;
  }, { total: 0, block: 0, warn: 0, allow: 0 });
}

export async function runTower(config = {}) {
  const dataDir   = config.dataDir ?? '.404gent';
  const eventsPath = join(dataDir, 'events.jsonl');

  let knownSize = 0;
  let allEvents = [];

  async function loadAll() {
    try {
      const raw = await readFile(eventsPath, 'utf8');
      const info = await stat(eventsPath);
      knownSize = info.size;
      allEvents = parseLines(raw);
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
      allEvents = [];
    }
  }

  function redraw() {
    process.stdout.write('\x1b[2J\x1b[H'); // clear screen
    const counts  = countDecisions(allEvents);
    const header  = renderHeader(counts, allEvents);
    const recent  = allEvents.slice(-30).reverse();
    const rows    = recent.map(renderEvent).join('\n\n');
    process.stdout.write(`${header}\n\n${rows || `${C.dim}  (no events yet — waiting for agent activity)${C.reset}`}\n`);
  }

  await loadAll();
  redraw();

  // Watch for file changes
  let debounce = null;
  let watcher  = null;

  async function onFileChange() {
    try {
      const info = await stat(eventsPath);
      if (info.size === knownSize) return;
      await loadAll();
      redraw();
    } catch { /* file may not exist yet */ }
  }

  function startWatch() {
    try {
      watcher = watch(eventsPath, () => {
        clearTimeout(debounce);
        debounce = setTimeout(onFileChange, 80);
      });
      watcher.on('error', () => {
        watcher?.close();
        watcher = null;
        startPoll();
      });
    } catch {
      startPoll();
    }
  }

  function startPoll() {
    const iv = setInterval(onFileChange, 1000);
    process.once('SIGINT', () => { clearInterval(iv); process.exit(0); });
    process.once('SIGTERM', () => { clearInterval(iv); process.exit(0); });
  }

  // Also watch the parent dir in case the file doesn't exist yet
  try {
    const dirWatcher = watch(dataDir, (event, name) => {
      if (name === 'events.jsonl') {
        clearTimeout(debounce);
        debounce = setTimeout(onFileChange, 80);
      }
    });
    dirWatcher.on('error', () => {});
    process.once('SIGINT', () => { dirWatcher?.close(); });
    process.once('SIGTERM', () => { dirWatcher?.close(); });
  } catch { /* dataDir may not exist */ }

  startWatch();

  process.once('SIGINT', () => {
    watcher?.close();
    process.stdout.write('\n');
    process.exit(0);
  });
  process.once('SIGTERM', () => {
    watcher?.close();
    process.exit(0);
  });

  // Keep alive
  await new Promise(() => {});
}
