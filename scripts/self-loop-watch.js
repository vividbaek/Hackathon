#!/usr/bin/env node
import { loadConfig } from '../src/config.js';
import { analyze, status } from '../src/learn/index.js';

const DEFAULT_INTERVAL_MS = 60_000;

function intervalMs() {
  const raw = Number(process.env.FOUR04GENT_SELF_LOOP_INTERVAL_SECONDS ?? 60);
  if (!Number.isFinite(raw) || raw <= 0) {
    return DEFAULT_INTERVAL_MS;
  }
  return Math.max(5, raw) * 1000;
}

function print(event) {
  process.stdout.write(`${JSON.stringify({ timestamp: new Date().toISOString(), ...event })}\n`);
}

async function tick(config) {
  const current = await status(config);
  if (!current.ready) {
    print({
      ok: true,
      analyzed: false,
      reason: current.cooldownElapsed
        ? `Trigger not ready: ${current.events}/${current.minEvents} risky events.`
        : `Cooldown active until ${current.lastAnalyzedAt}.`,
      status: current
    });
    return;
  }

  const result = await analyze(config, {
    manual: false,
    windowMinutes: Number(process.env.FOUR04GENT_SELF_LOOP_MINUTES ?? 30)
  });
  print({
    ok: result.ok,
    analyzed: result.analyzed,
    proposed: result.proposed ?? 0,
    shadowRules: result.shadowRules ?? 0,
    paths: result.paths
  });
}

const config = await loadConfig();
const delay = intervalMs();
print({ ok: true, mode: 'self-loop-watch', intervalMs: delay });

await tick(config);
setInterval(() => {
  tick(config).catch((error) => {
    print({ ok: false, error: error.message });
  });
}, delay);
