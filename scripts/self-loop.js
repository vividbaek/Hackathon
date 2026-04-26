#!/usr/bin/env node
import { loadConfig } from '../src/config.js';
import { analyze } from '../src/learn/index.js';

const config = await loadConfig();
const result = await analyze(config, {
  manual: true,
  windowMinutes: Number(process.env.FOUR04GENT_SELF_LOOP_MINUTES ?? 30)
});

console.log(JSON.stringify({
  ok: result.ok,
  candidates: result.proposed ?? 0,
  path: result.paths?.ruleCandidates ?? '.404gent/rule-candidates.json'
}, null, 2));
