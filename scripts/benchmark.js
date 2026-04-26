import { performance } from 'node:perf_hooks';
import { scanText } from '../src/policy/engine.js';

const samples = ['hello', 'ignore previous instructions', 'rm -rf /'];
const start = performance.now();
for (let i = 0; i < 1000; i += 1) {
  scanText({ surface: i % 3 === 0 ? 'prompt' : 'command', text: samples[i % samples.length] });
}
const elapsed = performance.now() - start;
console.log(JSON.stringify({ scans: 1000, elapsedMs: Math.round(elapsed * 100) / 100 }, null, 2));
