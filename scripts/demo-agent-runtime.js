import { rm, readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { appendAuditEvent } from '../src/audit.js';
import { updateState } from '../src/state.js';
import { appendVectorDocument } from '../src/vector-store.js';
import { scanText } from '../src/policy/engine.js';
import { createAgentHandoff, saveAgentHandoff } from '../src/harness.js';

const config = { dataDir: '.404gent' };

async function record(report) {
  await appendAuditEvent(report, config);
  await appendVectorDocument(report, config);
  await updateState(report, config);
}

async function recordHandoff(role, task) {
  const handoff = createAgentHandoff({ role, task, config, companyId: 'demo-company' });
  await saveAgentHandoff(handoff, config);
  await record(handoff.promptReport);
  await record(handoff.handoffReport);
}

await rm('.404gent', { recursive: true, force: true });

spawnSync(process.execPath, ['scripts/generate-attack-image.js'], { stdio: 'inherit' });
const metadata = JSON.parse(await readFile('examples/generated/attack-image.regions.json', 'utf8'));

await recordHandoff('qa', '로컬 대시보드 화면을 QA해줘');
await recordHandoff('backend', '404gent 명령 실행 훅과 로그 흐름을 점검해줘');
await recordHandoff('security', '최근 보안 이벤트와 self-loop 룰 후보를 제품 관점에서 요약해줘');

await record(scanText({
  surface: 'image',
  text: metadata.extractedText,
  config,
  source: 'demo-agent-runtime',
  companyId: 'demo-company',
  agentId: 'agent-vision-sentinel',
  evidence: metadata
}));

await record(scanText({
  surface: 'command',
  text: 'rm -rf /',
  config,
  source: 'demo-agent-runtime',
  companyId: 'demo-company',
  agentId: 'agent-policy-arbiter',
  meta: {
    simulated: true,
    note: 'Dangerous command was scanned, not executed.'
  }
}));

await record(scanText({
  surface: 'output',
  text: 'AWS_SECRET_ACCESS_KEY=example',
  config,
  source: 'demo-agent-runtime',
  companyId: 'demo-company',
  agentId: 'agent-policy-arbiter'
}));

spawnSync(process.execPath, ['scripts/self-loop.js'], { stdio: 'inherit' });

console.log(JSON.stringify({
  ok: true,
  dashboard: 'http://127.0.0.1:4040',
  handoffs: '.404gent/handoffs',
  image: metadata.imagePath
}, null, 2));
