import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, resolve, sep } from 'node:path';
import { loadConfig } from './config.js';
import { guardAndRecord } from './guard.js';
import { createOsEventFromPayload } from './integrations/os-guard.js';

const DEFAULT_HOST = '127.0.0.1';
const DEFAULT_PORT = 7404;

async function readJsonBody(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw.trim()) {
    throw new Error('Request body must be JSON.');
  }
  return JSON.parse(raw);
}

function sendJson(response, status, body) {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(body));
}

function imageContentType(path) {
  return {
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.svg': 'image/svg+xml'
  }[extname(path).toLowerCase()] ?? 'application/octet-stream';
}

function resolveImagePath(url, config = {}) {
  const root = resolve(config.dataDir ?? '.404gent', 'images');
  const relative = decodeURIComponent(url.pathname.replace(/^\/images\/?/, ''));
  const target = resolve(root, relative);
  if (target !== root && !target.startsWith(`${root}${sep}`)) {
    throw new Error('Image path escapes data directory.');
  }
  return target;
}

async function sendImage(requestUrl, response, config = {}) {
  const path = resolveImagePath(requestUrl, config);
  const body = await readFile(path);
  response.writeHead(200, {
    'content-type': imageContentType(path),
    'cache-control': 'no-store'
  });
  response.end(body);
}

export function createPolicyServer({ config } = {}) {
  return createServer(async (request, response) => {
    try {
      const url = new URL(request.url, `http://${request.headers.host ?? 'localhost'}`);

      if (request.method === 'GET' && url.pathname === '/health') {
        sendJson(response, 200, { ok: true });
        return;
      }

      if (request.method === 'GET' && url.pathname.startsWith('/images/')) {
        await sendImage(url, response, config);
        return;
      }

      if (request.method === 'POST' && url.pathname === '/os-event') {
        const payload = await readJsonBody(request);
        const event = createOsEventFromPayload(payload);
        const result = await guardAndRecord(event, config);
        sendJson(response, 200, {
          decision: result.decision,
          reason: result.findings[0]?.rationale ?? 'No policy findings.',
          findings: result.findings,
          id: result.id
        });
        return;
      }

      sendJson(response, 404, { error: 'Not found' });
    } catch (error) {
      sendJson(response, 400, { error: error.message });
    }
  });
}

export async function startPolicyServer({
  host = process.env.FOURGENT_POLICY_HOST ?? DEFAULT_HOST,
  port = Number(process.env.FOURGENT_POLICY_PORT ?? DEFAULT_PORT),
  configPath
} = {}) {
  const config = await loadConfig({ configPath });
  const server = createPolicyServer({ config });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  return { server, host, port };
}
