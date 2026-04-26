import { execFile } from 'node:child_process';

const DEFAULT_DAEMON_ENDPOINT = 'http://127.0.0.1:7405';

export function daemonEndpointFromEnv(env = process.env) {
  return env.FOURGENT_DAEMON_ENDPOINT ?? DEFAULT_DAEMON_ENDPOINT;
}

export async function registerPidWithDaemon({ pid, agent, endpoint = daemonEndpointFromEnv() } = {}) {
  if (!pid || Number.isNaN(Number(pid))) {
    throw new Error('registerPidWithDaemon requires a numeric pid.');
  }

  const response = await fetch(new URL('/register-pid', endpoint), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ pid: Number(pid), agent })
  });

  if (!response.ok) {
    throw new Error(`Daemon PID registration failed: HTTP ${response.status}`);
  }

  return response.json();
}

export async function fetchDaemonStatus({ endpoint = daemonEndpointFromEnv() } = {}) {
  const response = await fetch(new URL('/status', endpoint));
  if (!response.ok) {
    throw new Error(`Daemon status failed: HTTP ${response.status}`);
  }
  return response.json();
}

export async function findProcessIdsByNames(names = []) {
  const uniqueNames = [...new Set(names.map((name) => String(name).trim()).filter(Boolean))];
  const pairs = await Promise.all(uniqueNames.map(async (name) => {
    const pids = await pgrepExact(name);
    return pids.map((pid) => ({ name, pid }));
  }));
  return pairs.flat();
}

function pgrepExact(name) {
  return new Promise((resolve) => {
    execFile('pgrep', ['-x', name], (error, stdout) => {
      if (error) {
        resolve([]);
        return;
      }
      resolve(stdout.split(/\s+/).filter(Boolean).map((pid) => Number(pid)));
    });
  });
}
