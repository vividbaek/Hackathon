function quoteValue(value) {
  return JSON.stringify(String(value ?? ''));
}

function normalizeArgv(argv = []) {
  if (Array.isArray(argv)) {
    return argv.map((arg) => String(arg)).filter(Boolean);
  }
  return String(argv ?? '').split(/\s+/).filter(Boolean);
}

function eventSource(agent) {
  return agent ? `agent:${agent}:os` : 'os-guard';
}

export function createOpenEvent(path, options = {}) {
  const agent = options.agent ? String(options.agent) : undefined;
  const mode = options.mode ?? 'simulate';
  const meta = {
    operation: 'open',
    path: String(path ?? ''),
    agent,
    pid: options.pid === undefined ? undefined : Number(options.pid),
    mode,
    authDecision: options.authDecision,
    reason: options.reason,
    cache: options.cache
  };

  return {
    type: 'os',
    text: `os open path=${quoteValue(meta.path)} pid=${meta.pid ?? ''} agent=${agent ?? ''} mode=${mode}`,
    source: eventSource(agent),
    meta
  };
}

export function createExecEvent(argv, options = {}) {
  const normalizedArgv = normalizeArgv(argv);
  const agent = options.agent ? String(options.agent) : undefined;
  const mode = options.mode ?? 'simulate';
  const executable = options.executable ?? normalizedArgv[0];
  const meta = {
    operation: 'exec',
    argv: normalizedArgv,
    executable,
    agent,
    pid: options.pid === undefined ? undefined : Number(options.pid),
    mode
  };

  return {
    type: 'os',
    text: `os exec argv=${quoteValue(normalizedArgv.join(' '))} executable=${quoteValue(executable ?? '')} pid=${meta.pid ?? ''} agent=${agent ?? ''} mode=${mode}`,
    source: eventSource(agent),
    meta
  };
}

export function createUnlinkEvent(path, options = {}) {
  const agent = options.agent ? String(options.agent) : undefined;
  const mode = options.mode ?? 'simulate';
  const meta = {
    operation: 'unlink',
    path: String(path ?? ''),
    agent,
    pid: options.pid === undefined ? undefined : Number(options.pid),
    mode
  };

  return {
    type: 'os',
    text: `os unlink path=${quoteValue(meta.path)} pid=${meta.pid ?? ''} agent=${agent ?? ''} mode=${mode}`,
    source: eventSource(agent),
    meta
  };
}

export function createOsEventFromPayload(payload = {}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('OS event payload must be a JSON object.');
  }

  if (payload.type === 'open') {
    if (typeof payload.path !== 'string' || payload.path.trim() === '') {
      throw new Error('OS open event requires a non-empty path string.');
    }
    return createOpenEvent(payload.path, {
      agent: payload.agent,
      pid: payload.pid,
      mode: payload.mode ?? 'native-notify',
      authDecision: payload.authDecision,
      reason: payload.reason,
      cache: payload.cache
    });
  }

  if (payload.type === 'exec') {
    const argv = Array.isArray(payload.argv) ? payload.argv : undefined;
    if ((!argv || argv.length === 0) && typeof payload.executable !== 'string') {
      throw new Error('OS exec event requires a non-empty argv array or executable string.');
    }
    return createExecEvent(argv ?? [payload.executable], {
      agent: payload.agent,
      pid: payload.pid,
      mode: payload.mode ?? 'native-notify',
      executable: payload.executable
    });
  }

  if (payload.type === 'unlink') {
    if (typeof payload.path !== 'string' || payload.path.trim() === '') {
      throw new Error('OS unlink event requires a non-empty path string.');
    }
    return createUnlinkEvent(payload.path, {
      agent: payload.agent,
      pid: payload.pid,
      mode: payload.mode ?? 'simulate'
    });
  }

  throw new Error(`Unsupported OS event type: ${payload.type}`);
}
