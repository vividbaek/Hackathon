import { scanText } from '../policy/engine.js';

export function scanCmuxPayload({ surface, text, config }) {
  return scanText({ surface, text, config });
}

export function scanCmuxEvent({ type, text, config, ...rest }) {
  return scanText({ surface: type, text, config, ...rest });
}
