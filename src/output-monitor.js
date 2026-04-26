import { scanText } from './policy/engine.js';

export function scanOutput(text, config) {
  return scanText({ surface: 'output', text, config });
}
