import { spawn } from 'node:child_process';
import { scanText } from './policy/engine.js';

function commandToText(args) {
  return args.map((arg) => (/\s/.test(arg) ? JSON.stringify(arg) : arg)).join(' ');
}

function appendChunk(chunks, chunk) {
  const text = chunk.toString();
  chunks.push(text);
  return text;
}

export async function runGuardedCommand(args, {
  config = {},
  recordReport,
  stdout = process.stdout,
  stderr = process.stderr,
  spawnImpl = spawn
} = {}) {
  if (!Array.isArray(args) || args.length === 0) {
    throw new Error('run requires a command after --');
  }

  const commandText = commandToText(args);
  const commandReport = scanText({
    surface: 'command',
    text: commandText,
    config,
    source: 'runner',
    meta: { argv: args }
  });

  if (recordReport) {
    await recordReport(commandReport);
  }

  if (commandReport.decision === 'block') {
    stderr.write(`404gent blocked command: ${commandText}\n`);
    return {
      exitCode: 126,
      commandReport,
      outputReport: null,
      stdoutText: '',
      stderrText: 'blocked'
    };
  }

  const stdoutChunks = [];
  const stderrChunks = [];

  const exitCode = await new Promise((resolve, reject) => {
    const child = spawnImpl(args[0], args.slice(1), {
      stdio: ['inherit', 'pipe', 'pipe'],
      shell: false
    });

    child.on('error', reject);
    child.stdout.on('data', (chunk) => stdout.write(appendChunk(stdoutChunks, chunk)));
    child.stderr.on('data', (chunk) => stderr.write(appendChunk(stderrChunks, chunk)));
    child.on('close', (code) => resolve(code ?? 0));
  });

  const stdoutText = stdoutChunks.join('');
  const stderrText = stderrChunks.join('');
  const combinedOutput = [stdoutText, stderrText].filter(Boolean).join('\n');
  const outputReport = scanText({
    surface: 'output',
    text: combinedOutput,
    config,
    source: 'runner',
    meta: {
      command: commandText,
      exitCode
    }
  });

  if (recordReport) {
    await recordReport(outputReport);
  }

  if (outputReport.decision === 'block') {
    stderr.write('\n404gent detected sensitive or unsafe output.\n');
  }

  return {
    exitCode,
    commandReport,
    outputReport,
    stdoutText,
    stderrText
  };
}
