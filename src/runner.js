import { spawn } from 'node:child_process';
import { scanText } from './policy/engine.js';

const STREAM_SCAN_HOLDBACK_CHARS = 2048;

function commandToText(args) {
  return args.map((arg) => (/\s/.test(arg) ? JSON.stringify(arg) : arg)).join(' ');
}

function redactText(text, report) {
  let redacted = text;
  for (const finding of report.findings ?? []) {
    const match = finding.match;
    if (!match) {
      continue;
    }
    redacted = redacted.split(match).join('[REDACTED]');
  }
  return redacted;
}

function scanAndRedactOutputChunk(chunk, { config, stream, commandText }) {
  const text = String(chunk ?? '');
  const report = scanText({
    surface: 'output',
    text,
    config,
    source: 'runner-stream',
    meta: {
      command: commandText,
      stream
    }
  });
  return {
    text,
    displayText: report.findings.length > 0 ? redactText(text, report) : text,
    report
  };
}

function createOutputStreamScanner({ config, stream, commandText, writer, originalChunks, streamReports }) {
  let pending = '';

  function scanAndWrite(text) {
    if (!text) {
      return;
    }
    const scanned = scanAndRedactOutputChunk(text, { config, stream, commandText });
    streamReports.push(scanned.report);
    writer.write(scanned.displayText);
  }

  return {
    write(chunk) {
      const text = chunk.toString();
      originalChunks.push(text);
      pending += text;

      const pendingReport = scanAndRedactOutputChunk(pending, { config, stream, commandText }).report;
      if (pendingReport.findings.length > 0) {
        streamReports.push(pendingReport);
        writer.write(redactText(pending, pendingReport));
        pending = '';
        return;
      }

      if (pending.length > STREAM_SCAN_HOLDBACK_CHARS) {
        const emitLength = pending.length - STREAM_SCAN_HOLDBACK_CHARS;
        scanAndWrite(pending.slice(0, emitLength));
        pending = pending.slice(emitLength);
      }
    },

    flush() {
      scanAndWrite(pending);
      pending = '';
    }
  };
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
  const streamReports = [];

  const exitCode = await new Promise((resolve, reject) => {
    const child = spawnImpl(args[0], args.slice(1), {
      stdio: ['inherit', 'pipe', 'pipe'],
      shell: false
    });
    const stdoutScanner = createOutputStreamScanner({
      config,
      stream: 'stdout',
      commandText,
      writer: stdout,
      originalChunks: stdoutChunks,
      streamReports
    });
    const stderrScanner = createOutputStreamScanner({
      config,
      stream: 'stderr',
      commandText,
      writer: stderr,
      originalChunks: stderrChunks,
      streamReports
    });

    child.on('error', reject);
    child.stdout.on('data', (chunk) => stdoutScanner.write(chunk));
    child.stderr.on('data', (chunk) => stderrScanner.write(chunk));
    child.on('close', (code) => {
      stdoutScanner.flush();
      stderrScanner.flush();
      resolve(code ?? 0);
    });
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
    streamReports,
    stdoutText,
    stderrText
  };
}
