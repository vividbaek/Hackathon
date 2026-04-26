#!/usr/bin/env node
import { loadConfig } from './config.js';
import { mergeReports, scanText } from './policy/engine.js';
import { appendAuditEvent } from './audit.js';
import { updateState } from './state.js';
import { appendVectorDocument } from './vector-store.js';
import { createLlmProvider, shouldReviewWithLlm } from './providers/llm.js';
import { encodeImageFile, createVisionProviderFromConfig } from './providers/vision-llm.js';
import { highestSeverity } from './policy/severity.js';
import { runGuardedCommand } from './runner.js';
import { createAgentHandoff } from './harness.js';

const HELP = `404gent - Terminal-first guardrails for AI coding agents in cmux.

Usage:
  404gent help
  404gent scan-prompt <text>
  404gent scan-command <command>
  404gent scan-output <text>
  404gent scan-image <vlm-or-ocr-text>
  404gent scan-image --file <image-path>
  404gent scan-llm <text>
  404gent agent --role <qa|backend|security> -- <task>
  404gent run -- <command> [args...]
  404gent doctor
  404gent tower

Options:
  --config <path>   Load a JSON config file.
  --file <path>     Image file path for scan-image (enables Claude Vision analysis).
  --role <role>     Agent harness role. Defaults to qa.
  --json            Print machine-readable JSON.
`;

function parseArgs(argv) {
  const args = [...argv];
  const options = { json: false, configPath: undefined, filePath: undefined, role: 'qa' };
  const positionals = [];
  const separatorIndex = args.indexOf('--');
  let passthrough = [];

  if (separatorIndex >= 0) {
    passthrough = args.splice(separatorIndex + 1);
    args.splice(separatorIndex, 1);
  }

  while (args.length > 0) {
    const arg = args.shift();
    if (arg === '--json') {
      options.json = true;
    } else if (arg === '--config') {
      options.configPath = args.shift();
    } else if (arg === '--file') {
      options.filePath = args.shift();
    } else if (arg === '--role') {
      options.role = args.shift() ?? 'qa';
    } else {
      positionals.push(arg);
    }
  }

  return { command: positionals[0] ?? 'help', text: positionals.slice(1).join(' '), options, passthrough };
}

function printResult(result, json) {
  if (json) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  console.log(`${result.surface}: ${result.decision.toUpperCase()} (${result.severity})`);

  const hiddenPrompts = result.event?.evidence?.hiddenPrompts ?? [];
  if (hiddenPrompts.length > 0) {
    console.log(`\n[!] Hidden prompt injection detected (${hiddenPrompts.length} found):`);
    for (const prompt of hiddenPrompts) {
      console.log(`    >> "${prompt}"`);
    }
  }

  const objects = result.event?.evidence?.objects ?? [];
  const suspicious = objects.filter((o) => o.suspicious);
  if (suspicious.length > 0) {
    console.log(`\n[!] Suspicious objects detected: ${suspicious.map((o) => o.label).join(', ')}`);
  }

  if (result.findings.length > 0) {
    console.log('');
  }
  for (const finding of result.findings) {
    console.log(`- [${finding.severity}] ${finding.id}: ${finding.rationale}`);
  }
}

export async function main(argv = process.argv.slice(2)) {
  const { command, text, options, passthrough } = parseArgs(argv);

  if (command === 'help' || command === '--help' || command === '-h') {
    console.log(HELP);
    return 0;
  }

  const config = await loadConfig({ configPath: options.configPath });

  if (command === 'doctor') {
    const result = { ok: true, node: process.versions.node, config };
    console.log(options.json ? JSON.stringify(result, null, 2) : '404gent doctor: ok');
    return 0;
  }

  if (command === 'tower') {
    console.log('404gent tower: runtime guardrail console is not implemented yet.');
    return 0;
  }

  async function recordReport(report) {
    await appendAuditEvent(report, config);
    await appendVectorDocument(report, config);
    await updateState(report, config);
  }

  if (command === 'run') {
    const result = await runGuardedCommand(passthrough.length > 0 ? passthrough : text.split(' ').filter(Boolean), {
      config,
      recordReport
    });
    return result.exitCode;
  }

  if (command === 'agent') {
    const task = passthrough.length > 0 ? passthrough.join(' ') : text;
    const handoff = createAgentHandoff({ role: options.role, task, config });
    await recordReport(handoff.promptReport);
    await recordReport(handoff.handoffReport);
    if (options.json) {
      console.log(JSON.stringify(handoff, null, 2));
    } else {
      console.log(handoff.brief);
    }
    return handoff.promptReport.decision === 'block' ? 1 : 0;
  }

  const surfaces = {
    'scan-prompt': 'prompt',
    'scan-command': 'command',
    'scan-output': 'output',
    'scan-image': 'image',
    'scan-llm': 'llm'
  };

  const surface = surfaces[command];
  if (!surface) {
    console.error(`Unknown command: ${command}`);
    console.error(HELP);
    return 2;
  }

  // Vision analysis path: actual image file via Claude Vision API
  if (surface === 'image' && options.filePath) {
    const encoded = await encodeImageFile(options.filePath);
    const visionProvider = createVisionProviderFromConfig(config);
    const visionResult = await visionProvider.analyzeImage(encoded);

    // Build scan text from extracted hidden content
    const scanInput = [
      ...visionResult.hiddenPrompts,
      ...(visionResult.regions ?? []).map((r) => r.text).filter(Boolean)
    ].join('\n') || text;

    let result = scanText({
      surface: 'image',
      text: scanInput,
      config,
      evidence: {
        hiddenPrompts: visionResult.hiddenPrompts,
        objects: visionResult.objects,
        regions: visionResult.regions,
        imagePath: options.filePath
      }
    });

    if (!visionResult.skipped) {
      const merged = mergeReports(result, visionResult, config);
      result = {
        ...merged,
        surface: 'image',
        text: scanInput,
        severity: merged.findings.length > 0 ? highestSeverity(merged.findings) : 'low',
        scannedAt: result.scannedAt
      };
    }

    await recordReport(result);
    printResult(result, options.json);
    return result.decision === 'block' ? 1 : 0;
  }

  // Generic text scan for all other surfaces (and scan-image without --file)
  let result = scanText({ surface, text, config });
  if (shouldReviewWithLlm(result, config)) {
    const llmReport = await createLlmProvider(config).evaluate(result);
    const merged = mergeReports(result, llmReport, config);
    result = {
      ...merged,
      surface,
      text: String(text ?? ''),
      severity: merged.findings.length > 0 ? highestSeverity(merged.findings) : 'low',
      scannedAt: result.scannedAt
    };
  }
  await recordReport(result);
  printResult(result, options.json);
  return result.decision === 'block' ? 1 : 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = await main();
}
