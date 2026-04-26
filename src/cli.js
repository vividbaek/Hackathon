#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { applyCompanyProfile, loadConfig } from './config.js';
import { mergeReports, scanText } from './policy/engine.js';
import { encodeImageFile, createVisionProviderFromConfig } from './providers/vision-llm.js';
import { preprocessImage } from './image-preprocess.js';
import { normalizePreprocessedImageResult } from './vision.js';
import { highestSeverity } from './policy/severity.js';
import { runGuardedCommand } from './runner.js';
import { createAgentHandoff, saveAgentHandoff, pipeToAgent } from './harness.js';
import { runTower } from './tower.js';
import { guardAndRecord, recordReport } from './guard.js';
import { startPolicyServer } from './server.js';
import { createExecEvent, createOpenEvent, createUnlinkEvent } from './integrations/os-guard.js';
import { fetchDaemonStatus, findProcessIdsByNames, registerPidWithDaemon } from './integrations/es-daemon.js';
import {
  analyze as analyzeLearn,
  approveRule,
  pending as pendingLearn,
  rejectRule,
  shadowStatus,
  status as learnStatus,
  testRule
} from './learn/index.js';

const HELP = `404gent - Terminal-first guardrails for AI coding agents in cmux.

Usage:
  404gent help
  404gent scan-prompt <text>
  404gent scan-command <command>
  404gent scan-output <text>
  404gent scan-image <vlm-or-ocr-text>
  404gent scan-image --file <image-path>
  404gent scan-image --preprocessed <json-path>
  404gent preprocess-image <image-path>
  404gent scan-llm <text>
  404gent agent --role <qa|backend|security> -- <task>
  404gent pipe --role <from> --to <to> -- <output-text>
  404gent run -- <command> [args...]
  404gent server
  404gent os-guard status
  404gent os-guard simulate-open <path> [--agent name] [--pid pid]
  404gent os-guard simulate-exec <command...> [--agent name] [--pid pid]
  404gent os-guard simulate-unlink <path> [--agent name] [--pid pid]
  404gent os-guard register-existing [--names codex,claude,gemini,opencode]
  404gent learn status
  404gent learn analyze
  404gent learn pending
  404gent learn shadow-status
  404gent learn test --rule <id>
  404gent learn approve --rule <id>
  404gent learn reject --rule <id>
  404gent agent --name demo --with-os-guard -- <command>
  404gent doctor
  404gent tower

Options:
  --config <path>   Load a JSON config file.
  --file <path>     Image file path for scan-image (enables Claude Vision analysis).
  --preprocessed <path>
                    Preprocessed image JSON for scan-image.
  --role <role>     Agent harness role. Defaults to qa.
  --company <id>    Company profile id for agent handoff metadata.
  --json            Print machine-readable JSON.
  --agent <name>    Agent name for OS Guard events.
  --pid <pid>       Process id for OS Guard events.
  --names <names>   Comma-separated process names for register-existing.
  --with-os-guard   Register spawned agent process with OS Guard.
  --rule <id>       Rule id for learn test/approve/reject.
`;

function parseArgs(argv) {
  const args = [...argv];
  const options = {
    json: false,
    configPath: undefined,
    filePath: undefined,
    preprocessedPath: undefined,
    role: 'qa',
    to: undefined,
    companyId: undefined,
    agent: undefined,
    pid: undefined,
    names: undefined,
    withOsGuard: false,
    name: undefined,
    rule: undefined
  };
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
    } else if (arg === '--preprocessed') {
      options.preprocessedPath = args.shift();
    } else if (arg === '--role') {
      options.role = args.shift() ?? 'qa';
    } else if (arg === '--to') {
      options.to = args.shift();
    } else if (arg === '--company') {
      options.companyId = args.shift();
    } else if (arg === '--agent' || arg === '--name') {
      const value = args.shift();
      options.agent = value;
      options.name = value;
    } else if (arg === '--pid') {
      options.pid = Number(args.shift());
    } else if (arg === '--names') {
      options.names = args.shift();
    } else if (arg === '--with-os-guard') {
      options.withOsGuard = true;
    } else if (arg === '--rule') {
      options.rule = args.shift();
    } else {
      positionals.push(arg);
    }
  }

  return { command: positionals[0] ?? 'help', text: positionals.slice(1).join(' '), options, passthrough, positionals };
}

import { execSync } from 'node:child_process';

function notifyBlock(result) {
  const ruleId = result.findings[0]?.id ?? 'unknown-rule';
  const sev = result.severity ?? 'high';
  const surface = result.surface ?? '?';
  const msg = `🚫 [404gent BLOCK] ${surface.toUpperCase()} | ${ruleId} (${sev})`;
  // tmux: display-message in status bar (works inside cmux/tmux session)
  if (process.env.TMUX) {
    try { execSync(`tmux display-message -p "${msg.replace(/"/g, "'")}"`); } catch {}
  }
  // macOS system notification (fallback)
  if (process.platform === 'darwin') {
    try {
      execSync(`osascript -e 'display notification "${msg.replace(/"/g, "'")}" with title "404gent 보안 차단"'`);
    } catch {}
  }
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

  if (result.decision === 'block') {
    notifyBlock(result);
  }
}

export async function main(argv = process.argv.slice(2)) {
  const { command, text, options, passthrough, positionals } = parseArgs(argv);

  if (command === 'help' || command === '--help' || command === '-h') {
    console.log(HELP);
    return 0;
  }

  let config = await loadConfig({ configPath: options.configPath });
  if (options.companyId) {
    config = applyCompanyProfile(config, options.companyId);
  }

  if (command === 'doctor') {
    const result = { ok: true, node: process.versions.node, config };
    console.log(options.json ? JSON.stringify(result, null, 2) : '404gent doctor: ok');
    return 0;
  }

  if (command === 'tower') {
    await runTower(config);
    return 0;
  }

  if (command === 'run') {
    const result = await runGuardedCommand(passthrough.length > 0 ? passthrough : text.split(' ').filter(Boolean), {
      config,
      recordReport: (report) => recordReport(report, config)
    });
    return result.exitCode;
  }

  if (command === 'agent') {
    if (options.withOsGuard) {
      return handleAgentCommand({ argv: passthrough, options });
    }
    const task = passthrough.length > 0 ? passthrough.join(' ') : text;
    const handoff = createAgentHandoff({ role: options.role, task, config, companyId: config.companyId });
    const paths = await saveAgentHandoff(handoff, config);
    await recordReport(handoff.promptReport, config);
    await recordReport(handoff.handoffReport, config);
    if (options.json) {
      console.log(JSON.stringify({ ...handoff, paths }, null, 2));
    } else {
      console.log(handoff.brief);
      console.log(`\nSaved handoff: ${paths.rolePath}`);
    }
    return handoff.promptReport.decision === 'block' ? 1 : 0;
  }

  if (command === 'pipe') {
    const fromRole   = options.role;
    const toRole     = options.to;
    const outputText = passthrough.length > 0 ? passthrough.join(' ') : text;

    if (!toRole) {
      console.error('pipe requires --to <role>  (e.g. --to backend)');
      return 2;
    }

    const result = pipeToAgent({ fromRole, toRole, outputText, config, companyId: config.companyId });
    await recordReport(result.pipeReport, config);

    if (result.blocked) {
      if (options.json) {
        console.log(JSON.stringify({ blocked: true, pipeReport: result.pipeReport }, null, 2));
      } else {
        console.error(`\n🚫 Pipe BLOCKED (${fromRole} → ${toRole}): cross-agent contamination detected.`);
        for (const f of result.pipeReport.findings) {
          console.error(`  [${f.severity}] ${f.id}: ${f.rationale}`);
        }
      }
      return 1;
    }

    const paths = await saveAgentHandoff(result.handoff, config);
    await recordReport(result.handoff.promptReport, config);
    await recordReport(result.handoff.handoffReport, config);

    if (options.json) {
      console.log(JSON.stringify({ blocked: false, pipeReport: result.pipeReport, handoff: result.handoff, paths }, null, 2));
    } else {
      console.log(result.handoff.brief);
      console.log(`\nPiped: ${fromRole} → ${toRole}  (saved: ${paths.rolePath})`);
    }
    return 0;
  }

  if (command === 'server') {
    const { host, port } = await startPolicyServer({ configPath: options.configPath });
    console.log(`404gent policy server listening on http://${host}:${port}`);
    await new Promise(() => {});
    return 0;
  }

  if (command === 'preprocess-image') {
    const imagePath = options.filePath ?? text;
    if (!imagePath) {
      console.error('preprocess-image requires an image path.');
      return 2;
    }
    const result = await preprocessImage(imagePath, config, { quiet: true });
    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(`Preprocessed image: ${result.imageId}`);
      console.log(`Raw: ${result.rawPath}`);
      console.log(`Normalized: ${result.normalizedPath}`);
      console.log(`JSON: ${result.preprocessedPath}`);
      console.log(`Detections: ${result.detections} (${result.hiddenDetections} hidden)`);
    }
    return 0;
  }

  if (command === 'os-guard') {
    return handleOsGuardCommand({ argv: positionals.slice(1), options, config });
  }

  if (command === 'learn') {
    return handleLearnCommand({ argv: positionals.slice(1), options, config });
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

  if (surface === 'image' && options.preprocessedPath) {
    const raw = await readFile(options.preprocessedPath, 'utf8');
    const preprocessed = JSON.parse(raw);
    const event = normalizePreprocessedImageResult(preprocessed, {
      preprocessedPath: options.preprocessedPath,
      pathBase: config.dataDir ?? '.404gent'
    });
    const result = await guardAndRecord(event, config);
    printResult(result, options.json);
    return result.decision === 'block' ? 1 : 0;
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

    await recordReport(result, config);
    printResult(result, options.json);
    return result.decision === 'block' ? 1 : 0;
  }

  // Generic text scan for all other surfaces (and scan-image without --file)
  const result = await guardAndRecord({ type: surface, text }, config);
  printResult(result, options.json);
  return result.decision === 'block' ? 1 : 0;
}

async function handleOsGuardCommand({ argv, options, config }) {
  const subcommand = argv[0] ?? 'status';

  if (subcommand === 'status') {
    try {
      const status = await fetchDaemonStatus();
      console.log(options.json ? JSON.stringify(status, null, 2) : `OS Guard daemon: watching ${status.watchedPIDs?.length ?? 0} PID(s), watchAll=${Boolean(status.watchAll)}`);
      return 0;
    } catch (error) {
      const result = { ok: false, error: error.message };
      console.log(options.json ? JSON.stringify(result, null, 2) : `OS Guard daemon unavailable: ${error.message}`);
      return 1;
    }
  }

  if (subcommand === 'simulate-open') {
    const path = argv[1];
    if (!path) {
      console.error('simulate-open requires a path.');
      return 2;
    }
    const result = await guardAndRecord(createOpenEvent(path, {
      agent: options.agent,
      pid: options.pid,
      mode: 'simulate'
    }), config);
    printResult(result, options.json);
    return result.decision === 'block' ? 1 : 0;
  }

  if (subcommand === 'simulate-exec') {
    const command = argv.slice(1);
    if (command.length === 0) {
      console.error('simulate-exec requires a command.');
      return 2;
    }
    const result = await guardAndRecord(createExecEvent(command, {
      agent: options.agent,
      pid: options.pid,
      mode: 'simulate'
    }), config);
    printResult(result, options.json);
    return result.decision === 'block' ? 1 : 0;
  }

  if (subcommand === 'simulate-unlink') {
    const path = argv[1];
    if (!path) {
      console.error('simulate-unlink requires a path.');
      return 2;
    }
    const result = await guardAndRecord(createUnlinkEvent(path, {
      agent: options.agent,
      pid: options.pid,
      mode: 'simulate'
    }), config);
    printResult(result, options.json);
    return result.decision === 'block' ? 1 : 0;
  }

  if (subcommand === 'register-existing') {
    const names = (options.names ?? 'codex,claude,gemini,opencode').split(',');
    const matches = await findProcessIdsByNames(names);
    const registered = [];
    for (const match of matches) {
      registered.push(await registerPidWithDaemon({ pid: match.pid, agent: match.name }));
    }
    const result = { registered: registered.length, matches };
    console.log(JSON.stringify(result, null, 2));
    return 0;
  }

  console.error(`Unknown os-guard command: ${subcommand}`);
  return 2;
}

async function handleLearnCommand({ argv, options, config }) {
  const subcommand = argv[0] ?? 'status';
  let result;

  if (subcommand === 'status') {
    result = await learnStatus(config);
  } else if (subcommand === 'analyze') {
    result = await analyzeLearn(config, { manual: true });
  } else if (subcommand === 'pending') {
    result = await pendingLearn(config);
  } else if (subcommand === 'shadow-status') {
    result = await shadowStatus(config);
  } else if (subcommand === 'test') {
    if (!options.rule) {
      console.error('learn test requires --rule <id>.');
      return 2;
    }
    result = await testRule(options.rule, config);
  } else if (subcommand === 'approve') {
    if (!options.rule) {
      console.error('learn approve requires --rule <id>.');
      return 2;
    }
    result = await approveRule(options.rule, config);
  } else if (subcommand === 'reject') {
    if (!options.rule) {
      console.error('learn reject requires --rule <id>.');
      return 2;
    }
    result = await rejectRule(options.rule, config);
  } else {
    console.error(`Unknown learn command: ${subcommand}`);
    return 2;
  }

  console.log(JSON.stringify(result, null, 2));
  return 0;
}

async function handleAgentCommand({ argv, options }) {
  const command = argv;
  if (command.length === 0) {
    console.error('agent requires a command after --.');
    return 2;
  }

  const { spawn } = await import('node:child_process');
  const child = spawn(command[0], command.slice(1), { stdio: 'inherit' });
  if (options.withOsGuard) {
    try {
      await registerPidWithDaemon({ pid: child.pid, agent: options.agent ?? 'agent' });
    } catch (error) {
      console.error(`OS Guard PID registration failed: ${error.message}`);
    }
  }

  return new Promise((resolve) => {
    child.on('exit', (code, signal) => {
      if (signal) {
        resolve(1);
        return;
      }
      resolve(code ?? 0);
    });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exitCode = await main();
}
