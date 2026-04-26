#!/usr/bin/env node
/**
 * 404gent Claude Code Hook
 *
 * Claude Code hooks 시스템과 연동하여 프롬프트, 명령어, 출력을
 * 자동으로 스캔하고 위험 시 차단(exit 2)합니다.
 *
 * Hook events:
 *   UserPromptSubmit → scan-prompt (프롬프트 인젝션 차단)
 *   PreToolUse(Bash) → scan-command (위험 명령어 차단)
 *   PostToolUse(Bash) → scan-output (비밀 유출 기록)
 */

import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = process.env.CLAUDE_PROJECT_DIR || resolve(__dirname, '..');

// Dynamic imports resolved relative to this file
const { loadConfig } = await import('./config.js');
const { scanText } = await import('./policy/engine.js');
const { appendAuditEvent } = await import('./audit.js');
const { updateState } = await import('./state.js');
const { appendVectorDocument } = await import('./vector-store.js');
const { createVisionProvider } = await import('./providers/vision-llm.js');
const { createGoogleVisionProvider } = await import('./providers/google-vision.js');

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
    // Safety: if no data after 5s, resolve with empty
    setTimeout(() => resolve(data), 5000);
  });
}

// Extract base64 image blocks from UserPromptSubmit content (multimodal prompts)
function extractImages(input) {
  const content = input.content ?? input.prompt;
  if (!Array.isArray(content)) return [];

  return content
    .filter((block) => block?.type === 'image')
    .map((block) => {
      const src = block.source ?? block;
      return {
        base64: src.data ?? src.base64 ?? '',
        mediaType: src.media_type ?? src.mediaType ?? 'image/png'
      };
    })
    .filter((img) => img.base64.length > 0);
}

function createVisionProviderForConfig(config) {
  const llmConfig = config.llm ?? {};
  const provider = llmConfig.visionProvider ?? llmConfig.provider ?? 'anthropic';

  if (provider === 'google') {
    const apiKey = process.env[llmConfig.googleApiKeyEnv ?? 'GOOGLE_API_KEY'];
    return createGoogleVisionProvider({
      apiKey,
      model: llmConfig.googleVisionModel ?? 'gemini-2.0-flash'
    });
  }

  const apiKey = process.env[llmConfig.apiKeyEnv ?? 'ANTHROPIC_API_KEY'];
  return createVisionProvider({
    apiKey,
    model: llmConfig.visionModel ?? llmConfig.model ?? 'claude-opus-4-6'
  });
}

function extractText(hookEvent, input) {
  if (hookEvent === 'UserPromptSubmit') {
    // Claude Code sends `prompt` (not `content`) for UserPromptSubmit
    const content = input.content;
    const text = Array.isArray(content)
      ? content.filter((b) => b?.type === 'text').map((b) => b.text).join('\n')
      : (input.prompt ?? input.content ?? '');
    return { surface: 'prompt', text };
  }

  if (hookEvent === 'PreToolUse' && input.tool_name === 'Bash') {
    return { surface: 'command', text: input.tool_input?.command ?? '' };
  }

  if (hookEvent === 'PostToolUse' && input.tool_name === 'Bash') {
    const resp = input.tool_response;
    let text = '';
    if (typeof resp === 'string') {
      text = resp;
    } else if (resp) {
      text = resp.stdout ?? resp.output ?? resp.content ?? '';
    }
    return { surface: 'output', text };
  }

  return null;
}

async function main() {
  let input;
  try {
    const raw = await readStdin();
    if (!raw.trim()) process.exit(0);
    input = JSON.parse(raw);
  } catch {
    // JSON 파싱 실패 → fail-open (차단하지 않음)
    process.exit(0);
  }

  const hookEvent = input.hook_event_name;
  const extracted = extractText(hookEvent, input);

  // 관심 없는 이벤트 → 패스
  if (!extracted) process.exit(0);

  const { surface, text } = extracted;

  // 빈 텍스트이고 이미지도 없으면 스캔 불필요
  const hasImages = hookEvent === 'UserPromptSubmit' && extractImages(input).length > 0;
  if (!text.trim() && !hasImages) process.exit(0);

  let config;
  try {
    config = await loadConfig();
  } catch {
    // config 로딩 실패 → fail-open
    process.exit(0);
  }

  // Override dataDir to project root
  config.dataDir = resolve(PROJECT_ROOT, config.dataDir ?? '.404gent');

  const result = scanText({
    surface,
    text,
    config,
    source: 'claude-code-hook',
    agentId: input.agent_id ?? undefined,
    meta: {
      hookEvent,
      sessionId: input.session_id,
      toolName: input.tool_name,
      cwd: input.cwd
    }
  });

  // Vision scan: check for prompt injections embedded in uploaded images
  const extraFindings = [];
  if (hookEvent === 'UserPromptSubmit') {
    const images = extractImages(input);
    if (images.length > 0) {
      try {
        const visionProvider = createVisionProviderForConfig(config);
        for (const img of images) {
          const visionResult = await visionProvider.analyzeImage(img);
          if (!visionResult.skipped) {
            extraFindings.push(...visionResult.findings);
            // Also run text-rule scan on any hidden prompts extracted from the image
            for (const hiddenPrompt of visionResult.hiddenPrompts) {
              const hiddenScan = scanText({
                surface: 'prompt',
                text: hiddenPrompt,
                config,
                source: 'vision-hidden-prompt'
              });
              extraFindings.push(...hiddenScan.findings);
            }
          }
        }
      } catch {
        // Vision analysis error → fail-open, do not block
      }
    }
  }

  // Merge vision findings into result
  if (extraFindings.length > 0) {
    result.findings.push(...extraFindings);
    const blockSeverities = config.blockSeverities ?? ['critical', 'high'];
    if (result.findings.some((f) => blockSeverities.includes(f.severity))) {
      result.decision = 'block';
    } else if (result.decision === 'allow') {
      result.decision = 'warn';
    }
  }

  // Record to audit log, vector store, state
  try {
    await appendAuditEvent(result, config);
    await appendVectorDocument(result, config);
    await updateState(result, config);
  } catch {
    // 기록 실패해도 판정은 수행
  }

  if (result.decision === 'block') {
    const findings = result.findings
      .map((f) => `  [${f.severity}] ${f.id}: ${f.rationale}`)
      .join('\n');
    process.stderr.write(
      `🚫 404gent BLOCK (${surface})\n${findings}\n`
    );
    process.exit(2);
  }

  if (result.decision === 'warn') {
    const ids = result.findings.map((f) => f.id).join(', ');
    const output = JSON.stringify({
      continue: true,
      hookSpecificOutput: {
        hookEventName: hookEvent,
        additionalContext: `⚠️ 404gent WARNING (${surface}): ${ids}`
      }
    });
    process.stdout.write(output);
  }

  process.exit(0);
}

main().catch(() => process.exit(0));
