import { createHash } from 'node:crypto';
import { isValidSeverity } from '../policy/severity.js';

const OPENAI_RESPONSES_URL = 'https://api.openai.com/v1/responses';
const DEFAULT_MODEL = 'gpt-5-mini';
const VALID_SURFACES = new Set(['prompt', 'command', 'output', 'image', 'vision_observation', 'llm', 'os']);
const SURFACE_ALIASES = {
  shell: 'command',
  es: 'os',
  screen: 'image'
};

function hash(value) {
  return createHash('sha1').update(value).digest('hex').slice(0, 10);
}

function normalizeRegexPattern(pattern) {
  const raw = String(pattern ?? '').trim();
  const slashMatch = raw.match(/^\/(.+)\/([dgimsuvy]*)$/);
  return slashMatch ? slashMatch[1] : raw;
}

function normalizeCategory(category) {
  return String(category ?? '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

function normalizeSurface(surface) {
  const normalized = String(surface ?? '').trim();
  return SURFACE_ALIASES[normalized] ?? normalized;
}

function asStringArray(value, limit = 10) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((entry) => String(entry ?? '').trim())
    .filter(Boolean)
    .slice(0, limit);
}

function extractResponseText(response) {
  if (typeof response.output_text === 'string') {
    return response.output_text;
  }
  const chunks = [];
  for (const item of response.output ?? []) {
    for (const content of item.content ?? []) {
      if ((content.type === 'output_text' || content.type === 'text') && content.text) {
        chunks.push(content.text);
      }
    }
  }
  return chunks.join('\n').trim();
}

function parseJsonResponse(text) {
  const trimmed = String(text ?? '').trim();
  if (!trimmed) {
    throw new Error('OpenAI response did not contain text.');
  }
  try {
    return JSON.parse(trimmed);
  } catch {
    const match = trimmed.match(/\{[\s\S]*\}/);
    if (!match) {
      throw new Error('OpenAI response did not contain JSON.');
    }
    return JSON.parse(match[0]);
  }
}

function similarRejected(rule, rejectedRules = []) {
  return rejectedRules.some((rejected) => {
    const pattern = rejected.rule?.pattern ?? rejected.pattern;
    return pattern && pattern === rule.pattern;
  });
}

export function sanitizeCandidate(candidate) {
  const pattern = normalizeRegexPattern(candidate?.pattern);
  if (!pattern) {
    return null;
  }
  try {
    new RegExp(pattern, 'ims');
  } catch {
    return null;
  }

  const surface = normalizeSurface(candidate?.surface);
  if (!VALID_SURFACES.has(surface)) {
    return null;
  }

  const severity = String(candidate?.severity ?? '').trim().toLowerCase();
  if (!isValidSeverity(severity)) {
    return null;
  }

  const category = normalizeCategory(candidate?.category);
  if (!category) {
    return null;
  }

  const nearMiss = asStringArray(candidate?.near_miss_benign);
  if (nearMiss.length === 0) {
    return null;
  }

  return {
    pattern,
    surface,
    severity,
    category,
    rationale: String(candidate?.rationale ?? 'OpenAI proposed this rule from recent attack logs.').trim(),
    remediation: String(candidate?.remediation ?? 'Review the event and remove unsafe content.').trim(),
    attack_variants: asStringArray(candidate?.attack_variants),
    near_miss_benign: nearMiss
  };
}

export function sanitizeCandidates(candidates = []) {
  return candidates.map(sanitizeCandidate).filter(Boolean);
}

function strongestEvidence(attacks, surface) {
  return attacks.find((attack) => attack.surface === surface) ?? attacks[0] ?? {};
}

export function candidatesToProposals(candidates = [], attackLogs = [], { rejectedRules = [] } = {}) {
  const proposals = [];
  for (const candidate of candidates) {
    const evidence = strongestEvidence(attackLogs, candidate.surface);
    const rule = {
      id: `learned-openai-${hash(`${candidate.surface}:${candidate.pattern}`)}`,
      appliesTo: [candidate.surface],
      severity: candidate.severity,
      category: candidate.category,
      pattern: candidate.pattern,
      rationale: candidate.rationale,
      remediation: candidate.remediation
    };

    if (similarRejected(rule, rejectedRules)) {
      continue;
    }

    proposals.push({
      id: rule.id,
      status: 'pending',
      createdAt: new Date().toISOString(),
      source: 'openai',
      sourceRule: evidence.matched_rule ?? 'openai-inference',
      layer: evidence.layer ?? candidate.surface,
      evidenceCount: attackLogs.length,
      rule,
      samples: {
        attacks: [evidence.input, ...candidate.attack_variants].filter(Boolean).slice(0, 10),
        near_miss_benign: candidate.near_miss_benign
      },
      evidence: attackLogs.slice(0, 5)
    });
  }
  return proposals;
}

function buildPrompt(attacks) {
  return `Analyze recent guardrail attack logs and propose precise runtime rule candidates.

Return only JSON matching the schema. Use runtime surfaces only:
prompt, command, output, image, vision_observation, llm, os.

Rules:
- Prefer narrow regex patterns that match the malicious behavior.
- Do not propose broad rules that would block normal webhook/API/healthcheck traffic.
- Include near_miss_benign samples that are similar but safe.
- Use severity low, medium, high, or critical.
- Use lowercase underscore categories.

Attack logs:
${JSON.stringify(attacks.slice(0, 20), null, 2)}`;
}

function responseSchema() {
  const candidate = {
    type: 'object',
    additionalProperties: false,
    required: [
      'pattern',
      'surface',
      'severity',
      'category',
      'rationale',
      'remediation',
      'attack_variants',
      'near_miss_benign'
    ],
    properties: {
      pattern: { type: 'string' },
      surface: { type: 'string', enum: [...VALID_SURFACES] },
      severity: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
      category: { type: 'string' },
      rationale: { type: 'string' },
      remediation: { type: 'string' },
      attack_variants: { type: 'array', items: { type: 'string' } },
      near_miss_benign: { type: 'array', items: { type: 'string' } }
    }
  };

  return {
    type: 'object',
    additionalProperties: false,
    required: ['candidates'],
    properties: {
      candidates: {
        type: 'array',
        maxItems: 5,
        items: candidate
      }
    }
  };
}

export async function proposeRulesWithInference(attackLogs = [], config = {}, {
  rejectedRules = [],
  fetchImpl = globalThis.fetch
} = {}) {
  const inferenceConfig = config.learn?.inference ?? {};
  if (inferenceConfig.enabled === false) {
    return { ok: false, skipped: true, reason: 'disabled', proposals: [] };
  }

  const apiKeyEnv = inferenceConfig.apiKeyEnv ?? 'OPENAI_API_KEY';
  const apiKey = process.env[apiKeyEnv];
  if (!apiKey) {
    return { ok: false, skipped: true, reason: 'missing_api_key', proposals: [] };
  }
  if (typeof fetchImpl !== 'function') {
    return { ok: false, skipped: true, reason: 'missing_fetch', proposals: [] };
  }

  const model = inferenceConfig.model || process.env.OPENAI_MODEL || DEFAULT_MODEL;
  const response = await fetchImpl(OPENAI_RESPONSES_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'content-type': 'application/json'
    },
    body: JSON.stringify({
      model,
      input: buildPrompt(attackLogs),
      text: {
        verbosity: 'low',
        format: {
          type: 'json_schema',
          name: 'self_healing_rule_candidates',
          strict: true,
          schema: responseSchema()
        }
      }
    })
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`OpenAI inference failed: ${response.status} ${body.slice(0, 200)}`);
  }

  const parsed = parseJsonResponse(extractResponseText(await response.json()));
  const candidates = sanitizeCandidates(parsed.candidates ?? []);
  return {
    ok: true,
    skipped: false,
    model,
    candidateCount: Array.isArray(parsed.candidates) ? parsed.candidates.length : 0,
    validCandidates: candidates.length,
    proposals: candidatesToProposals(candidates, attackLogs, { rejectedRules })
  };
}
