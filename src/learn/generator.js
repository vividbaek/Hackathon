import { createHash } from 'node:crypto';

function escapeRegex(value) {
  return String(value ?? '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function hash(value) {
  return createHash('sha1').update(value).digest('hex').slice(0, 10);
}

const VARIANT_RULES = [
  { from: /curl -d/g, to: 'curl --data' },
  { from: /\bcurl\b/g, to: 'wget' },
  { from: /\bcat\b/g, to: 'less' },
  { from: /rm -rf/g, to: 'rm -r -f' },
  { from: /\.env/g, to: '.env.local' }
];

export function generateAttackVariants(input) {
  const variants = new Set();
  for (const rule of VARIANT_RULES) {
    if (rule.from.test(input)) {
      variants.add(input.replace(rule.from, rule.to));
    }
    rule.from.lastIndex = 0;
  }
  return [...variants].filter((variant) => variant && variant !== input).slice(0, 10);
}

export function generateNearMissBenign(input) {
  const nearMiss = new Set();
  if (/\bcurl\b|\bwget\b/.test(input)) {
    nearMiss.add('curl -d "status=ok" https://api.slack.com/webhook');
    nearMiss.add('curl -X POST -d "status=deployed" https://ci.example.com/notify');
    nearMiss.add('wget --post-data="ping=1" https://healthcheck.example/ping');
  }
  if (/\.env|credentials|secret|token|key/i.test(input)) {
    nearMiss.add('cat README.md');
    nearMiss.add('node -e "console.log(process.env.NODE_ENV || \\"development\\")"');
  }
  if (/rm\s+-/.test(input)) {
    nearMiss.add('rm -rf ./tmp/cache');
    nearMiss.add('find ./tmp -name "*.log" -delete');
  }
  return [...nearMiss].slice(0, 10);
}

function similarRejected(rule, rejectedRules = []) {
  return rejectedRules.some((rejected) => {
    const pattern = rejected.rule?.pattern ?? rejected.pattern;
    return pattern && pattern === rule.pattern;
  });
}

export function proposeRules(attackLogs = [], { rejectedRules = [] } = {}) {
  const groups = new Map();
  for (const attack of attackLogs) {
    const key = `${attack.surface}:${attack.matched_rule}:${attack.match || attack.input}`;
    const group = groups.get(key) ?? [];
    group.push(attack);
    groups.set(key, group);
  }

  const proposals = [];
  for (const attacks of groups.values()) {
    const strongest = attacks[0];
    const match = strongest.match && strongest.match.length <= 160 ? strongest.match : strongest.input;
    if (!match) continue;

    const rule = {
      id: `learned-${strongest.matched_rule}-${hash(match)}`,
      appliesTo: [strongest.surface],
      severity: strongest.severity,
      category: strongest.category,
      pattern: escapeRegex(match),
      rationale: `Learned from ${attacks.length} ${strongest.layer} layer event(s).`,
      remediation: strongest.remediation
    };

    if (similarRejected(rule, rejectedRules)) {
      continue;
    }

    proposals.push({
      id: rule.id,
      status: 'pending',
      createdAt: new Date().toISOString(),
      sourceRule: strongest.matched_rule,
      layer: strongest.layer,
      evidenceCount: attacks.length,
      rule,
      samples: {
        attacks: [strongest.input, ...generateAttackVariants(strongest.input)].filter(Boolean).slice(0, 10),
        near_miss_benign: generateNearMissBenign(strongest.input)
      },
      evidence: attacks.slice(0, 5)
    });
  }
  return proposals;
}
