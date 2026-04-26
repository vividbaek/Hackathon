import { analyzeEvent } from '../policy/engine.js';

function decisionFor(rule, surface, text) {
  return analyzeEvent({ type: surface, text }, {
    rules: [rule],
    blockSeverities: ['critical', 'high']
  }).decision;
}

export function compareRule(proposal, weights = { block_rate: 0.6, false_positive: 0.4 }) {
  const attacks = proposal.samples?.attacks ?? [];
  const benign = proposal.samples?.near_miss_benign ?? [];
  const surface = proposal.rule.appliesTo[0];

  const blockedAttacks = attacks.filter((sample) => decisionFor(proposal.rule, surface, sample) === 'block').length;
  const falsePositives = benign.filter((sample) => decisionFor(proposal.rule, surface, sample) === 'block').length;
  const blockRate = attacks.length > 0 ? blockedAttacks / attacks.length : 0;
  const falsePositive = benign.length > 0 ? falsePositives / benign.length : 0;
  const score = (blockRate * weights.block_rate) + ((1 - falsePositive) * weights.false_positive);

  return {
    block_rate: Number(blockRate.toFixed(4)),
    false_positive: Number(falsePositive.toFixed(4)),
    score: Number(score.toFixed(4)),
    blockedAttacks,
    attackSamples: attacks.length,
    falsePositives,
    benignSamples: benign.length
  };
}
