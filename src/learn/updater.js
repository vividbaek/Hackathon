import { learnPaths, readJson, writeJson } from './store.js';

function removeRule(rules, id) {
  return (rules ?? []).filter((entry) => (entry.id ?? entry.rule?.id) !== id);
}

export async function approveRule(id, config = {}) {
  const paths = learnPaths(config);
  const pending = await readJson(paths.pendingRules, { rules: [] });
  const shadow = await readJson(paths.shadowRules, { rules: [] });
  const approved = await readJson(paths.approvedRules, { rules: [] });
  const entry = (pending.rules ?? []).find((rule) => rule.id === id)
    ?? (shadow.rules ?? []).find((rule) => rule.id === id);
  if (!entry) {
    throw new Error(`Unknown pending rule: ${id}`);
  }

  const approvedRule = { ...entry.rule };
  const nextApprovedRules = [
    ...(approved.rules ?? []).filter((rule) => rule.id !== approvedRule.id),
    approvedRule
  ];
  await writeJson(paths.approvedRules, {
    updatedAt: new Date().toISOString(),
    rules: nextApprovedRules
  });
  await writeJson(paths.pendingRules, {
    ...pending,
    rules: removeRule(pending.rules, id)
  });
  await writeJson(paths.shadowRules, {
    ...shadow,
    rules: removeRule(shadow.rules, id)
  });
  return { id, approved: true, rule: approvedRule };
}

export async function rejectRule(id, config = {}, { reason = 'Rejected by user.' } = {}) {
  const paths = learnPaths(config);
  const pending = await readJson(paths.pendingRules, { rules: [] });
  const shadow = await readJson(paths.shadowRules, { rules: [] });
  const rejected = await readJson(paths.rejectedRules, { rules: [] });
  const entry = (pending.rules ?? []).find((rule) => rule.id === id)
    ?? (shadow.rules ?? []).find((rule) => rule.id === id);
  if (!entry) {
    throw new Error(`Unknown pending rule: ${id}`);
  }

  const rejectedEntry = {
    ...entry,
    status: 'rejected',
    rejectedAt: new Date().toISOString(),
    reason
  };
  await writeJson(paths.rejectedRules, {
    updatedAt: new Date().toISOString(),
    rules: [
      ...(rejected.rules ?? []).filter((rule) => rule.id !== id),
      rejectedEntry
    ]
  });
  await writeJson(paths.pendingRules, {
    ...pending,
    rules: removeRule(pending.rules, id)
  });
  await writeJson(paths.shadowRules, {
    ...shadow,
    rules: removeRule(shadow.rules, id)
  });
  return { id, rejected: true };
}
