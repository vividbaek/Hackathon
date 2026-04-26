import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { defaultRules } from './default-rules.js';
import { isValidSeverity } from './severity.js';

const OVERRIDABLE_FIELDS = ['severity', 'category', 'rationale', 'remediation', 'pattern', 'appliesTo'];

export function compileRule(rule) {
  return {
    ...rule,
    regex: new RegExp(rule.pattern, 'ims')
  };
}

function asArray(value) {
  if (!value) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

function normalizeRulePack(raw, path) {
  const parsed = JSON.parse(raw);
  if (Array.isArray(parsed)) {
    return parsed;
  }
  if (Array.isArray(parsed.rules)) {
    return parsed.rules;
  }
  throw new Error(`Rule pack must be an array or { "rules": [] }: ${path}`);
}

function loadRulePack(path) {
  const absolutePath = resolve(path);
  return normalizeRulePack(readFileSync(absolutePath, 'utf8'), absolutePath);
}

function loadRulePackIfExists(path) {
  const absolutePath = resolve(path);
  if (!existsSync(absolutePath)) {
    return [];
  }
  return normalizeRulePack(readFileSync(absolutePath, 'utf8'), absolutePath);
}

function applyOverrides(rules, overrides = []) {
  const byId = new Map(rules.map((rule) => [rule.id, { ...rule }]));
  for (const override of asArray(overrides)) {
    if (!override?.id || !byId.has(override.id)) {
      continue;
    }

    const next = { ...byId.get(override.id) };
    for (const field of OVERRIDABLE_FIELDS) {
      if (Object.hasOwn(override, field)) {
        next[field] = override[field];
      }
    }
    byId.set(override.id, next);
  }
  return [...byId.values()];
}

export function getRules(config = {}) {
  const ruleConfig = config.rules;
  const approvedPath = config.learn?.approvedRulesPath ?? join(config.dataDir ?? '.404gent', 'approved-rules.json');
  const approvedRules = config.learn?.loadApprovedRules === false ? [] : loadRulePackIfExists(approvedPath);

  if (Array.isArray(ruleConfig)) {
    return applyOverrides([...ruleConfig, ...approvedRules], config.overrides);
  }

  const paths = asArray(ruleConfig?.paths);
  const pathRules = paths.flatMap(loadRulePack);
  const customRules = asArray(ruleConfig?.custom);
  const overrides = asArray(ruleConfig?.overrides);

  return applyOverrides([...defaultRules, ...pathRules, ...approvedRules, ...customRules], overrides);
}

export function validateRules(rules) {
  const errors = [];
  const ids = new Set();

  for (const rule of rules) {
    if (!rule || typeof rule !== 'object') {
      errors.push('Rule must be an object.');
      continue;
    }
    if (!rule.id) {
      errors.push('Rule is missing id.');
    } else if (ids.has(rule.id)) {
      errors.push(`Duplicate rule id: ${rule.id}`);
    } else {
      ids.add(rule.id);
    }
    if (!rule.pattern) {
      errors.push(`Rule ${rule.id ?? '<unknown>'} is missing pattern.`);
    } else {
      try {
        compileRule(rule);
      } catch (error) {
        errors.push(`Rule ${rule.id ?? '<unknown>'} has invalid pattern: ${error.message}`);
      }
    }
    if (!isValidSeverity(rule.severity)) {
      errors.push(`Rule ${rule.id ?? '<unknown>'} has invalid severity: ${rule.severity}`);
    }
    if (!rule.category) {
      errors.push(`Rule ${rule.id ?? '<unknown>'} is missing category.`);
    }
    if (!rule.rationale) {
      errors.push(`Rule ${rule.id ?? '<unknown>'} is missing rationale.`);
    }
    if (!rule.remediation) {
      errors.push(`Rule ${rule.id ?? '<unknown>'} is missing remediation.`);
    }
    if (asArray(rule.appliesTo).length === 0) {
      errors.push(`Rule ${rule.id ?? '<unknown>'} is missing appliesTo.`);
    }
  }

  return {
    ok: errors.length === 0,
    errors
  };
}

export function summarizeRules(rules) {
  const summary = {
    total: rules.length,
    bySeverity: {},
    byCategory: {},
    byType: {}
  };

  for (const rule of rules) {
    summary.bySeverity[rule.severity] = (summary.bySeverity[rule.severity] ?? 0) + 1;
    summary.byCategory[rule.category] = (summary.byCategory[rule.category] ?? 0) + 1;
    for (const type of asArray(rule.appliesTo)) {
      summary.byType[type] = (summary.byType[type] ?? 0) + 1;
    }
  }

  return summary;
}
