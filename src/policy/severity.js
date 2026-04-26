export const severityRank = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

export const DEFAULT_BLOCK_SEVERITIES = ['critical', 'high'];

export function compareSeverityDesc(a, b) {
  return (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0);
}

export function highestSeverity(findings) {
  return findings.reduce((highest, finding) => {
    return (severityRank[finding.severity] ?? 0) > (severityRank[highest] ?? 0) ? finding.severity : highest;
  }, 'low');
}

export function isValidSeverity(severity) {
  return Object.hasOwn(severityRank, severity);
}
