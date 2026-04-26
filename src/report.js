export function summarizeResult(result) {
  return {
    surface: result.surface,
    decision: result.decision,
    severity: result.severity,
    findingCount: result.findings.length
  };
}
