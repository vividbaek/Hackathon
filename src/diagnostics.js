export function createDiagnostic(result) {
  return {
    decision: result.decision,
    severity: result.severity,
    findings: result.findings
  };
}
