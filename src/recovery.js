export function suggestRecovery(result) {
  if (result.decision === 'block') {
    return ['Review the blocked action before retrying.', 'Remove secrets or destructive flags.'];
  }
  return [];
}
