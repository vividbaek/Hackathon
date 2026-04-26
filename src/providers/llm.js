export function createMockLlmProvider(response = { decision: 'allow', reason: 'mock' }) {
  return {
    async evaluate() {
      return response;
    }
  };
}
