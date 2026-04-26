import { appendAuditEvent } from './audit.js';
import { mergeReports, scanText } from './policy/engine.js';
import { highestSeverity } from './policy/severity.js';
import { appendVectorDocument } from './vector-store.js';
import { updateState } from './state.js';
import { createLlmProvider, shouldReviewWithLlm } from './providers/llm.js';

export async function guard(event, config = {}) {
  let result = scanText({
    ...event,
    surface: event.type,
    text: event.text,
    config
  });

  if (shouldReviewWithLlm(result, config)) {
    const llmReport = await createLlmProvider(config).evaluate(result);
    const merged = mergeReports(result, llmReport, config);
    result = {
      ...merged,
      surface: event.type,
      text: String(event.text ?? ''),
      severity: merged.findings.length > 0 ? highestSeverity(merged.findings) : 'low',
      scannedAt: result.scannedAt
    };
  }

  return result;
}

export async function recordReport(report, config = {}) {
  await appendAuditEvent(report, config);
  await appendVectorDocument(report, config);
  await updateState(report, config);
  return report;
}

export async function guardAndRecord(event, config = {}) {
  return recordReport(await guard(event, config), config);
}
