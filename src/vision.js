import { createHash } from 'node:crypto';

function hashValue(value) {
  return createHash('sha256').update(String(value ?? '')).digest('hex');
}

function joinText(parts) {
  return parts
    .filter((part) => typeof part === 'string' && part.trim().length > 0)
    .join('\n');
}

export function normalizeVisionObservation(observation = {}) {
  const extractedText = joinText([
    observation.extractedText,
    observation.ocrText,
    observation.caption,
    ...(Array.isArray(observation.textBlocks) ? observation.textBlocks : [])
  ]);
  const imageRef = observation.imagePath ?? observation.imageUrl ?? observation.imageId ?? '';
  const imageHash = observation.imageHash ?? hashValue(`${imageRef}:${extractedText}`);

  return {
    type: observation.type ?? 'image',
    text: extractedText,
    source: observation.source ?? 'vision-agent',
    companyId: observation.companyId,
    agentId: observation.agentId,
    evidence: {
      imageId: observation.imageId,
      imageHash,
      imagePath: observation.imagePath,
      imageUrl: observation.imageUrl,
      extractedText,
      regions: observation.regions ?? [],
      visualSignals: observation.visualSignals ?? [],
      confidence: observation.confidence,
      hiddenPrompts: observation.hiddenPrompts ?? [],
      objects: observation.objects ?? []
    },
    artifacts: [
      {
        type: 'image',
        id: observation.imageId,
        path: observation.imagePath,
        url: observation.imageUrl,
        hash: imageHash
      }
    ],
    meta: {
      ...observation.meta,
      frameId: observation.frameId,
      captureTime: observation.captureTime,
      visionProvider: observation.visionProvider
    }
  };
}
