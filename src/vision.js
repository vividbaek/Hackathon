import { createHash } from 'node:crypto';
import { isAbsolute, normalize } from 'node:path';

export const PREPROCESSED_IMAGE_SCHEMA_VERSION = 'image_preprocess_v1';

function hashValue(value) {
  return createHash('sha256').update(String(value ?? '')).digest('hex');
}

function joinText(parts) {
  return parts
    .filter((part) => typeof part === 'string' && part.trim().length > 0)
    .join('\n');
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizeDetectionRegion(detection = {}) {
  const bbox = detection.bbox ?? {};
  return {
    id: detection.id,
    x: bbox.x,
    y: bbox.y,
    width: bbox.width,
    height: bbox.height,
    text: detection.text ?? detection.extractedValue,
    label: detection.kind,
    threat: detection.kind !== 'ocr_text',
    confidence: detection.confidence,
    severityHint: detection.severityHint
  };
}

function detectionText(detection = {}) {
  return joinText([
    detection.kind ? `image_detection_kind=${detection.kind}` : '',
    detection.severityHint ? `severity=${detection.severityHint}` : '',
    detection.text,
    detection.extractedValue
  ]);
}

function validateDataRelativePath(path, field) {
  if (path === undefined || path === null || path === '') {
    return path;
  }
  if (typeof path !== 'string') {
    throw new Error(`${field} must be a .404gent-relative path.`);
  }
  const normalized = normalize(path).replaceAll('\\', '/');
  if (isAbsolute(path) || normalized === '..' || normalized.startsWith('../')) {
    throw new Error(`${field} must be relative to .404gent and cannot escape the data directory.`);
  }
  return path;
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

export function normalizePreprocessedImageResult(input = {}, options = {}) {
  if (input.schemaVersion !== PREPROCESSED_IMAGE_SCHEMA_VERSION) {
    throw new Error(`Unsupported preprocessed image schema: ${input.schemaVersion ?? 'missing'}`);
  }

  const detections = asArray(input.detections);
  const extractedText = joinText(detections.map(detectionText));
  const sourceImagePath = validateDataRelativePath(input.sourceImagePath, 'sourceImagePath');
  const normalizedImagePath = validateDataRelativePath(input.normalizedImagePath, 'normalizedImagePath');
  const imageRef = sourceImagePath ?? normalizedImagePath ?? input.imageId ?? options.preprocessedPath ?? '';
  const imageHash = input.imageHash ?? hashValue(`${imageRef}:${extractedText}`);
  const hiddenPrompts = detections
    .filter((detection) => ['hidden_text', 'pdf_hidden_text', 'visual_prompt_injection'].includes(detection.kind))
    .map((detection) => detection.extractedValue ?? detection.text)
    .filter(Boolean);

  return {
    type: 'image',
    text: extractedText,
    source: input.source ?? 'image-preprocessor',
    companyId: input.companyId,
    agentId: input.agentId,
    evidence: {
      imageId: input.imageId,
      imageHash,
      imagePath: sourceImagePath,
      normalizedImagePath,
      preprocessedPath: options.preprocessedPath,
      extractedText,
      detections,
      regions: detections.map(normalizeDetectionRegion),
      visualSignals: detections
        .filter((detection) => detection.kind && detection.kind !== 'ocr_text')
        .map((detection) => ({
          id: detection.id,
          kind: detection.kind,
          severityHint: detection.severityHint,
          confidence: detection.confidence
        })),
      confidence: input.confidence,
      hiddenPrompts,
      objects: detections
        .filter((detection) => ['qr_code', 'suspicious_object'].includes(detection.kind))
        .map((detection) => ({
          id: detection.id,
          label: detection.kind,
          suspicious: detection.kind !== 'ocr_text',
          ...detection.bbox,
          confidence: detection.confidence
        }))
    },
    artifacts: [
      {
        type: 'image',
        id: input.imageId,
        path: sourceImagePath,
        hash: imageHash
      },
      {
        type: 'normalized_image',
        id: input.imageId,
        path: normalizedImagePath,
        hash: imageHash
      }
    ].filter((artifact) => artifact.path),
    meta: {
      ...input.meta,
      schemaVersion: input.schemaVersion,
      preprocessedPath: options.preprocessedPath,
      pathBase: options.pathBase ?? '.404gent'
    }
  };
}
