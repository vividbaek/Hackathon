import { createHash } from 'node:crypto';
import { copyFile, mkdir, writeFile } from 'node:fs/promises';
import { basename, extname, join } from 'node:path';
import { PREPROCESSED_IMAGE_SCHEMA_VERSION } from './vision.js';

function timestampForPath(date = new Date()) {
  return date.toISOString().replace(/[-:]/g, '').replace(/\..+$/, '').replace('T', '_');
}

function shortHash(value) {
  return createHash('sha256').update(String(value)).digest('hex').slice(0, 8);
}

function imageHash(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

function imageId(inputPath, date = new Date()) {
  return `${timestampForPath(date)}_${shortHash(`${inputPath}:${date.toISOString()}`)}`;
}

function normalizeBox(word, resolution) {
  const bbox = word.bbox ?? {};
  const width = resolution.width || 1;
  const height = resolution.height || 1;
  return {
    x: Number((bbox.x / width).toFixed(6)),
    y: Number((bbox.y / height).toFixed(6)),
    width: Number((bbox.w / width).toFixed(6)),
    height: Number((bbox.h / height).toFixed(6))
  };
}

function wordDetection(word, index, resolution, kind, severityHint) {
  return {
    id: `${kind}-${index + 1}`,
    kind,
    severityHint,
    text: word.text,
    extractedValue: word.text,
    bbox: normalizeBox(word, resolution),
    confidence: Number(((word.conf ?? 0) / 100).toFixed(4)),
    meta: {
      engine: word.engine
    }
  };
}

function attackDetection(attack, index, resolution) {
  const width = resolution.width || 1;
  const height = resolution.height || 1;
  return {
    id: `hidden_text-attack-${index + 1}`,
    kind: 'hidden_text',
    severityHint: 'critical',
    text: attack.text,
    extractedValue: attack.text,
    bbox: {
      x: Number(((attack.x ?? 0) / width).toFixed(6)),
      y: Number(((attack.y ?? 0) / height).toFixed(6)),
      width: Number(((attack.w ?? 0) / width).toFixed(6)),
      height: Number(((attack.h ?? 0) / height).toFixed(6))
    },
    confidence: Number(((attack.score ?? 0) / 100).toFixed(4)),
    meta: {
      engine: 'attack-detection',
      type: attack.type,
      category: attack.category,
      sources: attack.sources
    }
  };
}

function detectionsFromScan(scan) {
  const hidden = (scan.hiddenWords ?? []).map((word, index) =>
    wordDetection(word, index, scan.resolution, 'hidden_text', 'critical')
  );
  const attacks = (scan.hiddenAttacks ?? []).map((attack, index) =>
    attackDetection(attack, index, scan.resolution)
  );
  const visible = (scan.normalWords ?? [])
    .filter((word) => Number(word.conf ?? 0) >= 60)
    .map((word, index) => wordDetection(word, index, scan.resolution, 'ocr_text', 'low'));
  return [...hidden, ...attacks, ...visible];
}

export function createPreprocessedImageDocument({
  id,
  inputPath,
  rawRelative,
  normalizedRelative,
  normalizedBuffer,
  scan,
  date = new Date(),
  targetWidth = 2000
}) {
  return {
    schemaVersion: PREPROCESSED_IMAGE_SCHEMA_VERSION,
    imageId: id,
    sourceImagePath: rawRelative,
    normalizedImagePath: normalizedRelative,
    imageHash: imageHash(normalizedBuffer),
    detections: detectionsFromScan(scan),
    meta: {
      preprocessor: '404gent-local-ocr',
      sourceFileName: basename(inputPath),
      processedAt: date.toISOString(),
      targetWidth,
      resolution: scan.resolution
    }
  };
}

export async function preprocessImage(inputPath, config = {}, options = {}) {
  const dataDir = config.dataDir ?? '.404gent';
  const date = options.date ?? new Date();
  const id = options.imageId ?? imageId(inputPath, date);
  const ext = extname(inputPath).toLowerCase() || '.png';
  const rawRelative = `images/raw/${id}${ext}`;
  const normalizedRelative = `images/normalized/${id}.normalized.png`;
  const preprocessedRelative = `preprocessed/${id}.json`;

  const rawPath = join(dataDir, rawRelative);
  const normalizedPath = join(dataDir, normalizedRelative);
  const preprocessedPath = join(dataDir, preprocessedRelative);

  await mkdir(join(dataDir, 'images', 'raw'), { recursive: true });
  await mkdir(join(dataDir, 'images', 'normalized'), { recursive: true });
  await mkdir(join(dataDir, 'preprocessed'), { recursive: true });
  await copyFile(inputPath, rawPath);

  const [{ default: sharp }, { scanStandardized }, processor] = await Promise.all([
    import('sharp'),
    import('./ocr.js'),
    import('./utils/image-processor.js')
  ]);
  const scan = await scanStandardized(inputPath, options.targetWidth ?? 2000, { quiet: options.quiet ?? true });
  const normalizedBuffer = scan.hiddenWords?.length > 0
    ? await processor.drawBoundingBoxes(inputPath, scan.hiddenWords, options.targetWidth ?? 2000)
    : await sharp(scan.normalizedBuffer).png().toBuffer();
  await writeFile(normalizedPath, normalizedBuffer);

  const preprocessed = createPreprocessedImageDocument({
    id,
    inputPath,
    rawRelative,
    normalizedRelative,
    normalizedBuffer,
    scan,
    date,
    targetWidth: options.targetWidth ?? 2000
  });

  await writeFile(preprocessedPath, `${JSON.stringify(preprocessed, null, 2)}\n`);

  return {
    ok: true,
    imageId: id,
    rawPath,
    normalizedPath,
    preprocessedPath,
    rawRelative,
    normalizedRelative,
    preprocessedRelative,
    detections: preprocessed.detections.length,
    hiddenDetections: preprocessed.detections.filter((detection) => detection.kind === 'hidden_text').length,
    preprocessed
  };
}
