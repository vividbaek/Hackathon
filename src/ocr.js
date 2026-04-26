import Tesseract from 'tesseract.js';
import { spawn } from 'node:child_process';
import * as processor from './utils/image-processor.js';
import sharp from 'sharp';
import { writeFile, unlink, mkdir, readFile } from 'node:fs/promises';
import path, { join } from 'node:path';
import { tmpdir } from 'node:os';
import { detectAndDecodeQR } from './utils/qr-processor.js';

import pkgCanvas from 'canvas';
const { createCanvas, DOMMatrix } = pkgCanvas;

// Polyfills for Node.js
if (typeof global.DOMMatrix === 'undefined') {
  global.DOMMatrix = DOMMatrix;
}

import * as pdfjs from 'pdfjs-dist/legacy/build/pdf.mjs';

/**
 * Tesseract Engine Implementation
 */
async function recognizeWithTesseract(buffer, cropInfo) {
  let worker = null;
  try {
    worker = await Tesseract.createWorker('eng');
    
    await worker.setParameters({
      tessedit_pageseg_mode: '3',
      user_defined_dpi: '300',
    });

    const result = await worker.recognize(buffer, {}, { blocks: true });
    const data = result.data;

    let words = data.words;
    if (!words && data.blocks) {
      words = data.blocks.flatMap(block => 
        (block.paragraphs || []).flatMap(para => 
          (para.lines || []).flatMap(line => line.words || [])
        )
      );
    }

    if (!words || words.length === 0) return [];

    return words.map(word => ({
      engine: 'tesseract',
      text: word.text,
      conf: word.confidence,
      bbox: {
        x: Math.round((word.bbox.x0 / cropInfo.factor) + cropInfo.left),
        y: Math.round((word.bbox.y0 / cropInfo.factor) + cropInfo.top),
        w: Math.round((word.bbox.x1 - word.bbox.x0) / cropInfo.factor),
        h: Math.round((word.bbox.y1 - word.bbox.y0) / cropInfo.factor)
      }
    }));
  } catch (err) {
    console.error('Tesseract Error:', err);
    return [];
  } finally {
    if (worker) await worker.terminate();
  }
}

/**
 * EasyOCR Engine Implementation (Kept as optional/internal)
 */
async function recognizeWithEasyOcr(buffer, cropInfo) {
  const pythonPath = process.env.CONDA_PREFIX ? `${process.env.CONDA_PREFIX}/bin/python` : 'python3';
  const tmpPath = join(tmpdir(), `ocr_tmp_${Date.now()}_${Math.floor(Math.random() * 1000)}.png`);
  
  try {
    const meta = await sharp(buffer).metadata();
    if (meta.width < 10 || meta.height < 10) return [];
    await writeFile(tmpPath, buffer);

    return new Promise((resolve) => {
      const python = spawn(pythonPath, ['src/ocr_engine.py', tmpPath]);
      let output = '';
      python.stdout.on('data', (data) => { output += data.toString(); });
      python.on('close', async () => {
        try { await unlink(tmpPath); } catch (e) {}
        try {
          const rawResults = JSON.parse(output);
          resolve(rawResults.map(res => ({
            engine: 'easyocr',
            text: res.text,
            conf: res.conf,
            bbox: {
              x: Math.round((res.bbox.x / cropInfo.factor) + cropInfo.left),
              y: Math.round((res.bbox.y / cropInfo.factor) + cropInfo.top),
              w: Math.round(res.bbox.w / cropInfo.factor),
              h: Math.round(res.bbox.h / cropInfo.factor)
            }
          })));
        } catch (e) { resolve([]); }
      });
    });
  } catch (err) { return []; }
}

/**
 * Main Standardized Pipeline
 */
export async function scanStandardized(inputSource, targetWidth = 2000, options = { invert: true }) {
  // 1. Create a normalized master buffer
  const normalizedBuffer = await sharp(inputSource, { density: 300 })
    .resize({ width: targetWidth })
    .flatten({ background: { r: 255, g: 255, b: 255 } })
    .png()
    .toBuffer();

  const metadata = await sharp(normalizedBuffer).metadata();
  const rows = 2;
  const cols = 2;
  const factor = 4; // Increased from 2 to 4 for extreme tiny text detection
  const gridCrops = await processor.gridScaleUp(normalizedBuffer, rows, cols, factor, targetWidth);
  
  const allResults = [];
  const cellW = Math.floor(metadata.width / cols);
  const cellH = Math.floor(metadata.height / rows);

  const sourceLabel = Buffer.isBuffer(inputSource) ? 'Buffer' : inputSource;
  console.error(`Processing ${sourceLabel} with standardized pipeline...`);
  
  // Decide which versions of the image to scan (Multi-pass Attack Detection)
  const buffersToScan = [
    { buffer: normalizedBuffer, label: 'original' }
  ];

  // --- Attack Detection Passes ---
  console.error('Running Attack Detection Passes...');
  
  // Pass 1: Extreme Contrast & Gamma (Low-contrast hidden text)
  const extreme = await processor.applyExtremeContrast(normalizedBuffer);
  buffersToScan.push({ buffer: extreme, label: 'extreme_contrast' });

  // Pass 2: High-maxSlope CLAHE (Local texture anomalies)
  const clahe = await processor.applyClahe(normalizedBuffer, 50, 50, 100);
  buffersToScan.push({ buffer: clahe, label: 'high_clahe' });

  // Pass 3: Edge detection (Outlined text)
  const edge = await processor.applyEdgeDetect(normalizedBuffer);
  buffersToScan.push({ buffer: edge, label: 'edge_detect' });

  // Pass 4: Low-threshold (Faint text on bright bg)
  const darkText = await processor.applyThreshold(normalizedBuffer, 40);
  buffersToScan.push({ buffer: darkText, label: 'low_threshold' });

  const normalResults = [];
  const extremeResults = [];
  const qrAttacks = [];

  // Pass 0: Initial QR Scan on main buffer
  const mainQr = await detectAndDecodeQR(normalizedBuffer);
  qrAttacks.push(...mainQr.map(q => ({ ...q, source: 'qr_main' })));

  for (const { buffer, label } of buffersToScan) {
    console.error(` -> Processing [${label}] version...`);
    const isExtreme = ['extreme_contrast', 'high_clahe', 'edge_detect', 'low_threshold'].includes(label);
    
    // Scan whole image
    const wholeWords = await recognizeWithTesseract(buffer, { left: 0, top: 0, factor: 1 });
    const wholeWordsWithSource = wholeWords.map(w => ({ ...w, source: label }));
    if (isExtreme) extremeResults.push(...wholeWordsWithSource);
    else normalResults.push(...wholeWordsWithSource);

    // Scan grid crops
    for (const crop of gridCrops) {
      const left = crop.col * cellW;
      const top = crop.row * cellH;
      
      let cropBuffer = crop.buffer;
      if (label === 'extreme_contrast') {
        cropBuffer = await processor.applyExtremeContrast(crop.buffer);
      } else if (label === 'high_clahe') {
        cropBuffer = await processor.applyClahe(crop.buffer, 30, 30, 100);
      } else if (label === 'edge_detect') {
        cropBuffer = await processor.applyEdgeDetect(crop.buffer);
      } else if (label === 'low_threshold') {
        cropBuffer = await processor.applyThreshold(crop.buffer, 40);
      }
      
      const words = await recognizeWithTesseract(cropBuffer, { left, top, factor });
      const wordsWithSource = words.map(w => ({ ...w, source: label }));
      if (isExtreme) extremeResults.push(...wordsWithSource);
      else normalResults.push(...wordsWithSource);
    }
  }

  // Pass 0.1: QR Scan on original crops (optimized)
  for (const crop of gridCrops) {
    const left = crop.col * cellW;
    const top = crop.row * cellH;
    const cropQr = await detectAndDecodeQR(crop.buffer);
    qrAttacks.push(...cropQr.map(q => ({
      ...q,
      source: `qr_crop_${crop.row}_${crop.col}`,
      bbox: {
        x: Math.round((q.bbox.x / factor) + left),
        y: Math.round((q.bbox.y / factor) + top),
        w: Math.round(q.bbox.w / factor),
        h: Math.round(q.bbox.h / factor)
      }
    })));
  }

  // Helper to de-duplicate and match
  const deduplicate = (list) => {
    const seen = new Map();
    
    list.forEach(w => {
      const key = `${w.text.trim().toLowerCase()}_${Math.round(w.bbox.x/10)}_${Math.round(w.bbox.y/10)}`;
      if (!seen.has(key)) {
        seen.set(key, w);
      } else {
        // Optional: Combine sources if found in multiple passes
        const existing = seen.get(key);
        if (existing.source !== w.source && !existing.source.includes(w.source)) {
          existing.source = `${existing.source}, ${w.source}`;
        }
      }
    });

    return Array.from(seen.values()).filter(w => w.text.length > 1);
  };

  const cleanNormal = deduplicate(normalResults);
  const cleanExtreme = deduplicate(extremeResults);

  // Find "Hidden" text candidate words
  const hiddenCandidateWords = cleanExtreme.filter(ext => {
    const isFoundInNormal = cleanNormal.some(norm => {
      const textMatch = norm.text.trim().toLowerCase() === ext.text.trim().toLowerCase();
      const dist = Math.sqrt(Math.pow(norm.bbox.x - ext.bbox.x, 2) + Math.pow(norm.bbox.y - ext.bbox.y, 2));
      return textMatch && dist < 30;
    });
    return !isFoundInNormal;
  });

  // --- 1. Group Hidden Words into Lines/Sentences ---
  const groups = [];
  if (hiddenCandidateWords.length > 0) {
    const sorted = [...hiddenCandidateWords].sort((a, b) => (a.bbox.y - b.bbox.y) || (a.bbox.x - b.bbox.x));
    let currentGroup = [sorted[0]];
    for (let i = 1; i < sorted.length; i++) {
      const last = currentGroup[currentGroup.length - 1];
      const curr = sorted[i];
      const yDiff = Math.abs(curr.bbox.y - last.bbox.y);
      const xDist = curr.bbox.x - (last.bbox.x + last.bbox.w);
      if (yDiff < 15 && xDist < 60) currentGroup.push(curr);
      else { groups.push(currentGroup); currentGroup = [curr]; }
    }
    groups.push(currentGroup);
  }

  // --- 2. Score Each Line ---
  const scoredLines = groups.map(group => {
    const minX = Math.min(...group.map(w => w.bbox.x));
    const minY = Math.min(...group.map(w => w.bbox.y));
    const maxX = Math.max(...group.map(w => w.bbox.x + w.bbox.w));
    const maxY = Math.max(...group.map(w => w.bbox.y + w.bbox.h));
    const text = group.map(w => w.text).join(' ');
    const sources = Array.from(new Set(group.flatMap(w => w.source.split(', '))));
    const avgConf = group.reduce((acc, w) => acc + w.conf, 0) / group.length;
    const avgHeight = (maxY - minY);

    let score = 20; // Lowered base score
    
    // Length Penalty (Filter out tiny fragments like 'ing', 'NN')
    if (text.length < 5) score -= 30;
    else if (text.length > 10) score += 15;

    // Source analysis
    if (sources.includes('high_clahe')) score += 10;
    if (sources.includes('low_threshold')) score += 10;
    if (sources.length >= 2) score += 20;

    // Location analysis (Is in margin?)
    const isMargin = minX < 100 || maxX > (metadata.width - 100) || minY < 100 || maxY > (metadata.height - 100);
    if (isMargin) score += 15;
    if (avgHeight < 25) score += 20; // Strong tiny text signal

    // Confidence
    if (avgConf > 80) score += 10;
    if (avgConf < 50) score -= 25; // Harsher penalty for low confidence

    // Content analysis (The most important factor)
    const containsUrl = /http|https|\.com|\.test|\.sh|curl|bash|admin|root|override|inject|exploit/i.test(text);
    if (containsUrl) score += 40; // Increased bonus for clear attack patterns
    if (/[A-Z]{3,}/.test(text)) score += 10;
    if (/=|:|\[|\]|\/|\.|\-/.test(text)) score += 10;

    // Proximity Penalty: Check if it's too close to normal visible text
    const isCloseToNormal = cleanNormal.some(norm => {
      const dist = Math.sqrt(Math.pow(norm.bbox.x - minX, 2) + Math.pow(norm.bbox.y - minY, 2));
      return dist < 50; // Within 50px of visible text is likely a halo/ghost
    });
    if (isCloseToNormal) score -= 30;

    return {
      x: minX, y: minY, w: maxX - minX, h: maxY - minY,
      text, sources, score, avgConf
    };
  });

  // Strict Threshold: Only high confidence attacks
  const filteredAttacks = scoredLines.filter(line => line.score >= 85);

  // --- 3. Merge QR Attacks ---
  const finalAttacks = [
    ...filteredAttacks.map(a => ({ ...a, type: 'hidden_text' })),
    ...qrAttacks.map(q => ({
      x: q.bbox.x, y: q.bbox.y, w: q.bbox.w, h: q.bbox.h,
      text: q.text, sources: [q.source], score: q.score, avgConf: 100,
      type: 'qr_code', category: q.category
    }))
  ];

  return {
    resolution: { width: metadata.width, height: metadata.height },
    normalWords: cleanNormal,
    hiddenAttacks: finalAttacks.sort((a, b) => b.score - a.score)
  };
}

/**
 * Self-Test to verify Tesseract is working
 */
async function runSelfTest() {
  console.error('Running OCR Self-Test...');
  try {
    const blank = await sharp({
      create: { width: 200, height: 100, channels: 3, background: { r: 255, g: 255, b: 255 } }
    }).png().toBuffer();
    
    const worker = await Tesseract.createWorker('eng');
    const result = await worker.recognize(blank, {}, { blocks: true });
    await worker.terminate();
    
    console.error('Self-Test Result: Engine is alive');
    return true;
  } catch (err) {
    console.error('Self-Test FAILED:', err);
    return false;
  }
}

// CLI Execution
if (process.argv[1].endsWith('ocr.js')) {
  const filePath = process.argv[2];
  if (!filePath) {
    console.error('Usage: node src/ocr.js <image_or_pdf_path>');
    process.exit(1);
  }

  runSelfTest().then(async alive => {
    if (!alive) process.exit(1);
    
    let inputSource = filePath;
    
    // Handle PDF by converting first page to image
    if (filePath.toLowerCase().endsWith('.pdf')) {
      console.error(`📄 PDF detected: ${filePath}. Extracting first page...`);
      try {
        const data = new Uint8Array(await readFile(filePath));
        const loadingTask = pdfjs.getDocument({ data, verbosity: 0 });
        const pdf = await loadingTask.promise;
        const page = await pdf.getPage(1);
        const viewport = page.getViewport({ scale: 2.0 });
        
        // We use canvas to render the PDF page to a buffer
        const canvas = createCanvas(viewport.width, viewport.height);
        const context = canvas.getContext('2d');
        
        await page.render({
          canvasContext: context,
          viewport: viewport
        }).promise;
        
        inputSource = canvas.toBuffer('image/png');
      } catch (err) {
        console.error('Failed to process PDF:', err);
        process.exit(1);
      }
    }

    scanStandardized(inputSource).then(async data => {
      // Visualization (Only for Scored Attacks)
      const outputDir = 'examples/detected';
      const fileName = path.basename(filePath, path.extname(filePath));
      const outputPath = path.join(outputDir, `${fileName}_detected.png`);

      await mkdir(outputDir, { recursive: true });
      const vizBuffer = await processor.drawBoundingBoxes(inputSource, data.hiddenAttacks);
      await writeFile(outputPath, vizBuffer);

      // Construct JSON Output
      const resultJson = {
        source: filePath,
        resolution: `${data.resolution.width}x${data.resolution.height}`,
        visualized_result: outputPath,
        visible_text: data.normalWords.map(w => w.text).join(' '),
        detected_attacks: data.hiddenAttacks.map(attack => ({
          type: attack.type,
          category: attack.category || 'hidden_text',
          text: attack.text,
          score: attack.score,
          location: { x: attack.x, y: attack.y, w: attack.w, h: attack.h },
          sources: attack.sources
        }))
      };

      // Print only JSON to stdout
      console.log(JSON.stringify(resultJson, null, 2));

    }).catch(err => {
      console.error(JSON.stringify({ error: 'Pipeline failed', details: err.message }, null, 2));
    });
  });
}
