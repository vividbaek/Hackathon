import Tesseract from 'tesseract.js';
import { spawn } from 'node:child_process';
import * as processor from './utils/image-processor.js';
import sharp from 'sharp';
import { writeFile, unlink, mkdir } from 'node:fs/promises';
import path, { join } from 'node:path';
import { tmpdir } from 'node:os';

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
export async function scanStandardized(inputPath, targetWidth = 2000, options = { invert: true }) {
  const quiet = Boolean(options.quiet);
  // 1. Create a normalized master buffer
  const normalizedBuffer = await sharp(inputPath, { density: 300 })
    .resize({ width: targetWidth })
    .flatten({ background: { r: 255, g: 255, b: 255 } })
    .png()
    .toBuffer();

  const metadata = await sharp(normalizedBuffer).metadata();
  const rows = 2, cols = 2, factor = 2;
  const gridCrops = await processor.gridScaleUp(normalizedBuffer, rows, cols, factor, targetWidth, { quiet });
  
  const allResults = [];
  const cellW = Math.floor(metadata.width / cols);
  const cellH = Math.floor(metadata.height / rows);

  if (!quiet) {
    console.log(`Processing ${inputPath} with standardized pipeline...`);
  }
  
  // Decide which versions of the image to scan (Multi-pass Attack Detection)
  const buffersToScan = [
    { buffer: normalizedBuffer, label: 'original' }
  ];

  // --- Attack Detection Passes ---
  if (!quiet) {
    console.log('Running Attack Detection Passes...');
  }
  
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

  for (const { buffer, label } of buffersToScan) {
    if (!quiet) {
      console.log(` -> Processing [${label}] version...`);
    }
    const isExtreme = ['extreme_contrast', 'high_clahe', 'edge_detect', 'low_threshold'].includes(label);
    
    // Scan whole image
    const wholeWords = await recognizeWithTesseract(buffer, { left: 0, top: 0, factor: 1 });
    if (isExtreme) extremeResults.push(...wholeWords);
    else normalResults.push(...wholeWords);

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
      if (isExtreme) extremeResults.push(...words);
      else normalResults.push(...words);
    }
  }

  // Helper to de-duplicate and match
  const deduplicate = (list) => {
    return Array.from(new Set(list.map(w => JSON.stringify({ text: w.text.trim().toLowerCase(), x: Math.round(w.bbox.x/10), y: Math.round(w.bbox.y/10) }))))
      .map(s => {
        const p = JSON.parse(s);
        return list.find(w => w.text.trim().toLowerCase() === p.text && Math.round(w.bbox.x/10) === p.x && Math.round(w.bbox.y/10) === p.y);
      })
      .filter(w => w.text.length > 1);
  };

  const cleanNormal = deduplicate(normalResults);
  const cleanExtreme = deduplicate(extremeResults);

  // Find "Hidden" text: Found in extreme but NOT in normal
  const hiddenText = cleanExtreme.filter(ext => {
    // Check if any normal word matches this extreme word spatially and textually
    const isFoundInNormal = cleanNormal.some(norm => {
      const textMatch = norm.text.trim().toLowerCase() === ext.text.trim().toLowerCase();
      const dist = Math.sqrt(Math.pow(norm.bbox.x - ext.bbox.x, 2) + Math.pow(norm.bbox.y - ext.bbox.y, 2));
      return textMatch && dist < 30; // Within 30px distance
    });
    return !isFoundInNormal;
  });

  return {
    resolution: { width: metadata.width, height: metadata.height },
    normalizedBuffer,
    normalWords: cleanNormal,
    hiddenWords: hiddenText
  };
}

/**
 * Self-Test to verify Tesseract is working
 */
async function runSelfTest() {
  console.log('Running OCR Self-Test...');
  try {
    const blank = await sharp({
      create: { width: 200, height: 100, channels: 3, background: { r: 255, g: 255, b: 255 } }
    }).png().toBuffer();
    
    const worker = await Tesseract.createWorker('eng');
    const result = await worker.recognize(blank, {}, { blocks: true });
    await worker.terminate();
    
    console.log('Self-Test Result: Engine is alive');
    return true;
  } catch (err) {
    console.error('Self-Test FAILED:', err);
    return false;
  }
}

// CLI Execution
if (process.argv[1].endsWith('ocr.js')) {
  const imgPath = process.argv[2];
  if (!imgPath) {
    console.log('Usage: node src/ocr.js <image_path>');
    process.exit(1);
  }

  runSelfTest().then(alive => {
    if (!alive) process.exit(1);
    
    scanStandardized(imgPath).then(data => {
      console.log('\n' + '='.repeat(50));
      console.log('📊 OCR ANALYSIS REPORT');
      console.log('='.repeat(50));
      console.log(`Resolution: ${data.resolution.width}x${data.resolution.height}`);
      
      console.log('\n[1] NORMAL VISIBLE TEXT:');
      if (data.normalWords.length === 0) console.log(' (None)');
      data.normalWords.forEach(w => {
        if (w.conf > 60) console.log(` - ${w.text} (${w.conf}%)`);
      });

      console.log('\n' + '!'.repeat(50));
      console.log('🚨 HIDDEN ATTACK DETECTION (Extreme Processing Only)');
      console.log('!'.repeat(50));
      if (data.hiddenWords.length === 0) {
        console.log(' ✅ No hidden text detected.');
      } else {
        data.hiddenWords.forEach(w => {
          console.log(` 🚩 DETECTED: "${w.text}" (conf: ${w.conf}%) at x:${w.bbox.x}, y:${w.bbox.y}`);
        });
      }
      console.log('!'.repeat(50) + '\n');

      // Visualization (Only for Hidden Attacks)
      const outputDir = 'examples/detected';
      const fileName = path.basename(imgPath, path.extname(imgPath));
      const outputPath = path.join(outputDir, `${fileName}_detected.png`);

      mkdir(outputDir, { recursive: true })
        .then(() => processor.drawBoundingBoxes(imgPath, data.hiddenWords))
        .then(vizBuffer => writeFile(outputPath, vizBuffer))
        .then(() => console.log(`✅ Visualized result (HIDDEN ONLY) saved to: ${outputPath}`))
        .catch(err => console.error('Failed to save visualization:', err));

    }).catch(err => {
      console.error('Pipeline failed:', err);
    });
  });
}
