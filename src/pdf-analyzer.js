import pkgCanvas from 'canvas';
const { createCanvas, DOMMatrix } = pkgCanvas;

// Polyfills for Node.js
if (typeof global.DOMMatrix === 'undefined') {
  global.DOMMatrix = DOMMatrix;
}

import * as pdfjs from 'pdfjs-dist/legacy/build/pdf.mjs';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { scanStandardized } from './ocr.js';
import path from 'node:path';

// Node.js worker setup
pdfjs.GlobalWorkerOptions.workerSrc = path.resolve('./node_modules/pdfjs-dist/legacy/build/pdf.worker.mjs');

/**
 * Analyzes a PDF for hidden text attacks by comparing the text layer with OCR results.
 */
export async function analyzePdf(pdfPath) {
  const data = new Uint8Array(await readFile(pdfPath));
  const loadingTask = pdfjs.getDocument({ 
    data,
    useSystemFonts: true,
    disableFontFace: false
  });
  const doc = await loadingTask.promise;
  
  console.log(`\n📄 Analyzing PDF: ${path.basename(pdfPath)}`);
  console.log(`Total Pages: ${doc.numPages}`);
  
  const allPageResults = [];

  for (let pageNum = 1; pageNum <= doc.numPages; pageNum++) {
    console.log(`\n--- Page ${pageNum} ---`);
    const page = await doc.getPage(pageNum);
    
    // 1. Render Page to Image for OCR
    const scale = 2.0; 
    const viewport = page.getViewport({ scale });
    const canvas = createCanvas(viewport.width, viewport.height);
    const context = canvas.getContext('2d');
    
    await page.render({ 
      canvasContext: context, 
      viewport,
      intent: 'print' // Use print intent to ensure all elements are rendered
    }).promise;
    
    const buffer = canvas.toBuffer('image/png');
    
    // 2. Extract Text Layer
    const textContent = await page.getTextContent();
    const layerItems = textContent.items.map(item => ({
      text: item.str,
      x: item.transform[4],
      y: item.transform[5],
      width: item.width,
      height: item.height,
      fontName: item.fontName
    })).filter(item => item.text.trim().length > 0);

    const fullLayerText = layerItems.map(i => i.text).join(' ');
    
    // 3. Run OCR Pipeline (including attack detection passes)
    const ocrResult = await scanStandardized(buffer);
    
    // 4. Comparison Logic
    const pdfToImageFactor = 2000 / viewport.width;
    const hiddenInLayer = [];
    
    for (const item of layerItems) {
      const cleanItem = item.text.trim().toLowerCase();
      if (cleanItem.length < 2) continue;

      const isVisible = ocrResult.normalWords.some(w => {
        const cleanOcr = w.text.trim().toLowerCase();
        return cleanOcr.includes(cleanItem) || cleanItem.includes(cleanOcr);
      });

      if (!isVisible) {
        const attackMatch = ocrResult.hiddenAttacks.find(a => {
            const cleanAttack = a.text.toLowerCase();
            return cleanAttack.includes(cleanItem) || cleanItem.includes(cleanAttack);
        });

        // Determine Attack Type
        let type = 'HIDDEN (LAYER-ONLY)';
        let score = 90;

        if (attackMatch) {
            type = 'OBFUSCATED (RECOVERED)';
            score = 100;
        } else if (item.height < 3) {
            type = 'TINY TEXT (MICRO)';
            score = 95;
        }

        const [vx, vy] = viewport.convertToViewportPoint(item.x, item.y);
        
        hiddenInLayer.push({
          ...item,
          type,
          score,
          imageX: vx * pdfToImageFactor,
          imageY: vy * pdfToImageFactor,
          imageW: (item.width || 50) * scale * pdfToImageFactor,
          imageH: (item.height || 10) * scale * pdfToImageFactor,
          caughtByEnhancement: !!attackMatch
        });
      }
    }

    const groupedHidden = groupHiddenItems(hiddenInLayer);

    // 5. Visualization
    const combinedAttacks = [
        ...ocrResult.hiddenAttacks.map(a => ({ ...a, type: 'VISUAL ANOMALY' })),
        ...groupedHidden.map(h => ({
            x: h.imageX,
            y: h.imageY - h.imageH,
            w: h.imageW,
            h: h.imageH,
            text: h.text,
            sources: [h.type],
            score: h.score
        }))
    ];

    const outputDir = 'examples/detected';
    await mkdir(outputDir, { recursive: true });
    const fileName = path.basename(pdfPath, '.pdf');
    const outputPath = path.join(outputDir, `${fileName}_p${pageNum}_detected.png`);
    
    const vizBuffer = await processor.drawBoundingBoxes(buffer, combinedAttacks);
    await writeFile(outputPath, vizBuffer);
    console.log(`✅ Visualized result saved to: ${outputPath}`);

    allPageResults.push({
      page: pageNum,
      resolution: ocrResult.resolution,
      layerText: fullLayerText,
      ocrVisibleText: ocrResult.normalWords.map(w => w.text).join(' '),
      detectedAttacks: ocrResult.hiddenAttacks,
      hiddenLayerCandidates: groupedHidden,
      vizPath: outputPath
    });
  }

  return allPageResults;
}

import * as processor from './utils/image-processor.js';

function groupHiddenItems(items) {
    if (items.length === 0) return [];
    
    const sorted = [...items].sort((a, b) => (Math.abs(b.y - a.y) > 2 ? b.y - a.y : a.x - b.x));
    
    const groups = [];
    if (sorted.length > 0) {
        let currentGroup = [sorted[0]];
        for (let i = 1; i < sorted.length; i++) {
            const last = currentGroup[currentGroup.length - 1];
            const curr = sorted[i];
            
            const yDiff = Math.abs(curr.y - last.y);
            const xDist = curr.x - (last.x + last.width);
            
            if (yDiff < 5 && (xDist < 30 || xDist < 0)) {
                currentGroup.push(curr);
            } else {
                groups.push(currentGroup);
                currentGroup = [curr];
            }
        }
        groups.push(currentGroup);
    }
    
    return groups.map(g => ({
        text: g.map(i => i.text).join(' ').replace(/\s+/g, ' ').trim(),
        x: Math.min(...g.map(i => i.x)),
        y: Math.max(...g.map(i => i.y)),
        imageX: Math.min(...g.map(i => i.imageX)),
        imageY: Math.min(...g.map(i => i.imageY)),
        imageW: Math.max(...g.map(i => (i.imageX + i.imageW))) - Math.min(...g.map(i => i.imageX)),
        imageH: Math.max(...g.map(i => i.imageH)),
        caughtByEnhancement: g.some(i => i.caughtByEnhancement),
        type: g[0].type, // Take type from first item in group
        score: Math.max(...g.map(i => i.score))
    })).filter(g => g.text.length > 1);
}

// CLI Support
if (process.argv[1].endsWith('pdf-analyzer.js')) {
    const pdfPath = process.argv[2];
    if (!pdfPath) {
        console.log('Usage: node src/pdf-analyzer.js <path_to_pdf>');
        process.exit(1);
    }

    analyzePdf(pdfPath).then(results => {
        console.log('\n' + '═'.repeat(70));
        console.log('🛡️  ADVANCED PDF THREAT ANALYSIS');
        console.log('═'.repeat(70));

        let totalAttacks = 0;

        results.forEach(res => {
            console.log(`\n[PAGE ${res.page}]`);
            
            const hidden = res.hiddenLayerCandidates;
            const visual = res.detectedAttacks;

            if (hidden.length === 0 && visual.length === 0) {
                console.log('  ✅ Clean: No hidden or anomalous text detected.');
                return;
            }

            if (hidden.length > 0) {
                console.log('\n  🚨 HIDDEN LAYER ATTACK CANDIDATES:');
                hidden.forEach(cand => {
                    totalAttacks++;
                    const status = cand.caughtByEnhancement ? '⚠️  OBFUSCATED (RECOVERED)' : `🔴  ${cand.type}`;
                    console.log(`  ┌─ ${cand.text}`);
                    console.log(`  │  Category: ${cand.type}`);
                    console.log(`  │  Status: ${status}`);
                    console.log(`  │  Location: PDF(x:${Math.round(cand.x)}, y:${Math.round(cand.y)})`);
                    
                    const containsAttack = /http|https|\.com|\.test|\.sh|curl|bash|admin|root|override|inject|exploit|powershell|cmd|eval/i.test(cand.text);
                    if (containsAttack) {
                        console.log(`  │  RISK: 💀 CRITICAL - Remote Execution / Injection Pattern Detected!`);
                    }
                    console.log('  └──────────────────────────────────────────────────────────');
                });
            }

            if (visual.length > 0) {
                console.log('\n  ⚠️  VISUAL ANOMALIES (Detected via Image Multi-pass):');
                visual.forEach(a => {
                    console.log(`  🚩 "${a.text}" (Risk Score: ${a.score})`);
                });
            }
        });

        console.log('\n' + '═'.repeat(70));
        if (totalAttacks > 0) {
            console.log(`🚨 THREATS DETECTED: ${totalAttacks} hidden text candidates found.`);
            console.log('Recommendation: REJECT this PDF or sanitize the text layer.');
        } else {
            console.log('✅ ANALYSIS COMPLETE: No critical threats found.');
        }
        console.log('═'.repeat(70) + '\n');
    }).catch(err => {
        console.error('PDF Analysis Failed:', err);
    });
}

