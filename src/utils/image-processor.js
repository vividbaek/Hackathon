import sharp from 'sharp';

/**
 * Image processing utilities for OCR enhancement
 */

// 1. [Base] Original
export async function getOriginal(input) {
  return sharp(input).toBuffer();
}

// 2. [Size] Grid Split & Scale-up
/**
 * Splits image into grid after normalizing to a standard width (Industry Standard)
 */
export async function gridScaleUp(input, rows = 2, cols = 2, factor = 2, targetWidth = 2000) {
  // 1. Ensure image is at target width
  let image = sharp(input);
  let metadata = await image.metadata();
  
  if (metadata.width !== targetWidth) {
    const resizedBuffer = await image.resize({ width: targetWidth }).toBuffer();
    image = sharp(resizedBuffer);
    metadata = await image.metadata();
  }

  const width = metadata.width;
  const height = metadata.height;
  const cellWidth = Math.floor(width / cols);
  const cellHeight = Math.floor(height / rows);
  
  const crops = [];
  const normalizedBuffer = await image.toBuffer();
  
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const left = c * cellWidth;
      const top = r * cellHeight;
      const actualWidth = (c === cols - 1) ? width - left : cellWidth;
      const actualHeight = (r === rows - 1) ? height - top : cellHeight;

      console.error(`  -> Crop [${r},${c}]: ${actualWidth}x${actualHeight} at (${left},${top})`);

      // Skip very small crops or slivers (user requested to drop too small images)
      if (actualWidth < 100 || actualHeight < 100) {
        console.warn(`     [SKIP] Image too small for scaling`);
        continue;
      }
      
      try {
        const buffer = await sharp(normalizedBuffer)
          .extract({ 
            left: Math.floor(left), 
            top: Math.floor(top), 
            width: Math.floor(actualWidth), 
            height: Math.floor(actualHeight) 
          })
          .resize(Math.floor(actualWidth * factor), Math.floor(actualHeight * factor))
          .toBuffer();
        
        crops.push({ row: r, col: c, buffer });
      } catch (err) {
        console.error(`     [ERROR] Failed to extract/resize at [${r},${c}]: ${err.message}`);
      }
    }
  }
  
  return crops;
}

// 3. [Contrast] CLAHE (Enhanced for hidden text)
export async function applyClahe(input, width = 20, height = 20, maxSlope = 100) {
  return sharp(input)
    .clahe({ width, height, maxSlope })
    .toBuffer();
}

// 4. [Binarization] Threshold (Adaptive-like)
export async function applyThreshold(input, value = 128) {
  return sharp(input)
    .greyscale()
    .threshold(value)
    .toBuffer();
}

// 5. [Color] Inversion
export async function applyInversion(input) {
  return sharp(input)
    .negate()
    .toBuffer();
}

// 6. [Detail] Sharpening
export async function applySharpen(input) {
  return sharp(input)
    .sharpen({ sigma: 2 })
    .toBuffer();
}

// 7. [Extreme] Gamma & Linear Stretching (Uncovers low-contrast hidden text)
export async function applyExtremeContrast(input) {
  return sharp(input)
    .gamma(3.0) // Boost dark areas
    .linear(2.0, -100) // Stretch contrast
    .modulate({ contrast: 2.0, brightness: 1.2 })
    .toBuffer();
}

// 8. [Extreme] Edge Detection
export async function applyEdgeDetect(input) {
  return sharp(input)
    .greyscale()
    .convolve({
      width: 3,
      height: 3,
      kernel: [-1, -1, -1, -1, 8, -1, -1, -1, -1]
    })
    .threshold(10)
    .toBuffer();
}

// 9. [Visualization] Draw Bounding Boxes
export async function drawBoundingBoxes(input, hiddenAttacks, targetWidth = 2000) {
  const normalizedBase = await sharp(input, { density: 300 })
    .resize({ width: targetWidth })
    .toBuffer();
    
  const meta = await sharp(normalizedBase).metadata();
  const { width, height } = meta;

  // --- Create SVG Overlay ---
  let svgParts = [
    `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg">`
  ];

  hiddenAttacks.forEach(attack => {
    const isQr = attack.type === 'qr_code';
    const color = isQr ? '#7C3AED' : 'red'; // Purple for QR, Red for Hidden Text
    const bgColor = isQr ? 'rgba(124, 58, 237, 0.2)' : 'rgba(255, 0, 0, 0.2)';
    const icon = isQr ? '📱' : '🚨';
    const typeLabel = isQr ? `QR: ${attack.category}` : 'HIDDEN TEXT';
    const sourceStr = attack.sources.join(', ');
    
    svgParts.push(`
      <g>
        <!-- Box -->
        <rect x="${attack.x - 5}" y="${attack.y - 5}" width="${attack.w + 10}" height="${attack.h + 10}" 
              fill="${bgColor}" stroke="${color}" stroke-width="4" rx="5" stroke-dasharray="${isQr ? '0' : '8,4'}" />
        
        <!-- Label Background -->
        <rect x="${attack.x - 5}" y="${attack.y - 85}" width="${Math.max(attack.text.length * 15, (typeLabel.length + sourceStr.length) * 12 + 100)}" height="80" fill="${color}" rx="5" />
        
        <!-- Label Text -->
        <text x="${attack.x + 5}" y="${attack.y - 50}" fill="white" font-family="monospace" font-size="22" font-weight="bold">
          ${icon} ${typeLabel} (Score: ${attack.score})
        </text>
        <text x="${attack.x + 5}" y="${attack.y - 20}" fill="rgba(255,255,255,0.9)" font-family="monospace" font-size="18">
          Payload: "${attack.text.length > 50 ? attack.text.substring(0, 47) + '...' : attack.text}"
        </text>
      </g>
    `);
  });

  svgParts.push('</svg>');
  const svgBuffer = Buffer.from(svgParts.join(''));

  return sharp(normalizedBase)
    .composite([{ input: svgBuffer, top: 0, left: 0 }])
    .png()
    .toBuffer();
}
