import jsQR from 'jsqr';
import sharp from 'sharp';

/**
 * QR Code Processor for Attack Detection
 */

/**
 * Decodes QR codes from an image buffer
 * @param {Buffer} buffer - Image buffer
 * @returns {Promise<Array>} - Array of detected QR code data
 */
export async function detectAndDecodeQR(buffer) {
  try {
    const image = sharp(buffer);
    const { data, info } = await image
      .ensureAlpha()
      .raw()
      .toBuffer({ resolveWithObject: true });

    const code = jsQR(new Uint8ClampedArray(data), info.width, info.height);

    if (code) {
      const classification = classifyQrContent(code.data);
      const scoreData = scoreQrAttack(code.data, classification, info);

      return [{
        text: code.data,
        location: code.location,
        bbox: {
          x: code.location.topLeftCorner.x,
          y: code.location.topLeftCorner.y,
          w: code.location.topRightCorner.x - code.location.topLeftCorner.x,
          h: code.location.bottomLeftCorner.y - code.location.topLeftCorner.y
        },
        classification,
        ...scoreData
      }];
    }
    return [];
  } catch (err) {
    console.error('QR Detection Error:', err);
    return [];
  }
}

/**
 * Classifies QR content into categories
 */
export function classifyQrContent(text) {
  const patterns = {
    COMMAND: /\b(curl|wget|bash|sh|sudo|rm|python|perl|ruby|nc|netcat)\b/i,
    URL: /^(https?:\/\/|www\.)[^\s/$.?#].[^\s]*$/i,
    SUSPICIOUS_URL: /(bit\.ly|t\.co|goo\.gl|tinyurl|ipfs|onion|verify|login|secure|update)/i,
    CREDENTIALS: /(password|passwd|secret|key|token|auth|admin|root)/i,
    OBFUSCATED: /(base64|hex|\\x|0x)/i
  };

  if (patterns.COMMAND.test(text)) return 'COMMAND_INJECTION';
  if (patterns.SUSPICIOUS_URL.test(text)) return 'PHISHING_URL';
  if (patterns.URL.test(text)) return 'URL';
  if (patterns.CREDENTIALS.test(text)) return 'CREDENTIAL_EXFILTRATION';
  if (patterns.OBFUSCATED.test(text)) return 'OBFUSCATED_PAYLOAD';
  
  return 'PLAIN_TEXT';
}

/**
 * Scores the risk of a QR code
 */
export function scoreQrAttack(text, classification, metadata) {
  let score = 50; // Base score for any QR code (hidden intent)

  // Classification bonuses
  switch (classification) {
    case 'COMMAND_INJECTION': score += 45; break;
    case 'PHISHING_URL': score += 40; break;
    case 'CREDENTIAL_EXFILTRATION': score += 45; break;
    case 'OBFUSCATED_PAYLOAD': score += 35; break;
    case 'URL': score += 10; break;
    default: score += 0;
  }

  // Content-based bonuses
  if (text.length > 200) score += 10; // Large payload
  if (/(\.\.\/|\/etc\/|C:\\)/.test(text)) score += 20; // Path traversal
  if (/(override|bypass|ignore|grant|allow)/i.test(text)) score += 15; // Instruction override

  // Size-based bonus (Tiny QR codes are suspicious)
  // Assuming normal QR is at least 100x100 in a 2000px image
  const qrArea = (metadata.width * metadata.height) / 100; // arbitrary threshold
  // This is hard to judge without knowing the QR's actual size in the image
  // But let's say if the total resolution is high and we found it, it's already a good signal.

  return {
    score: Math.min(score, 100),
    category: classification
  };
}
