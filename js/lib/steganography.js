/**
 * Steganography (LSB — least significant bit) detect/extract for
 * images. Educational tool, clearly labeled as such in the UI. Works
 * on raw RGBA pixel data (e.g. from a <canvas> ImageData), so it is
 * pure and testable without any actual image/canvas dependency.
 *
 * Encoding scheme: message bytes (UTF-8) are written one bit at a time
 * into the LSB of each RGB channel (alpha channel skipped to avoid
 * visible transparency artifacts), in row-major pixel order. A 32-bit
 * big-endian length prefix (in bytes) precedes the message so the
 * decoder knows where to stop.
 */

const HEADER_BITS = 32;

function bytesToBits(bytes) {
  const bits = [];
  for (const b of bytes) {
    for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
  }
  return bits;
}

function bitsToBytes(bits) {
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i * 8 + j];
    bytes[i] = byte;
  }
  return bytes;
}

/** Max message bytes that can be embedded in an RGBA buffer of the given pixel count. */
export function lsbCapacityBytes(pixelCount) {
  const usableBits = pixelCount * 3; // R, G, B per pixel; alpha skipped
  return Math.max(0, Math.floor(usableBits / 8) - 4); // minus 4-byte length header
}

/**
 * Embed a UTF-8 string message into RGBA image data using LSB
 * steganography. Returns a NEW Uint8ClampedArray (does not mutate input).
 * @param {Uint8ClampedArray|Uint8Array} rgbaData
 * @param {string} message
 */
export function lsbEncode(rgbaData, message) {
  const msgBytes = new TextEncoder().encode(message);
  const pixelCount = rgbaData.length / 4;
  const capacity = lsbCapacityBytes(pixelCount);
  if (msgBytes.length > capacity) {
    throw new Error(`Message too long: ${msgBytes.length} bytes, capacity is ${capacity} bytes for this image`);
  }

  const lengthBytes = new Uint8Array(4);
  new DataView(lengthBytes.buffer).setUint32(0, msgBytes.length, false);

  const allBits = bytesToBits(lengthBytes).concat(bytesToBits(msgBytes));

  const out = new Uint8ClampedArray(rgbaData);
  let bitIndex = 0;
  for (let p = 0; p < pixelCount && bitIndex < allBits.length; p++) {
    for (let ch = 0; ch < 3 && bitIndex < allBits.length; ch++) {
      const idx = p * 4 + ch;
      out[idx] = (out[idx] & 0xfe) | allBits[bitIndex];
      bitIndex++;
    }
  }
  return out;
}

/**
 * Extract a hidden message from RGBA image data previously encoded
 * with lsbEncode. Returns the decoded string, or throws if no valid
 * length header is found (e.g. > capacity or clearly garbage).
 */
export function lsbDecode(rgbaData) {
  const pixelCount = rgbaData.length / 4;
  const maxBits = pixelCount * 3;

  const headerBits = [];
  let bitIndex = 0;
  for (let p = 0; p < pixelCount && bitIndex < HEADER_BITS; p++) {
    for (let ch = 0; ch < 3 && bitIndex < HEADER_BITS; ch++) {
      headerBits.push(rgbaData[p * 4 + ch] & 1);
      bitIndex++;
    }
  }
  const lengthBytes = bitsToBytes(headerBits);
  const msgLen = new DataView(lengthBytes.buffer).getUint32(0, false);

  const totalBitsNeeded = HEADER_BITS + msgLen * 8;
  if (msgLen === 0) return '';
  if (totalBitsNeeded > maxBits) {
    throw new Error('No valid hidden message found (length header exceeds image capacity)');
  }

  const msgBits = [];
  bitIndex = 0;
  let collected = 0;
  for (let p = 0; p < pixelCount && collected < totalBitsNeeded; p++) {
    for (let ch = 0; ch < 3 && collected < totalBitsNeeded; ch++) {
      if (collected >= HEADER_BITS) msgBits.push(rgbaData[p * 4 + ch] & 1);
      collected++;
    }
  }
  const msgBytes = bitsToBytes(msgBits);
  return new TextDecoder().decode(msgBytes);
}
