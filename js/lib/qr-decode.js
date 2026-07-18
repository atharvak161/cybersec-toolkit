/**
 * QR Code decoder for matrices produced by this project's own
 * js/lib/qr-encode.js (versions 1-4, byte mode, EC levels L/M). This
 * reads the format-info bits to recover the mask/level, walks the same
 * zigzag codeword order as the encoder, un-masks, and parses the byte-
 * mode bitstream back to a string.
 *
 * Scope note: this decodes a clean boolean module matrix (e.g. from
 * this tool's own generator, or a very cleanly cropped/axis-aligned
 * scan sampled onto a grid by the UI) — it is not a general-purpose
 * photo/perspective QR scanner (finder-pattern search, perspective
 * correction and Reed-Solomon error correction for damaged codes are
 * out of scope; see README for why).
 */

import {
  createEmptyMatrix,
  placeFinderPattern,
  placeAlignmentPattern,
  placeTimingPatterns,
  ALIGNMENT_CENTER,
  applyMask,
  QR_CAPACITY
} from './qr-encode.js';

const LEVEL_BITS_REVERSE = { 1: 'L', 0: 'M', 3: 'Q', 2: 'H' };
const G15_MASK = 0x5412;

function readFormatInfo(matrix) {
  const size = matrix.length;
  const b = (v) => (v ? 1 : 0);
  let bits = 0;
  // Read the first copy (top-left area), matching the encoder's write order exactly
  for (let i = 0; i <= 5; i++) bits |= b(matrix[i][8]) << i;
  bits |= b(matrix[7][8]) << 6;
  bits |= b(matrix[8][8]) << 7;
  bits |= b(matrix[8][7]) << 8;
  for (let i = 9; i <= 14; i++) bits |= b(matrix[8][15 - 1 - i]) << i;

  const unmasked = bits ^ G15_MASK;
  const dataBits = (unmasked >> 10) & 0x1f;
  const level = LEVEL_BITS_REVERSE[(dataBits >> 3) & 0x3];
  const maskPattern = dataBits & 0x7;
  return { level, maskPattern };
}

function versionFromSize(size) {
  const v = (size - 17) / 4;
  if (!Number.isInteger(v) || v < 1 || v > 4) throw new Error('Unsupported QR size (this decoder supports versions 1-4 only)');
  return v;
}

function buildFunctionMask(size, version) {
  const matrix = createEmptyMatrix(size);
  placeFinderPattern(matrix, 0, 0);
  placeFinderPattern(matrix, 0, size - 7);
  placeFinderPattern(matrix, size - 7, 0);
  const alignCenter = ALIGNMENT_CENTER[version];
  if (alignCenter) placeAlignmentPattern(matrix, alignCenter[0], alignCenter[1]);
  placeTimingPatterns(matrix);
  matrix[size - 8][8] = 1;
  for (let i = 0; i <= 8; i++) {
    if (matrix[8][i] === null) matrix[8][i] = 0;
    if (matrix[i][8] === null) matrix[i][8] = 0;
  }
  for (let i = 0; i < 8; i++) {
    if (matrix[8][size - 1 - i] === null) matrix[8][size - 1 - i] = 0;
    if (matrix[size - 1 - i][8] === null) matrix[size - 1 - i][8] = 0;
  }
  return matrix.map((row) => row.map((v) => v !== null));
}

function extractCodewordBits(matrix, functionMask, maskPattern) {
  const size = matrix.length;
  const bits = [];
  let col = size - 1;
  let upward = true;
  while (col > 0) {
    if (col === 6) col--;
    for (let i = 0; i < size; i++) {
      const row = upward ? size - 1 - i : i;
      for (const c of [col, col - 1]) {
        if (functionMask[row][c]) continue;
        let bit = matrix[row][c] ? 1 : 0;
        if (applyMask(maskPattern, row, c)) bit ^= 1;
        bits.push(bit);
      }
    }
    upward = !upward;
    col -= 2;
  }
  return bits;
}

function bitsToBytes(bits) {
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    bytes.push(b);
  }
  return bytes;
}

/**
 * Decode a boolean module matrix back into the original text.
 * @param {boolean[][]} matrix square matrix as returned by qrEncode()'s .matrix
 * @returns {{ version: number, level: string, maskPattern: number, text: string }}
 */
export function qrDecode(matrix) {
  const size = matrix.length;
  const version = versionFromSize(size);
  const { level, maskPattern } = readFormatInfo(matrix);
  if (!level) throw new Error('Could not read valid format info from this matrix');

  const functionMask = buildFunctionMask(size, version);
  const bits = extractCodewordBits(matrix, functionMask, maskPattern);
  const allBytes = bitsToBytes(bits);

  const cap = QR_CAPACITY[version][level];
  const dataBytes = allBytes.slice(0, cap.dataCodewords);

  // Parse bitstream: 4-bit mode indicator, 8-bit char count (byte mode, v1-9), then byte data
  const dataBits = [];
  for (const byte of dataBytes) for (let i = 7; i >= 0; i--) dataBits.push((byte >> i) & 1);

  let pos = 0;
  const readBits = (n) => {
    let v = 0;
    for (let i = 0; i < n; i++) v = (v << 1) | dataBits[pos++];
    return v;
  };
  const mode = readBits(4);
  if (mode !== 0b0100) throw new Error('Only byte mode is supported by this decoder, found mode ' + mode.toString(2));
  const charCount = readBits(8);
  const msgBytes = new Uint8Array(charCount);
  for (let i = 0; i < charCount; i++) msgBytes[i] = readBits(8);

  return { version, level, maskPattern, text: new TextDecoder().decode(msgBytes) };
}
