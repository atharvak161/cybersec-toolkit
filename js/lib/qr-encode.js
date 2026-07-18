/**
 * QR Code encoder — hand-written, from the ISO/IEC 18004 public
 * specification (byte mode, versions 1-4, error correction levels L/M
 * only). This is a deliberately scoped-down implementation: full QR
 * (all 40 versions, all 4 EC levels, multi-block Reed-Solomon
 * interleaving, alphanumeric/kanji modes) is a large undertaking, and
 * this project's sandbox does not allow executing a third-party
 * reference decoder to cross-verify against, so scope was capped to
 * the range that could be implemented and self-verified with highest
 * confidence (versions 1-4 need only a SINGLE Reed-Solomon block each,
 * avoiding the more error-prone multi-block interleaving logic).
 * Round-trip verified against this project's own js/lib/qr-decode.js.
 *
 * Byte-mode capacity (this implementation): V1-L=17, V1-M=14, V2-L=32,
 * V2-M=26, V3-L=53, V3-M=42, V4-L=78, V4-M=62 bytes.
 */

// ---------- GF(256) arithmetic (primitive poly 0x11d, used by QR's Reed-Solomon) ----------

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(function initGF() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

/** Reed-Solomon generator polynomial of given degree (EC codeword count). */
function rsGeneratorPoly(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= gfMul(poly[j], 1);
      next[j + 1] ^= gfMul(poly[j], GF_EXP[i]);
    }
    poly = next;
  }
  return poly;
}

/** Compute Reed-Solomon EC codewords for a data codeword array. */
function rsComputeEcc(dataCodewords, eccCount) {
  const generator = rsGeneratorPoly(eccCount);
  const remainder = new Uint8Array(dataCodewords.length + eccCount);
  remainder.set(dataCodewords, 0);
  for (let i = 0; i < dataCodewords.length; i++) {
    const factor = remainder[i];
    if (factor === 0) continue;
    for (let j = 0; j < generator.length; j++) {
      remainder[i + j] ^= gfMul(generator[j], factor);
    }
  }
  return Array.from(remainder.slice(dataCodewords.length));
}

// ---------- Version capacity table (byte mode, single-block only: versions 1-4, L/M) ----------

export const QR_CAPACITY = {
  1: { L: { dataCodewords: 19, eccCodewords: 7 }, M: { dataCodewords: 16, eccCodewords: 10 } },
  2: { L: { dataCodewords: 34, eccCodewords: 10 }, M: { dataCodewords: 28, eccCodewords: 16 } },
  3: { L: { dataCodewords: 55, eccCodewords: 15 }, M: { dataCodewords: 44, eccCodewords: 26 } },
  4: { L: { dataCodewords: 80, eccCodewords: 20 }, M: { dataCodewords: 64, eccCodewords: 18 } }
};

export const ALIGNMENT_CENTER = { 1: null, 2: [18, 18], 3: [22, 22], 4: [26, 26] };

export const LEVEL_BITS = { L: 1, M: 0, Q: 3, H: 2 };
const G15 = 0x537;
const G15_MASK = 0x5412;

export function bchDigitCount(n) {
  let d = 0;
  while (n !== 0) {
    d++;
    n >>>= 1;
  }
  return d;
}

export function formatInfoBits(level, maskPattern) {
  const data = (LEVEL_BITS[level] << 3) | maskPattern;
  let d = data << 10;
  while (bchDigitCount(d) - bchDigitCount(G15) >= 0) {
    d ^= G15 << (bchDigitCount(d) - bchDigitCount(G15));
  }
  return ((data << 10) | d) ^ G15_MASK;
}

// ---------- Bitstream builder ----------

class BitWriter {
  constructor() {
    this.bits = [];
  }
  writeBits(value, length) {
    for (let i = length - 1; i >= 0; i--) this.bits.push((value >>> i) & 1);
  }
  toBytes() {
    while (this.bits.length % 8 !== 0) this.bits.push(0);
    const bytes = new Uint8Array(this.bits.length / 8);
    for (let i = 0; i < bytes.length; i++) {
      let b = 0;
      for (let j = 0; j < 8; j++) b = (b << 1) | this.bits[i * 8 + j];
      bytes[i] = b;
    }
    return bytes;
  }
}

function chooseVersion(byteLength, level) {
  for (let v = 1; v <= 4; v++) {
    const cap = QR_CAPACITY[v][level];
    if (!cap) continue;
    // 4 bits mode + 8 bits char count (versions 1-9) + 8*byteLength data, rounded to bytes
    const neededBits = 4 + 8 + byteLength * 8;
    if (Math.ceil(neededBits / 8) <= cap.dataCodewords) return v;
  }
  return null;
}

function buildDataCodewords(bytes, version, level) {
  const cap = QR_CAPACITY[version][level];
  const bw = new BitWriter();
  bw.writeBits(0b0100, 4); // byte mode indicator
  bw.writeBits(bytes.length, 8); // char count indicator (versions 1-9: 8 bits for byte mode)
  for (const b of bytes) bw.writeBits(b, 8);

  const capacityBits = cap.dataCodewords * 8;
  const terminatorLen = Math.min(4, capacityBits - bw.bits.length);
  if (terminatorLen > 0) bw.writeBits(0, terminatorLen);

  let dataBytes = Array.from(bw.toBytes());
  // Pad to byte boundary already done; now pad with alternating 0xEC/0x11 to fill capacity
  const padBytes = [0xec, 0x11];
  let padIdx = 0;
  while (dataBytes.length < cap.dataCodewords) {
    dataBytes.push(padBytes[padIdx % 2]);
    padIdx++;
  }
  return dataBytes.slice(0, cap.dataCodewords);
}

// ---------- Matrix construction ----------

export function createEmptyMatrix(size) {
  return Array.from({ length: size }, () => new Array(size).fill(null));
}

export function placeFinderPattern(matrix, row, col) {
  for (let dr = -1; dr <= 7; dr++) {
    for (let dc = -1; dc <= 7; dc++) {
      const r = row + dr;
      const c = col + dc;
      if (r < 0 || r >= matrix.length || c < 0 || c >= matrix.length) continue;
      if (dr < 0 || dr > 6 || dc < 0 || dc > 6) {
        matrix[r][c] = 0; // white separator border
      } else {
        const isBorder = dr === 0 || dr === 6 || dc === 0 || dc === 6;
        const isCenter = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
        matrix[r][c] = isBorder || isCenter ? 1 : 0;
      }
    }
  }
}

export function placeAlignmentPattern(matrix, centerRow, centerCol) {
  for (let dr = -2; dr <= 2; dr++) {
    for (let dc = -2; dc <= 2; dc++) {
      const r = centerRow + dr;
      const c = centerCol + dc;
      matrix[r][c] = Math.max(Math.abs(dr), Math.abs(dc)) !== 1 ? 1 : 0;
    }
  }
}

export function placeTimingPatterns(matrix) {
  const size = matrix.length;
  for (let i = 8; i < size - 8; i++) {
    if (matrix[6][i] === null) matrix[6][i] = i % 2 === 0 ? 1 : 0;
    if (matrix[i][6] === null) matrix[i][6] = i % 2 === 0 ? 1 : 0;
  }
}

export function applyMask(maskPattern, row, col) {
  switch (maskPattern) {
    case 0: return (row + col) % 2 === 0;
    case 1: return row % 2 === 0;
    case 2: return col % 3 === 0;
    case 3: return (row + col) % 3 === 0;
    case 4: return (Math.floor(row / 2) + Math.floor(col / 3)) % 2 === 0;
    case 5: return ((row * col) % 2) + ((row * col) % 3) === 0;
    case 6: return (((row * col) % 2) + ((row * col) % 3)) % 2 === 0;
    case 7: return (((row + col) % 2) + ((row * col) % 3)) % 2 === 0;
    default: return false;
  }
}

function placeDataBits(matrix, functionMask, allCodewords, maskPattern) {
  const size = matrix.length;
  const bits = [];
  for (const byte of allCodewords) {
    for (let i = 7; i >= 0; i--) bits.push((byte >> i) & 1);
  }

  let bitIndex = 0;
  let col = size - 1;
  let upward = true;

  while (col > 0) {
    if (col === 6) col--; // skip timing pattern column
    for (let i = 0; i < size; i++) {
      const row = upward ? size - 1 - i : i;
      for (const c of [col, col - 1]) {
        if (functionMask[row][c]) continue;
        let bit = bitIndex < bits.length ? bits[bitIndex] : 0;
        bitIndex++;
        if (applyMask(maskPattern, row, c)) bit ^= 1;
        matrix[row][c] = bit;
      }
    }
    upward = !upward;
    col -= 2;
  }
  return matrix;
}

function evaluatePenalty(matrix) {
  const size = matrix.length;
  let penalty = 0;

  // Rule 1: runs of 5+ same-color modules in a row/column
  const runPenalty = (getCell) => {
    let p = 0;
    for (let i = 0; i < size; i++) {
      let runLen = 1;
      let last = getCell(i, 0);
      for (let j = 1; j < size; j++) {
        const v = getCell(i, j);
        if (v === last) {
          runLen++;
        } else {
          if (runLen >= 5) p += 3 + (runLen - 5);
          runLen = 1;
          last = v;
        }
      }
      if (runLen >= 5) p += 3 + (runLen - 5);
    }
    return p;
  };
  penalty += runPenalty((i, j) => matrix[i][j]);
  penalty += runPenalty((i, j) => matrix[j][i]);

  // Rule 2: 2x2 blocks of same color
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = matrix[r][c];
      if (v === matrix[r][c + 1] && v === matrix[r + 1][c] && v === matrix[r + 1][c + 1]) {
        penalty += 3;
      }
    }
  }

  // Rule 3: finder-like pattern 1:1:3:1:1 (dark-light-dark-dark-dark-light-dark with 4 light either side)
  const pattern = [1, 0, 1, 1, 1, 0, 1];
  const matchesPattern = (arr, start) => {
    for (let k = 0; k < pattern.length; k++) if (arr[start + k] !== pattern[k]) return false;
    return true;
  };
  const checkLine = (getCell, fixed) => {
    const line = Array.from({ length: size }, (_, i) => getCell(fixed, i));
    let p = 0;
    for (let start = 0; start + 6 < size; start++) {
      if (matchesPattern(line, start)) {
        const before4 = line.slice(Math.max(0, start - 4), start).every((v) => v === 0);
        const after4 = line.slice(start + 7, start + 11).every((v) => v === 0);
        if (before4 || after4) p += 40;
      }
    }
    return p;
  };
  for (let i = 0; i < size; i++) {
    penalty += checkLine((r, c) => matrix[r][c], i);
    penalty += checkLine((r, c) => matrix[c][r], i);
  }

  // Rule 4: overall dark module ratio deviation from 50%
  let dark = 0;
  for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) if (matrix[r][c]) dark++;
  const percent = (dark * 100) / (size * size);
  const deviation = Math.floor(Math.abs(percent - 50) / 5);
  penalty += deviation * 10;

  return penalty;
}

/**
 * Encode text into a QR code matrix.
 * @param {string} text
 * @param {'L'|'M'} [level='M']
 * @returns {{ version: number, level: string, size: number, maskPattern: number, matrix: number[][] }}
 */
export function qrEncode(text, level = 'M') {
  if (level !== 'L' && level !== 'M') throw new Error('This encoder supports EC levels L and M only');
  const bytes = new TextEncoder().encode(text);
  const version = chooseVersion(bytes.length, level);
  if (!version) {
    const maxCap = QR_CAPACITY[4][level].dataCodewords - 3; // rough usable byte estimate
    throw new Error(`Input too long for this encoder (versions 1-4 only): max ~${maxCap} bytes at level ${level}`);
  }

  const dataCodewords = buildDataCodewords(bytes, version, level);
  const eccCodewords = rsComputeEcc(dataCodewords, QR_CAPACITY[version][level].eccCodewords);
  const allCodewords = dataCodewords.concat(eccCodewords);

  const size = 17 + 4 * version;
  const matrix = createEmptyMatrix(size);

  placeFinderPattern(matrix, 0, 0);
  placeFinderPattern(matrix, 0, size - 7);
  placeFinderPattern(matrix, size - 7, 0);

  const alignCenter = ALIGNMENT_CENTER[version];
  if (alignCenter) placeAlignmentPattern(matrix, alignCenter[0], alignCenter[1]);

  placeTimingPatterns(matrix);
  matrix[size - 8][8] = 1; // fixed dark module

  // Reserve format info areas with placeholder 0 (will overwrite with real bits after mask selection)
  for (let i = 0; i <= 8; i++) {
    if (matrix[8][i] === null) matrix[8][i] = 0;
    if (matrix[i][8] === null) matrix[i][8] = 0;
  }
  for (let i = 0; i < 8; i++) {
    if (matrix[8][size - 1 - i] === null) matrix[8][size - 1 - i] = 0;
    if (matrix[size - 1 - i][8] === null) matrix[size - 1 - i][8] = 0;
  }

  // Snapshot which cells are "function pattern" cells (not to be used for data)
  const functionMask = matrix.map((row) => row.map((v) => v !== null));

  let best = null;
  for (let maskPattern = 0; maskPattern < 8; maskPattern++) {
    const trial = matrix.map((row) => row.slice());
    placeDataBits(trial, functionMask, allCodewords, maskPattern);
    writeFormatInfo(trial, level, maskPattern);
    const penalty = evaluatePenalty(trial);
    if (!best || penalty < best.penalty) best = { matrix: trial, penalty, maskPattern };
  }

  return { version, level, size, maskPattern: best.maskPattern, matrix: best.matrix.map((row) => row.map((v) => v === 1)) };
}

function writeFormatInfo(matrix, level, maskPattern) {
  const size = matrix.length;
  const bits = formatInfoBits(level, maskPattern);
  const bit = (i) => (bits >> i) & 1;

  // Vertical strip (column 8), split around the top-left finder + timing row 6
  for (let i = 0; i <= 5; i++) matrix[i][8] = bit(i);
  matrix[7][8] = bit(6);
  matrix[8][8] = bit(7);
  for (let i = 8; i <= 14; i++) matrix[size - 15 + i][8] = bit(i);

  // Horizontal strip (row 8), split around the top-left finder + timing col 6
  for (let i = 0; i <= 7; i++) matrix[8][size - 1 - i] = bit(i);
  matrix[8][7] = bit(8);
  for (let i = 9; i <= 14; i++) matrix[8][15 - 1 - i] = bit(i);

  // Fixed dark module
  matrix[size - 8][8] = 1;
}
