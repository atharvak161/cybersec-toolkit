/**
 * MD5 message digest — hand-implemented reference version 1.0.
 *
 * Source: RFC 1321 (The MD5 Message-Digest Algorithm), R. Rivest, 1992.
 * https://www.rfc-editor.org/rfc/rfc1321
 *
 * Provenance note: this file is NOT pulled from an external package/CDN.
 * It is a direct, from-spec implementation of the public RFC 1321
 * algorithm, written for this project and validated against the
 * standard RFC 1321 test vectors in test/run-tests.js (empty string,
 * "abc", "abcdefghijklmnopqrstuvwxyz", etc.).
 *
 * MD5 is cryptographically broken (collision attacks) — it is provided
 * here strictly as a legacy/checksum digest for the toolkit's hashing
 * and identification tools, never for anything security-sensitive.
 * Security-sensitive crypto (AES/RSA) in this toolkit always uses the
 * browser-native Web Crypto API — see js/lib/aes.js and js/lib/rsa.js.
 *
 * ES module. Exposes md5Hex(input: string | Uint8Array): string
 */

function toUtf8Bytes(str) {
  return new TextEncoder().encode(str);
}

function rotl(x, c) {
  return (x << c) | (x >>> (32 - c));
}

// Per-round shift amounts
const S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
];

// Precomputed K[i] = floor(abs(sin(i+1)) * 2^32), i = 0..63
const K = new Uint32Array([
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]);

function md5Bytes(msgBytes) {
  const origLenBits = msgBytes.length * 8;

  // Padding: append 0x80, then zeros until length % 64 == 56, then 8 bytes little-endian bit length
  let padLen = (56 - (msgBytes.length + 1) % 64 + 64) % 64;
  const total = msgBytes.length + 1 + padLen + 8;
  const buf = new Uint8Array(total);
  buf.set(msgBytes, 0);
  buf[msgBytes.length] = 0x80;
  // bit length as 64-bit little endian (we only use low 53 bits realistically)
  const lo = origLenBits >>> 0;
  const hi = Math.floor(origLenBits / 0x100000000) >>> 0;
  const dv = new DataView(buf.buffer);
  dv.setUint32(total - 8, lo, true);
  dv.setUint32(total - 4, hi, true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

  for (let chunkStart = 0; chunkStart < total; chunkStart += 64) {
    const M = new Uint32Array(16);
    for (let i = 0; i < 16; i++) {
      M[i] = dv.getUint32(chunkStart + i * 4, true);
    }

    let A = a0, B = b0, C = c0, D = d0;

    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) {
        F = (B & C) | (~B & D);
        g = i;
      } else if (i < 32) {
        F = (D & B) | (~D & C);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) % 16;
      }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D;
      D = C;
      C = B;
      B = (B + rotl(F, S[i])) >>> 0;
    }

    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }

  const out = new Uint8Array(16);
  const outDv = new DataView(out.buffer);
  outDv.setUint32(0, a0, true);
  outDv.setUint32(4, b0, true);
  outDv.setUint32(8, c0, true);
  outDv.setUint32(12, d0, true);
  return out;
}

function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Compute the MD5 hex digest of a string or byte array.
 * @param {string|Uint8Array} input
 * @returns {string} lowercase hex digest
 */
export function md5Hex(input) {
  const bytes = typeof input === 'string' ? toUtf8Bytes(input) : new Uint8Array(input);
  return bytesToHex(md5Bytes(bytes));
}
