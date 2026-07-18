/**
 * SHA-3 (Keccak) message digest — hand-implemented reference version 1.0.
 *
 * Source: FIPS 202 (SHA-3 Standard: Permutation-Based Hash and
 * Extendable-Output Functions), NIST, 2015.
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
 *
 * Provenance note: this file is NOT pulled from an external package/CDN.
 * It is a direct, from-spec implementation of the Keccak-f[1600]
 * permutation and the SHA3-224/256/384/512 sponge construction,
 * written for this project and validated against the official NIST
 * test vectors (empty string and "abc") in test/run-tests.js.
 *
 * ES module. Exposes sha3Hex(input, bits): string, where bits is one of
 * 224, 256, 384, 512.
 */

// Keccak round constants (24 rounds)
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
];

const MASK64 = (1n << 64n) - 1n;

function rotl64(x, n) {
  n = BigInt(n) % 64n;
  return ((x << n) | (x >> (64n - n))) & MASK64;
}

// Rotation offsets r[x][y], indexed as lane[x + 5*y]
const ROT = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14
];

function keccakF1600(state) {
  // state: BigUint64Array(25), lane[x + 5*y]
  for (let round = 0; round < 24; round++) {
    // Theta
    const C = new BigUint64Array(5);
    for (let x = 0; x < 5; x++) {
      C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    const D = new BigUint64Array(5);
    for (let x = 0; x < 5; x++) {
      D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1n);
    }
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        state[x + 5 * y] ^= D[x];
      }
    }

    // Rho + Pi
    const B = new BigUint64Array(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const newX = y;
        const newY = (2 * x + 3 * y) % 5;
        B[newX + 5 * newY] = rotl64(state[x + 5 * y], ROT[x + 5 * y]);
      }
    }

    // Chi
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        state[x + 5 * y] = B[x + 5 * y] ^ (~B[(x + 1) % 5 + 5 * y] & B[(x + 2) % 5 + 5 * y]);
      }
    }

    // Iota
    state[0] ^= RC[round];
  }
}

/**
 * Compute SHA3-{224,256,384,512} digest.
 * @param {string|Uint8Array} input
 * @param {number} bits one of 224, 256, 384, 512
 * @returns {string} lowercase hex digest
 */
export function sha3Hex(input, bits) {
  if (![224, 256, 384, 512].includes(bits)) {
    throw new Error('bits must be one of 224, 256, 384, 512');
  }
  const rateBytes = 200 - 2 * (bits / 8); // rate = 1600 - capacity(=2*bits) bits, in bytes
  const outputBytes = bits / 8;
  const msg = typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input);

  // Padding: SHA-3 domain separation byte 0x06, then pad10*1 to rate
  const padLen = rateBytes - (msg.length % rateBytes);
  const padded = new Uint8Array(msg.length + padLen);
  padded.set(msg, 0);
  padded[msg.length] = 0x06;
  padded[padded.length - 1] |= 0x80;

  const state = new BigUint64Array(25);

  // Absorb
  for (let offset = 0; offset < padded.length; offset += rateBytes) {
    for (let i = 0; i < rateBytes / 8; i++) {
      let lane = 0n;
      for (let b = 7; b >= 0; b--) {
        lane = (lane << 8n) | BigInt(padded[offset + i * 8 + b]);
      }
      state[i] ^= lane;
    }
    keccakF1600(state);
  }

  // Squeeze
  const out = new Uint8Array(outputBytes);
  let outPos = 0;
  while (outPos < outputBytes) {
    for (let i = 0; i < rateBytes / 8 && outPos < outputBytes; i++) {
      let lane = state[i];
      for (let b = 0; b < 8 && outPos < outputBytes; b++) {
        out[outPos++] = Number(lane & 0xffn);
        lane >>= 8n;
      }
    }
    if (outPos < outputBytes) keccakF1600(state);
  }

  let hex = '';
  for (let i = 0; i < out.length; i++) hex += out[i].toString(16).padStart(2, '0');
  return hex;
}
