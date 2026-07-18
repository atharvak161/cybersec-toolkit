/**
 * Hashing tools: SHA-1/256/384/512 and HMAC via the native Web Crypto API
 * (crypto.subtle — available identically in browsers and in Node 19+ as
 * globalThis.crypto.subtle, so these functions work unmodified in both
 * the browser UI and this project's Node test suite).
 *
 * MD5, SHA-3 and CRC32 are not supported by Web Crypto, so they are
 * provided by the hand-written reference implementations in
 * js/lib/vendor/ (see those files for algorithm sources/citations).
 */

import { md5Hex } from './vendor/md5.js';
import { sha3Hex } from './vendor/sha3.js';
import { crc32Hex } from './vendor/crc32.js';

function getSubtle() {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) throw new Error('Web Crypto API (crypto.subtle) is not available in this environment');
  return subtle;
}

function toBytes(input) {
  return typeof input === 'string' ? new TextEncoder().encode(input) : new Uint8Array(input);
}

function bufToHex(buf) {
  const bytes = new Uint8Array(buf);
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

const WEBCRYPTO_ALGOS = {
  'SHA-1': 'SHA-1',
  'SHA-256': 'SHA-256',
  'SHA-384': 'SHA-384',
  'SHA-512': 'SHA-512'
};

/** Async: SHA-1/256/384/512 via Web Crypto. */
export async function webCryptoDigestHex(algo, input) {
  const name = WEBCRYPTO_ALGOS[algo];
  if (!name) throw new Error('Unsupported Web Crypto digest: ' + algo);
  const digest = await getSubtle().digest(name, toBytes(input));
  return bufToHex(digest);
}

export const sha1Hex = (input) => webCryptoDigestHex('SHA-1', input);
export const sha256Hex = (input) => webCryptoDigestHex('SHA-256', input);
export const sha384Hex = (input) => webCryptoDigestHex('SHA-384', input);
export const sha512Hex = (input) => webCryptoDigestHex('SHA-512', input);

export { md5Hex, crc32Hex };
export const sha3_224Hex = (input) => sha3Hex(input, 224);
export const sha3_256Hex = (input) => sha3Hex(input, 256);
export const sha3_384Hex = (input) => sha3Hex(input, 384);
export const sha3_512Hex = (input) => sha3Hex(input, 512);

/** Async: HMAC-SHA{1,256,384,512} via Web Crypto. Returns hex. */
export async function hmacHex(algo, keyStr, message) {
  const name = WEBCRYPTO_ALGOS[algo];
  if (!name) throw new Error('Unsupported HMAC digest: ' + algo);
  const key = await getSubtle().importKey(
    'raw',
    toBytes(keyStr),
    { name: 'HMAC', hash: name },
    false,
    ['sign']
  );
  const sig = await getSubtle().sign('HMAC', key, toBytes(message));
  return bufToHex(sig);
}

/**
 * Hash-type identifier: guesses likely algorithm(s) from the length and
 * charset of a pasted hash string. Heuristic only — many algorithms
 * share output lengths (e.g. MD5 and MD4 and NTLM are all 32 hex chars),
 * so multiple candidates may be returned, ranked by commonness.
 */
const HASH_LENGTH_MAP = [
  { hexLen: 8, candidates: ['CRC32', 'Adler32'] },
  { hexLen: 32, candidates: ['MD5', 'MD4', 'NTLM', 'MD2'] },
  { hexLen: 40, candidates: ['SHA-1', 'RIPEMD-160'] },
  { hexLen: 56, candidates: ['SHA-224', 'SHA3-224'] },
  { hexLen: 64, candidates: ['SHA-256', 'SHA3-256', 'BLAKE2s'] },
  { hexLen: 96, candidates: ['SHA-384', 'SHA3-384'] },
  { hexLen: 128, candidates: ['SHA-512', 'SHA3-512', 'BLAKE2b'] }
];

export function identifyHash(hash) {
  const clean = hash.trim();
  const results = [];

  if (/^\$2[aby]?\$\d+\$/.test(clean)) {
    return [{ algorithm: 'bcrypt', confidence: 'high' }];
  }
  if (/^\$argon2(i|d|id)\$/.test(clean)) {
    return [{ algorithm: 'Argon2', confidence: 'high' }];
  }
  if (/^\$1\$/.test(clean)) return [{ algorithm: 'MD5-crypt', confidence: 'high' }];
  if (/^\$6\$/.test(clean)) return [{ algorithm: 'SHA512-crypt', confidence: 'high' }];
  if (/^\$5\$/.test(clean)) return [{ algorithm: 'SHA256-crypt', confidence: 'high' }];

  if (!/^[0-9a-fA-F]+$/.test(clean)) {
    // Not pure hex — could be base64 (e.g. some hash export formats)
    if (/^[A-Za-z0-9+/]+=*$/.test(clean)) {
      results.push({ algorithm: 'Unknown (base64-encoded digest)', confidence: 'low' });
    }
    return results.length ? results : [{ algorithm: 'Unrecognized format', confidence: 'none' }];
  }

  const entry = HASH_LENGTH_MAP.find((e) => e.hexLen === clean.length);
  if (entry) {
    entry.candidates.forEach((c, idx) =>
      results.push({ algorithm: c, confidence: idx === 0 ? 'medium' : 'low' })
    );
  } else {
    results.push({ algorithm: `Unknown (${clean.length} hex chars)`, confidence: 'none' });
  }
  return results;
}
