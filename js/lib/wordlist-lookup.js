/**
 * EDUCATIONAL DEMO hash-vs-common-password lookup. NOT a real cracking
 * tool — see data/common-passwords.js for the 300-entry capped, clearly
 * labeled demo wordlist this uses. Hashes each candidate with the
 * chosen algorithm and compares against the target hash.
 */

import { COMMON_PASSWORDS_DEMO } from '../../data/common-passwords.js';
import { md5Hex, sha1Hex, sha256Hex, crc32Hex } from './hashing.js';

const ALGORITHMS = {
  MD5: (s) => Promise.resolve(md5Hex(s)),
  'SHA-1': (s) => Promise.resolve(sha1Hex(s)),
  'SHA-256': (s) => Promise.resolve(sha256Hex(s)),
  CRC32: (s) => Promise.resolve(crc32Hex(s))
};

export const SUPPORTED_ALGORITHMS = Object.keys(ALGORITHMS);

/**
 * Try to find a plaintext in the educational demo wordlist whose hash
 * (under the given algorithm) matches targetHash.
 * @param {string} targetHash
 * @param {'MD5'|'SHA-1'|'SHA-256'|'CRC32'} algorithm
 * @returns {Promise<{ found: boolean, plaintext: string|null, attempts: number }>}
 */
export async function lookupHashInDemoWordlist(targetHash, algorithm) {
  const hashFn = ALGORITHMS[algorithm];
  if (!hashFn) throw new Error('Unsupported algorithm for demo lookup: ' + algorithm);
  const normalizedTarget = targetHash.trim().toLowerCase();

  let attempts = 0;
  for (const candidate of COMMON_PASSWORDS_DEMO) {
    attempts++;
    const h = (await hashFn(candidate)).toLowerCase();
    if (h === normalizedTarget) {
      return { found: true, plaintext: candidate, attempts };
    }
  }
  return { found: false, plaintext: null, attempts };
}
