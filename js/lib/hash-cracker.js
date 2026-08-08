/**
 * Offline hash cracker — a real client-side dictionary + rules attack, in the
 * spirit of CrackStation / Hashes.com but honest about the tradeoff: those
 * services reverse-look-up against multi-billion-entry server-side tables
 * (hundreds of GB). A static, in-browser tool can't ship that, so this instead
 * cracks the *common/weak* hashes that make up most real-world cracks — by
 * hashing every entry in the bundled wordlist plus common mangling rules
 * (case changes, leetspeak, appended digits/years/symbols) and matching.
 *
 * Nothing leaves the browser. Supports MD5, SHA-1, SHA-256, SHA-512, detected
 * automatically from the hash length. Salted or modern KDF hashes (bcrypt,
 * argon2, PBKDF2) are out of scope and reported as such.
 */
import { md5Hex, sha1Hex, sha256Hex, sha512Hex } from './hashing.js';
import { EFF_LARGE_WORDLIST } from '../../data/eff-large-wordlist.js';
import { COMMON_PASSWORDS_DEMO } from '../../data/common-passwords.js';

export const HASH_TYPES = {
  32: { name: 'MD5', hex: md5Hex, sync: true },
  40: { name: 'SHA-1', hex: sha1Hex, sync: false },
  64: { name: 'SHA-256', hex: sha256Hex, sync: false },
  128: { name: 'SHA-512', hex: sha512Hex, sync: false }
};

/** Detect the likely hash algorithm from a hex string's length. Pure. */
export function detectHashType(hash) {
  const h = (hash || '').trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(h)) return null;
  const t = HASH_TYPES[h.length];
  return t ? { length: h.length, name: t.name } : null;
}

const LEET = (w) => w.replace(/a/gi, '4').replace(/e/gi, '3').replace(/i/gi, '1').replace(/o/gi, '0').replace(/s/gi, '5');
const SUFFIXES = ['', '1', '2', '12', '123', '1234', '!', '!!', '123!', '2023', '2024', '2025', '01', '00', '007', '69', '007', '321'];

/**
 * Lazily generates candidate plaintexts from the bundled wordlists plus rules.
 * Yields strings; dedup is the caller's job (via the Map it builds). Kept as a
 * generator so a found-early crack doesn't pay for the whole space.
 */
export function* candidates() {
  const base = new Set([...COMMON_PASSWORDS_DEMO, ...EFF_LARGE_WORDLIST]);
  for (const w of base) {
    if (!w) continue;
    const forms = new Set([w, w.toLowerCase(), w.toUpperCase(), w[0].toUpperCase() + w.slice(1), LEET(w)]);
    for (const f of forms) {
      for (const sfx of SUFFIXES) yield f + sfx;
    }
  }
}

/** Rough size of the candidate space, for honest "tried N of ~M" messaging. */
export function candidateSpaceEstimate() {
  const base = new Set([...COMMON_PASSWORDS_DEMO, ...EFF_LARGE_WORDLIST]).size;
  return base * 5 * SUFFIXES.length; // upper bound before dedup
}

/**
 * Crack one or more hashes of the SAME detected type in a single pass over the
 * candidate space (so N hashes cost ~1 scan, not N). Async because SHA uses
 * Web Crypto. `onProgress(done, total)` is optional.
 *
 * Returns: { type, results: [{ hash, plaintext|null }], tried }
 */
export async function crackHashes(hashes, { onProgress, algorithm } = {}) {
  const norm = [...new Set(hashes.map((h) => (h || '').trim().toLowerCase()).filter(Boolean))];
  if (!norm.length) throw new Error('Enter at least one hash.');

  // All must be the same length/type for a single pass; pick from the first
  // (or an explicit override).
  const len = algorithm
    ? Number(Object.keys(HASH_TYPES).find((k) => HASH_TYPES[k].name === algorithm))
    : norm[0].length;
  const type = HASH_TYPES[len];
  if (!type) {
    throw new Error('Unrecognized hash length. This cracker handles MD5, SHA-1, SHA-256, and SHA-512 (unsalted).');
  }
  for (const h of norm) {
    if (!/^[0-9a-f]+$/.test(h)) throw new Error(`"${h}" is not a valid hex hash.`);
    if (h.length !== len) throw new Error('Crack one hash type at a time — mixed lengths detected.');
  }

  const targets = new Set(norm);
  const found = new Map();
  let tried = 0;
  const CHUNK = 1000;

  if (type.sync) {
    for (const cand of candidates()) {
      const h = type.hex(cand);
      if (targets.has(h) && !found.has(h)) {
        found.set(h, cand);
        if (found.size === targets.size) break;
      }
      if (++tried % 20000 === 0 && onProgress) onProgress(tried, candidateSpaceEstimate());
    }
  } else {
    // Async (SHA*): hash in batches with Promise.all to stay responsive.
    let batch = [];
    const flush = async () => {
      const hs = await Promise.all(batch.map((c) => type.hex(c)));
      for (let i = 0; i < hs.length; i++) {
        if (targets.has(hs[i]) && !found.has(hs[i])) found.set(hs[i], batch[i]);
      }
      tried += batch.length;
      batch = [];
      if (onProgress) onProgress(tried, candidateSpaceEstimate());
    };
    for (const cand of candidates()) {
      batch.push(cand);
      if (batch.length >= CHUNK) { await flush(); if (found.size === targets.size) return finalize(); }
    }
    if (batch.length) await flush();
  }

  function finalize() {
    return {
      type: type.name,
      tried,
      results: norm.map((h) => ({ hash: h, plaintext: found.has(h) ? found.get(h) : null }))
    };
  }
  return finalize();
}
