/**
 * Offline hash cracker — a real client-side dictionary + rules attack, in the
 * spirit of CrackStation / Hashes.com but honest about the tradeoff: those
 * services reverse-look-up against multi-billion-entry server-side tables
 * (hundreds of GB). A static, in-browser tool can't ship that, so this instead
 * runs two tiers:
 *
 *   1. Quick tier (this file's bundled 300 curated common passwords + the
 *      7,776-word EFF diceware list) — instant, no network fetch, good for
 *      the truly common/weak cases. See candidates()/crackHashes().
 *   2. Big tier — the 100,000-entry SecLists breached-password corpus
 *      (data/seclists-top100k.txt, real leaked passwords ranked by
 *      frequency; MIT, see data/SECLISTS-NOTICE.txt), fetched lazily by
 *      js/lib/seclists-wordlist.js only when a crack actually runs. See
 *      candidatesFromWords()/crackHashesFromWordlist().
 *
 * Both tiers apply the same mangling rules (case changes, leetspeak,
 * appended digits/years/symbols) via the shared mangle() generator, so a
 * hash doesn't need to match a wordlist entry verbatim.
 *
 * Nothing leaves the browser. Supports MD5, SHA-1, SHA-256, SHA-512, detected
 * automatically from the hash length. Salted or modern KDF hashes (bcrypt,
 * argon2, PBKDF2) are out of scope and reported as such.
 *
 * The UI (js/ui/hashing-tools.js) runs both tiers inside a Web Worker
 * (js/lib/hash-cracker-worker.js) so the candidate-space scan — which at the
 * big tier's ~100k words x ~90 rule variants is multiple million hashes —
 * never blocks the tab. The functions in this file are the pure algorithm;
 * they know nothing about Workers and are exercised directly (fast, on the
 * quick tier / small fixture word lists) by the test suite.
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
/** Forms-per-word x suffixes — the one place this multiplier is defined. */
const FORMS_PER_WORD = 5;

/**
 * Shared rules engine: lazily yields every case/leetspeak/suffix variant of
 * every word in `words`. Both the quick tier and the big (SecLists) tier
 * generate candidates through this single function, so a rule change or fix
 * only has to happen once.
 */
export function* mangle(words) {
  for (const w of words) {
    if (!w) continue;
    const forms = new Set([w, w.toLowerCase(), w.toUpperCase(), w[0].toUpperCase() + w.slice(1), LEET(w)]);
    for (const f of forms) {
      for (const sfx of SUFFIXES) yield f + sfx;
    }
  }
}

/**
 * Lazily generates candidate plaintexts from the bundled QUICK wordlists
 * (300 curated + 7,776 diceware) plus rules. Yields strings; dedup is the
 * caller's job (via the Map it builds). Generator so a found-early crack
 * doesn't pay for the whole space.
 */
export function* candidates() {
  yield* mangle(new Set([...COMMON_PASSWORDS_DEMO, ...EFF_LARGE_WORDLIST]));
}

/** Rough size of the quick-tier candidate space, for "tried N of ~M" messaging. */
export function candidateSpaceEstimate() {
  const base = new Set([...COMMON_PASSWORDS_DEMO, ...EFF_LARGE_WORDLIST]).size;
  return base * FORMS_PER_WORD * SUFFIXES.length; // upper bound before dedup
}

/**
 * Lazily generates candidates from an arbitrary word list (the big SecLists
 * tier, or any future/swapped-in list) plus the same rules as the quick
 * tier. Kept independent of *where* `words` came from — the caller (the
 * Worker, or a test's fixture array) owns loading it.
 */
export function* candidatesFromWords(words) {
  yield* mangle(words);
}

/** Rough size of the candidate space for an arbitrary word list. */
export function candidateSpaceEstimateFor(words) {
  return new Set(words).size * FORMS_PER_WORD * SUFFIXES.length;
}

function normalizeHashes(hashes, algorithm) {
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
  return { norm, type };
}

/**
 * Core scan: hash every candidate from `genCandidates()` against `norm`,
 * stopping early once every target is found. Shared by both public crack
 * functions below so the sync/async/batching/early-exit logic exists once.
 */
async function scanCandidates(norm, type, genCandidates, totalEstimate, onProgress) {
  const targets = new Set(norm);
  const found = new Map();
  let tried = 0;
  const CHUNK = 1000;

  if (type.sync) {
    for (const cand of genCandidates()) {
      const h = type.hex(cand);
      if (targets.has(h) && !found.has(h)) {
        found.set(h, cand);
        if (found.size === targets.size) break;
      }
      if (++tried % 20000 === 0 && onProgress) onProgress(tried, totalEstimate);
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
      if (onProgress) onProgress(tried, totalEstimate);
    };
    for (const cand of genCandidates()) {
      batch.push(cand);
      if (batch.length >= CHUNK) { await flush(); if (found.size === targets.size) break; }
    }
    if (batch.length && found.size < targets.size) await flush();
  }

  return {
    tried,
    results: norm.map((h) => ({ hash: h, plaintext: found.has(h) ? found.get(h) : null }))
  };
}

/**
 * Crack one or more hashes of the SAME detected type against the QUICK tier
 * (bundled 300 + diceware) in a single pass over the candidate space (so N
 * hashes cost ~1 scan, not N). Async because SHA uses Web Crypto.
 * `onProgress(done, total)` is optional.
 *
 * Returns: { type, results: [{ hash, plaintext|null }], tried }
 */
export async function crackHashes(hashes, { onProgress, algorithm } = {}) {
  const { norm, type } = normalizeHashes(hashes, algorithm);
  const { tried, results } = await scanCandidates(norm, type, candidates, candidateSpaceEstimate(), onProgress);
  return { type: type.name, tried, results };
}

/**
 * Crack one or more hashes against an arbitrary WORD LIST (the big SecLists
 * tier in production; a small fixture array in tests). Same semantics as
 * crackHashes() otherwise — same rules, same early-exit, same shape.
 *
 * `words` is provided by the caller so this function has no I/O of its own:
 * the browser UI loads it via js/lib/seclists-wordlist.js (lazily, only when
 * a crack runs), and tests pass a plain array — no fetch, no network, fast.
 *
 * Returns: { type, results: [{ hash, plaintext|null }], tried }
 */
export async function crackHashesFromWordlist(hashes, words, { onProgress, algorithm } = {}) {
  const { norm, type } = normalizeHashes(hashes, algorithm);
  const gen = () => candidatesFromWords(words);
  const { tried, results } = await scanCandidates(norm, type, gen, candidateSpaceEstimateFor(words), onProgress);
  return { type: type.name, tried, results };
}
