/**
 * Classical-cipher crackers: pure functions that, given ONLY ciphertext (no
 * key), return ranked/enumerated plaintext candidates. Companion to
 * encoding.js's caesarShift/rot13 (which apply a KNOWN transform) — these
 * functions search for the unknown key.
 *
 * Caesar shift convention: `shift` is the encryption key (the amount the
 * plaintext was shifted forward to produce the ciphertext) — the same
 * convention as the "Caesar cipher shift N" phrasing used in every classic
 * CTF/puzzle write-up. Decoding therefore shifts the ciphertext BACKWARD by
 * that same amount: caesarShift(ciphertext, -shift). Since caesarShift's
 * modulo arithmetic normalizes negative shifts, caesarShift(text, -shift)
 * is exactly caesarShift(text, 26 - shift).
 */

import { caesarShift } from './encoding.js';
import { scoreEnglish, ENGLISH_FREQ } from './english-fitness.js';

// ---------------------------------------------------------------------------
// Caesar
// ---------------------------------------------------------------------------

/**
 * Tries every possible Caesar key (0-25) and returns every candidate
 * plaintext. `shift` is the encryption key — see file header for the
 * convention. Callers rank/filter by whatever fitness measure they need
 * (see english-fitness.js for a ready-made one).
 * @param {string} text
 * @returns {Array<{shift:number, text:string}>}
 */
export function caesarCrackAll(text) {
  const results = [];
  for (let shift = 0; shift <= 25; shift++) {
    results.push({ shift, text: caesarShift(text, -shift) });
  }
  return results;
}

// ---------------------------------------------------------------------------
// Atbash
// ---------------------------------------------------------------------------

/**
 * Atbash cipher: A<->Z, B<->Y, ... a fixed-alphabet-reversal substitution
 * with no key. Its own inverse (an involution) — same function encrypts and
 * decrypts. Non-letters pass through unchanged.
 * @param {string} text
 * @returns {string}
 */
export function atbash(text) {
  return text.replace(/[a-zA-Z]/g, (ch) => {
    const isUpper = ch <= 'Z';
    const base = isUpper ? 65 : 97;
    const code = ch.charCodeAt(0) - base;
    return String.fromCharCode(base + (25 - code));
  });
}

// ---------------------------------------------------------------------------
// Single-byte XOR
// ---------------------------------------------------------------------------

function toByteArray(bytesOrString) {
  if (bytesOrString instanceof Uint8Array) return bytesOrString;
  if (Array.isArray(bytesOrString)) return Uint8Array.from(bytesOrString);
  const str = String(bytesOrString);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i) & 0xff;
  return bytes;
}

function bytesPrintableRatio(bytes) {
  if (bytes.length === 0) return 0;
  let printable = 0;
  for (const b of bytes) {
    if ((b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d) printable++;
  }
  return printable / bytes.length;
}

/**
 * Brute-forces every single-byte XOR key (0-255) against `bytesOrString`
 * (a Uint8Array, plain array of byte values, or a string treated as one
 * byte per character — i.e. Latin-1, NOT UTF-8, since ciphertext bytes are
 * arbitrary and not necessarily valid UTF-8 sequences). Only keys whose
 * output is overwhelmingly printable ASCII are returned — the rest are
 * near-certainly wrong keys producing binary noise, and including them would
 * flood the caller with garbage.
 * @param {Uint8Array|number[]|string} bytesOrString
 * @returns {Array<{key:number, text:string}>}
 */
export function xorSingleByteCrackAll(bytesOrString) {
  const bytes = toByteArray(bytesOrString);
  const results = [];
  for (let key = 0; key <= 255; key++) {
    const out = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ key;
    if (bytesPrintableRatio(out) < 0.85) continue;
    let text = '';
    for (const b of out) text += String.fromCharCode(b);
    results.push({ key, text });
  }
  return results;
}

// ---------------------------------------------------------------------------
// Rail fence
// ---------------------------------------------------------------------------

function railPattern(len, rails) {
  const pattern = new Array(len);
  let rail = 0;
  let dir = 1;
  for (let i = 0; i < len; i++) {
    pattern[i] = rail;
    if (rail === 0) dir = 1;
    else if (rail === rails - 1) dir = -1;
    rail += dir;
  }
  return pattern;
}

/**
 * Decrypts a rail-fence cipher with a KNOWN number of rails.
 * @param {string} text
 * @param {number} rails
 * @returns {string}
 */
export function railFenceDecrypt(text, rails) {
  if (rails < 2 || text.length === 0) return text;
  const len = text.length;
  const pattern = railPattern(len, rails);

  const counts = new Array(rails).fill(0);
  for (const r of pattern) counts[r]++;

  let idx = 0;
  const railChars = [];
  for (let r = 0; r < rails; r++) {
    railChars.push(text.slice(idx, idx + counts[r]).split(''));
    idx += counts[r];
  }

  const pos = new Array(rails).fill(0);
  let out = '';
  for (const r of pattern) out += railChars[r][pos[r]++];
  return out;
}

/**
 * Tries rail counts 2..min(10, length-1) and returns every candidate.
 * @param {string} text
 * @returns {Array<{rails:number, text:string}>}
 */
export function railFenceCrackAll(text) {
  const maxRails = Math.min(10, text.length - 1);
  const results = [];
  for (let rails = 2; rails <= maxRails; rails++) {
    results.push({ rails, text: railFenceDecrypt(text, rails) });
  }
  return results;
}

// ---------------------------------------------------------------------------
// Vigenere
// ---------------------------------------------------------------------------

/**
 * Decrypts Vigenere ciphertext with a KNOWN key. Non-letter characters pass
 * through unchanged and do not consume a key position (standard convention).
 * @param {string} text
 * @param {string} key
 * @returns {string}
 */
export function vigenereDecrypt(text, key) {
  const keyLetters = String(key).toUpperCase().replace(/[^A-Z]/g, '');
  if (!keyLetters) return text;
  let ki = 0;
  return text.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= 'Z' ? 65 : 97;
    const shift = keyLetters.charCodeAt(ki % keyLetters.length) - 65;
    ki++;
    const code = ((ch.charCodeAt(0) - base - shift) % 26 + 26) % 26;
    return String.fromCharCode(base + code);
  });
}

/**
 * Encrypts with a Vigenere key — the inverse of vigenereDecrypt, provided
 * for tests/tooling that need to construct a known ciphertext.
 * @param {string} text
 * @param {string} key
 * @returns {string}
 */
export function vigenereEncrypt(text, key) {
  const keyLetters = String(key).toUpperCase().replace(/[^A-Z]/g, '');
  if (!keyLetters) return text;
  let ki = 0;
  return text.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= 'Z' ? 65 : 97;
    const shift = keyLetters.charCodeAt(ki % keyLetters.length) - 65;
    ki++;
    const code = ((ch.charCodeAt(0) - base + shift) % 26 + 26) % 26;
    return String.fromCharCode(base + code);
  });
}

const MAX_VIGENERE_KEY_LENGTH = 16;

// Average Index of Coincidence, split into `keyLen` columns by position.
// The correct key length produces columns that are each a simple Caesar
// shift of English (IoC ~0.0667); wrong key lengths mix multiple alphabets
// per column and land closer to uniform-random (IoC ~0.0385).
function averageColumnIoC(letters, keyLen) {
  let total = 0;
  let counted = 0;
  for (let col = 0; col < keyLen; col++) {
    let colLetters = '';
    for (let i = col; i < letters.length; i += keyLen) colLetters += letters[i];
    if (colLetters.length < 2) continue;
    const counts = {};
    for (const ch of colLetters) counts[ch] = (counts[ch] || 0) + 1;
    let sum = 0;
    for (const ch in counts) sum += counts[ch] * (counts[ch] - 1);
    const n = colLetters.length;
    total += sum / (n * (n - 1));
    counted++;
  }
  return counted === 0 ? 0 : total / counted;
}

// Chi-squared ranking of all 26 possible shifts for one column, reusing the
// same standard-English frequency table english-fitness.js exposes (single
// source of truth for the reference distribution — no second copy of these
// numbers anywhere in the codebase). Returns shifts best-first (lowest chi
// first), not just the single winner — the refinement step below needs a
// short list of statistically-plausible alternatives per column, not just
// one candidate, to safely correct the occasional wrong pick without
// degenerating into an unconstrained free search.
function rankShiftsForColumn(colLetters, englishFreq) {
  const n = colLetters.length;
  if (n === 0) return [0];
  const counts = new Array(26).fill(0);
  for (const ch of colLetters) counts[ch.charCodeAt(0) - 65]++;

  const scored = [];
  for (let shift = 0; shift < 26; shift++) {
    let chi = 0;
    for (let letterIdx = 0; letterIdx < 26; letterIdx++) {
      // If the column plaintext letter is P, ciphertext letter is (P+shift).
      // observed[cipherIdx] should match englishFreq[plainIdx] once shifted
      // back, so compare counts[(letterIdx+shift)%26] against englishFreq[letterIdx].
      const cipherIdx = (letterIdx + shift) % 26;
      const expected = englishFreq[String.fromCharCode(65 + letterIdx)] * n;
      const observed = counts[cipherIdx];
      chi += ((observed - expected) ** 2) / (expected || 1e-6);
    }
    scored.push({ shift, chi });
  }
  scored.sort((a, b) => a.chi - b.chi);
  return scored.map((s) => s.shift);
}

// Local refinement: independent per-column chi-squared (above) is the
// standard first pass, but on short ciphertext each column only has a
// handful of letters to work with — not enough samples for fully reliable
// frequency analysis — and can leave the greedy (rank-1-per-column) key one
// or two letters off (a real, well-known limitation of column-independent
// Vigenere analysis, not a bug).
//
// This step searches a bounded NEIGHBORHOOD of the greedy key: the greedy
// key itself, plus one variant for every (position, alternative-shift) pair
// drawn from that position's own top-`shortlist.length` chi-squared-
// plausible shifts, changing exactly ONE position at a time. It picks
// whichever single-swap variant (or the unmodified base) scores best on the
// FULL decrypted text via scoreEnglish — the whole-text signal (cross-
// column bigram/trigram structure) that per-column chi-squared cannot see.
//
// Deliberately NOT iterative coordinate-ascent (try-and-keep repeated over
// several sweeps): that compounds — each accepted single-position swap
// changes the "current best" that the NEXT position's swap is judged
// against, so a few rounds of small, individually-plausible improvements can
// drift the combined key several positions away from the greedy answer into
// a combination that was never actually evaluated as a whole against the
// alternative — and on a short sample, scoreEnglish's noisier sub-signals
// (trigram density especially, having only a couple dozen samples) can
// reward that drift with a fluke high score for a wrong key. Evaluating
// single-swap variants against the ORIGINAL greedy base only, all in one
// flat pass, removes that compounding path entirely while still catching
// the common "one column's argmin chi shift was wrong" case.
function refineKeyByNeighborhoodSearch(text, greedyKey, shiftShortlists) {
  let bestKey = greedyKey;
  let bestScore = scoreEnglish(vigenereDecrypt(text, greedyKey));

  for (let pos = 0; pos < greedyKey.length; pos++) {
    for (const shift of shiftShortlists[pos]) {
      const candidateLetter = String.fromCharCode(65 + shift);
      if (candidateLetter === greedyKey[pos]) continue;
      const candidateKey = greedyKey.slice(0, pos) + candidateLetter + greedyKey.slice(pos + 1);
      const candidateScore = scoreEnglish(vigenereDecrypt(text, candidateKey));
      if (candidateScore > bestScore) {
        bestScore = candidateScore;
        bestKey = candidateKey;
      }
    }
  }
  return { key: bestKey, score: bestScore };
}

/**
 * Cracks Vigenere ciphertext with NO known key: estimates the key length via
 * average Index of Coincidence across candidate column splits (1..16), then
 * for the best few candidate lengths recovers each column's shift via
 * chi-squared frequency analysis, assembles the key, decrypts, and scores
 * the result with scoreEnglish. Returns candidates ranked by score,
 * descending.
 * @param {string} text
 * @param {object} [options]
 * @param {number} [options.maxKeyLength=16]
 * @param {number} [options.topLengths=3] - how many key-length hypotheses to fully explore
 * @returns {Array<{key:string, text:string, score:number}>}
 */
export function vigenereCrack(text, options = {}) {
  const maxKeyLength = Math.min(options.maxKeyLength || MAX_VIGENERE_KEY_LENGTH, MAX_VIGENERE_KEY_LENGTH);
  const topLengths = options.topLengths || 3;

  const letters = text.toUpperCase().replace(/[^A-Z]/g, '');
  if (letters.length < 8) return [];

  const icByLength = [];
  const maxLen = Math.min(maxKeyLength, Math.floor(letters.length / 2));
  for (let keyLen = 1; keyLen <= Math.max(1, maxLen); keyLen++) {
    // Data-sufficiency guard: a column needs several letters before its
    // frequency profile carries any real signal. Below 4 letters/column,
    // IoC and chi-squared are both essentially noise, and — worse — the
    // refinement step below has enough free parameters relative to the
    // data to hill-climb its way to a fluke high-scoring wrong key. Simplest
    // fix: never treat an under-sampled length as a candidate at all.
    if (Math.floor(letters.length / keyLen) < 4) continue;
    icByLength.push({ keyLen, ic: averageColumnIoC(letters, keyLen) });
  }
  if (icByLength.length === 0) return [];
  // Closest-to-English-IoC first; ties broken toward the shorter key
  // (Occam's razor — a length-2 key that fits the data is a better
  // explanation than an incidental length-14 fit of the same data).
  icByLength.sort((a, b) => Math.abs(a.ic - 0.0667) - Math.abs(b.ic - 0.0667) || a.keyLen - b.keyLen);

  const candidateLengths = icByLength.slice(0, topLengths).map((c) => c.keyLen);

  const results = [];
  const seenKeys = new Set();

  for (const keyLen of candidateLengths) {
    let key = '';
    const shiftShortlists = [];
    for (let col = 0; col < keyLen; col++) {
      let colLetters = '';
      for (let i = col; i < letters.length; i += keyLen) colLetters += letters[i];
      const ranked = rankShiftsForColumn(colLetters, ENGLISH_FREQ);
      shiftShortlists.push(ranked.slice(0, 4)); // top-4 chi-squared-plausible shifts
      key += String.fromCharCode(65 + ranked[0]);
    }
    const refined = refineKeyByNeighborhoodSearch(text, key, shiftShortlists);
    if (seenKeys.has(refined.key)) continue;
    seenKeys.add(refined.key);

    results.push({ key: refined.key, text: vigenereDecrypt(text, refined.key), score: refined.score });
  }

  results.sort((a, b) => b.score - a.score);
  return results;
}

// ---------------------------------------------------------------------------
// Combined cracker — tries every classical cipher above and ranks the pooled
// results. Used by the standalone Cipher Cracker tool, where a human reviews
// several ranked candidates (unlike the fully-automatic Magic Wand, this is
// NOT trying to pick one "the answer" — see auto-decode.js's own doc
// comments on why Vigenere in particular is not safe to fully automate).
// ---------------------------------------------------------------------------

/**
 * Runs Caesar, Atbash, single-byte XOR, rail-fence, and Vigenere against the
 * same ciphertext, scores every resulting candidate with scoreEnglish, and
 * returns the top `maxResults` (default 8), deduplicated by output text and
 * excluding any candidate identical to the input (a no-op, not a decode).
 * @param {string} text
 * @param {object} [options]
 * @param {number} [options.maxResults=8]
 * @returns {Array<{cipher:string, key:string, text:string, score:number}>}
 */
export function crackAllCiphers(text, options = {}) {
  const maxResults = Number.isInteger(options.maxResults) ? options.maxResults : 8;

  const pool = [];
  for (const c of caesarCrackAll(text)) {
    pool.push({ cipher: 'Caesar', key: `shift ${c.shift}`, text: c.text });
  }
  pool.push({ cipher: 'Atbash', key: 'n/a (no key)', text: atbash(text) });
  for (const c of railFenceCrackAll(text)) {
    pool.push({ cipher: 'Rail Fence', key: `${c.rails} rails`, text: c.text });
  }
  for (const c of xorSingleByteCrackAll(text)) {
    pool.push({ cipher: 'XOR (single-byte)', key: `0x${c.key.toString(16).padStart(2, '0')}`, text: c.text });
  }
  for (const c of vigenereCrack(text)) {
    pool.push({ cipher: 'Vigenere', key: c.key, text: c.text });
  }

  const seen = new Set();
  const scored = [];
  for (const cand of pool) {
    if (cand.text === text) continue; // no-op, not a decode
    if (seen.has(cand.text)) continue;
    seen.add(cand.text);
    scored.push({ ...cand, score: scoreEnglish(cand.text) });
  }

  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, maxResults);
}
