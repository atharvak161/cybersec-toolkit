/**
 * Compact, dependency-free English-likelihood scorer for SPACELESS,
 * uppercase-or-any-case text — the exact shape classical-cipher plaintext
 * comes in (Caesar/Vigenere/Atbash/rail-fence output has no word breaks).
 *
 * Deliberately does NOT vendor a quadgram corpus (that's megabytes of data
 * for a client-side, no-build-step toolkit). Instead this is a composite of
 * four classical, well-understood cryptanalysis signals that together are
 * highly discriminative on their own:
 *   1. Chi-squared distance of letter frequencies vs standard English —
 *      the same statistic used to crack Caesar/Vigenere ciphers by hand.
 *   2. Common-bigram / common-trigram density — the ~40 bigrams and ~30
 *      trigrams below cover a large fraction of all digraph/trigraph
 *      occurrences in real English regardless of word boundaries.
 *   3. Index of Coincidence — English text clusters near ~0.0667; uniform
 *      random letters cluster near 1/26 ~= 0.0385.
 *   4. Vowel ratio sanity check — English is ~38-40% vowels; degenerate
 *      inputs (all-consonant, all-vowel) are penalized.
 *
 * Every helper here is pure and independently unit-tested.
 */

// Standard English single-letter frequencies (fractions, sum to 1).
// Source: classical cryptanalysis reference tables (e.g. Cornell CS/Simon
// Singh's "The Code Book" tables) — the same numbers used by every textbook
// Caesar/Vigenere chi-squared cracker.
export const ENGLISH_FREQ = {
  A: 0.08167, B: 0.01492, C: 0.02782, D: 0.04253, E: 0.12702, F: 0.02228,
  G: 0.02015, H: 0.06094, I: 0.06966, J: 0.00153, K: 0.00772, L: 0.04025,
  M: 0.02406, N: 0.06749, O: 0.07507, P: 0.01929, Q: 0.00095, R: 0.05987,
  S: 0.06327, T: 0.09056, U: 0.02758, V: 0.00978, W: 0.02360, X: 0.00150,
  Y: 0.01974, Z: 0.00074
};

const COMMON_BIGRAMS = new Set([
  'TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT', 'EN', 'ND', 'TI', 'ES',
  'OR', 'TE', 'OF', 'ED', 'IS', 'IT', 'AL', 'AR', 'ST', 'TO', 'NT', 'NG',
  'SE', 'HA', 'AS', 'OU', 'IO', 'LE', 'VE', 'CO', 'ME', 'DE', 'HI', 'RI',
  'RO', 'IC', 'NE', 'EA', 'RA', 'CE', 'LI', 'CH', 'LL', 'BE', 'MA', 'SI',
  'OM', 'UR'
]);

const COMMON_TRIGRAMS = new Set([
  'THE', 'AND', 'ING', 'ENT', 'ION', 'HER', 'FOR', 'THA', 'NTH', 'INT',
  'ERE', 'TIO', 'TER', 'EST', 'ERS', 'ATI', 'HAT', 'ATE', 'ALL', 'ETH',
  'HES', 'VER', 'HIS', 'OFT', 'ITH', 'FTH', 'STH', 'OTH', 'RES', 'ONT'
]);

/** Extracts only the alphabetic characters, upper-cased. */
export function lettersOnly(text) {
  return String(text == null ? '' : text).toUpperCase().replace(/[^A-Z]/g, '');
}

/**
 * Chi-squared goodness-of-fit statistic of a letter-frequency distribution
 * against ENGLISH_FREQ, normalized per-letter (divided by n) so it is
 * comparable across inputs of different lengths — for text genuinely drawn
 * from the English distribution the per-letter statistic stays roughly flat
 * regardless of length (sampling noise around a fixed reference); for text
 * drawn from a different distribution (random letters, or English shifted by
 * the wrong Caesar key) it stays elevated regardless of length too, which is
 * exactly what makes chi-squared the standard tool for this.
 * Returns Infinity for empty input.
 */
export function chiSquaredPerChar(letters) {
  const n = letters.length;
  if (n === 0) return Infinity;
  const counts = {};
  for (const ch of letters) counts[ch] = (counts[ch] || 0) + 1;
  let chi = 0;
  for (const ch in ENGLISH_FREQ) {
    const expected = ENGLISH_FREQ[ch] * n;
    const observed = counts[ch] || 0;
    chi += ((observed - expected) ** 2) / expected;
  }
  return chi / n;
}

/**
 * Index of Coincidence: sum n_i(n_i-1) / (N(N-1)). English prose lands
 * around ~0.0667; uniform-random letters land around 1/26 ~= 0.0385.
 * Returns 0 for inputs too short to compute (N < 2).
 */
export function indexOfCoincidence(letters) {
  const n = letters.length;
  if (n < 2) return 0;
  const counts = {};
  for (const ch of letters) counts[ch] = (counts[ch] || 0) + 1;
  let sum = 0;
  for (const ch in counts) {
    const c = counts[ch];
    sum += c * (c - 1);
  }
  return sum / (n * (n - 1));
}

/** Fraction of overlapping bigrams that are in the common-English set. */
export function bigramDensity(letters) {
  if (letters.length < 2) return 0;
  let hits = 0;
  const total = letters.length - 1;
  for (let i = 0; i < total; i++) {
    if (COMMON_BIGRAMS.has(letters.slice(i, i + 2))) hits++;
  }
  return hits / total;
}

/** Fraction of overlapping trigrams that are in the common-English set. */
export function trigramDensity(letters) {
  if (letters.length < 3) return 0;
  let hits = 0;
  const total = letters.length - 2;
  for (let i = 0; i < total; i++) {
    if (COMMON_TRIGRAMS.has(letters.slice(i, i + 3))) hits++;
  }
  return hits / total;
}

/** Fraction of letters that are vowels (A E I O U). */
export function vowelRatio(letters) {
  if (letters.length === 0) return 0;
  let vowels = 0;
  for (const ch of letters) if (ch === 'A' || ch === 'E' || ch === 'I' || ch === 'O' || ch === 'U') vowels++;
  return vowels / letters.length;
}

// Chi-squared calibration: a per-char statistic under ~1 is a clean English
// match; it climbs for wrong-key/random text. exp(-chi/K) maps low chi to a
// high score and falls off from there.
const CHI_SCALE = 1.9;

// IoC calibration: score peaks at the English target (0.0667) and falls off
// on both sides; width tuned so uniform-random letters (IoC ~0.0385, a
// distance of ~0.028) land close to 0.
const IC_TARGET = 0.0667;
const IC_WIDTH = 0.028;

// Bigram/trigram raw-density normalizers: a raw density at or above these
// values earns full credit for that component.
const BIGRAM_FULL_DENSITY = 0.26;
const TRIGRAM_FULL_DENSITY = 0.12;

// Confidence dampening for short samples: every signal above is a
// statistical estimate that gets noisy on a handful of letters (a random
// 10-letter string can accidentally look "clean" by chi-squared alone).
// `letters.length` is normalized against LEN_NORM and raised to LEN_POW so
// short strings are pulled down hard while anything at/above ~19-20 letters
// keeps its full raw score. This is what keeps genuinely random short
// strings below the "looks like English" floor without also suppressing
// genuine short plaintext (Caesar/Vigenere candidates in practice are
// almost always scored *relative to their sibling shifts/keys* by callers,
// where this dampening still preserves ranking order).
const LEN_NORM = 19;
const LEN_POW = 1.6;

/**
 * Scores how much `text` looks like real English, for SPACELESS or
 * ordinarily-punctuated text alike. Returns a value in [0, 1].
 */
// Common English words (3+ letters) plus a few security/CTF-flavoured ones, for
// a word-level signal. Pure letter-frequency stats can be fooled on SHORT
// strings — a lucky XOR result can out-score a real but short plaintext. Real
// words as substrings are far stronger evidence: "ICANENCRYPT" contains CAN and
// ENCRYPT; a coincidental scramble contains none. Longer matches count for much
// more (length-squared), since a 7-letter word appearing by chance is unlikely.
const COMMON_WORDS = ('the and that have for not with you this but his from they say her she will one all would there '
  + 'their what out about who get which when make can like time just him know take people into year your good some '
  + 'could them see other than then now look only come over think also back after use two how our work first well '
  + 'way even new want because any these give day most man find here thing many well large must big high different '
  + 'small next early young important few public bad same able hello world secret message password encrypt decrypt '
  + 'cipher attack security cyber flag admin root user login logout data file test name pass code key hack access '
  + 'network server client token exploit payload shell inject victim target').split(/\s+/);
const COMMON_WORDS_SET = new Set(COMMON_WORDS);
const MAX_WORD_LEN = COMMON_WORDS.reduce((m, w) => Math.max(m, w.length), 0);

/** 0..1 signal for how much of the (uppercased, letters-only) text is covered by
 *  recognisable English words appearing as substrings, weighted by word length. */
export function wordSignal(letters) {
  const s = letters.toUpperCase();
  if (s.length < 3) return 0;
  let hitWeight = 0;
  for (let i = 0; i < s.length; i++) {
    for (let len = Math.min(MAX_WORD_LEN, s.length - i); len >= 3; len--) {
      const sub = s.slice(i, i + len).toLowerCase();
      if (COMMON_WORDS_SET.has(sub)) { hitWeight += len * len; i += len - 1; break; }
    }
  }
  // Normalise against the strongest plausible coverage (~len * avgWordLen).
  return Math.min(1, hitWeight / (s.length * 5));
}

export function scoreEnglish(text) {
  const letters = lettersOnly(text);
  if (letters.length < 4) return 0;

  // Penalise candidates full of non-letter noise (a hallmark of a wrong XOR key
  // or a mis-decode). Spaces are fine in real text and don't count against it.
  const meaningful = (text.match(/[^\s]/g) || []).length;
  const letterPurity = meaningful === 0 ? 0 : letters.length / meaningful;

  const chi = chiSquaredPerChar(letters);
  const chiScore = Math.exp(-chi / CHI_SCALE);

  const bigramScore = Math.min(1, bigramDensity(letters) / BIGRAM_FULL_DENSITY);
  const trigramScore = Math.min(1, trigramDensity(letters) / TRIGRAM_FULL_DENSITY);

  const ic = indexOfCoincidence(letters);
  const icDistance = Math.abs(ic - IC_TARGET);
  const icScore = Math.max(0, 1 - icDistance / IC_WIDTH);

  const vr = vowelRatio(letters);
  // Full credit inside [0.33, 0.47] (comfortably covers English's ~0.38-0.40
  // with sampling slack on short strings), linear falloff outside it.
  let vowelScore;
  if (vr >= 0.33 && vr <= 0.47) {
    vowelScore = 1;
  } else {
    const d = vr < 0.33 ? 0.33 - vr : vr - 0.47;
    vowelScore = Math.max(0, 1 - d / 0.25);
  }

  const wordScore = wordSignal(letters);

  const raw =
    0.24 * chiScore +
    0.22 * bigramScore +
    0.16 * trigramScore +
    0.10 * icScore +
    0.06 * vowelScore +
    0.22 * wordScore;

  const confidence = Math.min(1, Math.pow(letters.length / LEN_NORM, LEN_POW));

  // letterPurity applied with a floor so a single stray symbol doesn't tank an
  // otherwise-clean plaintext, but heavy non-letter noise is punished.
  const purityFactor = 0.5 + 0.5 * letterPurity;

  return Math.max(0, Math.min(1, raw * confidence * purityFactor));
}
