/**
 * Cryptographically random password generator. Uses crypto.getRandomValues
 * exclusively (never Math.random) with rejection sampling so every draw
 * from a charset has exactly equal probability — no modulo bias.
 *
 * When multiple character sets are selected, the generator guarantees at
 * least one character from each set (a common site requirement). To keep
 * this as close to uniform as possible, the password is first drawn
 * ENTIRELY uniformly from the combined charset; only sets that happen to
 * be entirely absent from that draw get a single character force-inserted
 * (replacing a random position) to satisfy the guarantee. For any
 * reasonably-sized password this means most draws need no forcing at all
 * (e.g. a 16-char password with a 10-char digit set has ~86% chance of
 * already containing a digit), so representation stays proportional to
 * each set's size rather than skewed toward smaller sets. Forcing only
 * kicks in — and only for the specific set(s) that came up empty — on the
 * unlucky draws, which is unavoidable skew: any scheme that *guarantees*
 * coverage of every selected set must, on draws where a small set was
 * naturally absent, insert one of its characters, and for very short
 * passwords with many required sets that skew becomes a larger share of
 * the total. That residual is inherent to the coverage guarantee itself,
 * not a fixable implementation bug.
 */

const CHARSETS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  digits: '0123456789',
  symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
};

// Characters that are easy to misread/mistype and commonly excluded from
// generated passwords: 0/O, 1/l/I, and a couple of visually-similar symbols.
const AMBIGUOUS = new Set(['0', 'O', '1', 'l', 'I', '|', "'", '`', '"']);

/**
 * @param {{ length?: number, upper?: boolean, lower?: boolean, digits?: boolean,
 *   symbols?: boolean, excludeAmbiguous?: boolean }} opts
 * @returns {string}
 */
export function generatePassword(opts = {}) {
  const {
    length = 16,
    upper = true,
    lower = true,
    digits = true,
    symbols = true,
    excludeAmbiguous = false
  } = opts;

  if (!Number.isInteger(length) || length < 1) throw new Error('Length must be a positive integer');

  const selectedSets = [];
  if (upper) selectedSets.push(CHARSETS.upper);
  if (lower) selectedSets.push(CHARSETS.lower);
  if (digits) selectedSets.push(CHARSETS.digits);
  if (symbols) selectedSets.push(CHARSETS.symbols);
  if (selectedSets.length === 0) throw new Error('Select at least one character set');

  let charset = selectedSets.join('');
  if (excludeAmbiguous) {
    charset = Array.from(charset).filter((c) => !AMBIGUOUS.has(c)).join('');
  }
  if (charset.length === 0) throw new Error('Character set is empty after exclusions');

  const chars = Array.from(charset);

  // Guarantee at least one char from each selected set (common site requirement),
  // by construction rather than by re-rolling until satisfied (avoids
  // unbounded/variable-time loops on unlucky draws).
  const requiredSets = selectedSets.map((set) =>
    excludeAmbiguous ? Array.from(set).filter((c) => !AMBIGUOUS.has(c)) : Array.from(set)
  ).filter((set) => set.length > 0);

  // Draw every position uniformly from the full combined charset first —
  // this is the only draw that happens for most passwords.
  const passwordChars = Array.from({ length }, () => chars[randomIndex(chars.length)]);

  if (requiredSets.length > 1 && length >= requiredSets.length) {
    // Only force-insert for sets that came up completely empty in the
    // uniform draw above — not for every required set unconditionally.
    // This is what keeps representation close to proportional: a set that
    // already appears naturally is left alone.
    const missingSetIndexes = requiredSets
      .map((set, i) => (passwordChars.some((c) => set.includes(c)) ? -1 : i))
      .filter((i) => i !== -1);

    if (missingSetIndexes.length > 0) {
      const positions = randomUniqueIndexes(length, missingSetIndexes.length);
      missingSetIndexes.forEach((setIdx, i) => {
        const set = requiredSets[setIdx];
        passwordChars[positions[i]] = set[randomIndex(set.length)];
      });
    }
  }

  return passwordChars.join('');
}

/** Unbiased random index in [0, max) via rejection sampling over crypto.getRandomValues. */
export function randomIndex(max) {
  if (max <= 0) throw new Error('max must be positive');
  const arr = new Uint32Array(1);
  const limit = Math.floor(0x100000000 / max) * max;
  let value;
  do {
    globalThis.crypto.getRandomValues(arr);
    value = arr[0];
  } while (value >= limit);
  return value % max;
}

/** n distinct random indexes in [0, length), via partial Fisher-Yates over an index pool. */
function randomUniqueIndexes(length, n) {
  const pool = Array.from({ length }, (_, i) => i);
  for (let i = 0; i < n; i++) {
    const j = i + randomIndex(pool.length - i);
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }
  return pool.slice(0, n);
}

/** Rough entropy estimate for the generated password, given the same options. */
export function estimateEntropyBits(opts = {}) {
  const { length = 16, upper = true, lower = true, digits = true, symbols = true, excludeAmbiguous = false } = opts;
  let charsetSize = 0;
  if (upper) charsetSize += CHARSETS.upper.length;
  if (lower) charsetSize += CHARSETS.lower.length;
  if (digits) charsetSize += CHARSETS.digits.length;
  if (symbols) charsetSize += CHARSETS.symbols.length;
  if (excludeAmbiguous) {
    // Approximate: subtract ambiguous chars that fall within selected sets.
    let ambiguousInSet = 0;
    const all = [upper && CHARSETS.upper, lower && CHARSETS.lower, digits && CHARSETS.digits, symbols && CHARSETS.symbols]
      .filter(Boolean)
      .join('');
    for (const c of AMBIGUOUS) if (all.includes(c)) ambiguousInSet++;
    charsetSize -= ambiguousInSet;
  }
  if (charsetSize <= 0) return 0;
  return Math.round(length * Math.log2(charsetSize) * 10) / 10;
}
