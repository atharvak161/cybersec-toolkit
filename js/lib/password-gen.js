/**
 * Cryptographically random password generator. Uses crypto.getRandomValues
 * exclusively (never Math.random) with rejection sampling so every
 * character in the configured charset has exactly equal probability —
 * no modulo bias.
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
  let password = randomStringFromCharset(chars, length);

  // Guarantee at least one char from each selected set (common site requirement),
  // by construction rather than by re-rolling until satisfied (avoids
  // unbounded/variable-time loops on unlucky draws).
  const requiredSets = selectedSets.map((set) =>
    excludeAmbiguous ? Array.from(set).filter((c) => !AMBIGUOUS.has(c)) : Array.from(set)
  ).filter((set) => set.length > 0);

  if (requiredSets.length > 1 && length >= requiredSets.length) {
    const positions = randomUniqueIndexes(length, requiredSets.length);
    const passwordChars = Array.from(password);
    requiredSets.forEach((set, i) => {
      passwordChars[positions[i]] = set[randomIndex(set.length)];
    });
    password = passwordChars.join('');
  }

  return password;
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

function randomStringFromCharset(chars, length) {
  let out = '';
  for (let i = 0; i < length; i++) out += chars[randomIndex(chars.length)];
  return out;
}

/** n distinct random indexes in [0, length), Fisher-Yates partial shuffle. */
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
