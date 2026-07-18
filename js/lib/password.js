/**
 * Password strength / entropy analyzer. Pure logic — estimates entropy
 * from effective charset size and length, flags common weaknesses
 * (repeated chars, sequences, common patterns), and gives a rough
 * offline-crack-time estimate. This is a heuristic estimate, not a
 * substitute for a real password policy engine (e.g. zxcvbn).
 */

const CHARSET_TESTS = [
  { re: /[a-z]/, size: 26 },
  { re: /[A-Z]/, size: 26 },
  { re: /[0-9]/, size: 10 },
  { re: /[^a-zA-Z0-9]/, size: 33 } // approx printable symbol set
];

function effectiveCharsetSize(password) {
  return CHARSET_TESTS.reduce((sum, t) => (t.re.test(password) ? sum + t.size : sum), 0) || 1;
}

function hasSequential(password, len = 3) {
  const lower = password.toLowerCase();
  const sequences = ['abcdefghijklmnopqrstuvwxyz', '0123456789', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
  for (const seq of sequences) {
    for (let i = 0; i <= seq.length - len; i++) {
      const fwd = seq.slice(i, i + len);
      const rev = fwd.split('').reverse().join('');
      if (lower.includes(fwd) || lower.includes(rev)) return true;
    }
  }
  return false;
}

function hasRepeats(password, len = 3) {
  const re = new RegExp(`(.)\\1{${len - 1},}`);
  return re.test(password);
}

/**
 * Analyze password strength.
 * @param {string} password
 * @returns {{ entropyBits: number, charsetSize: number, length: number,
 *   crackTimeSeconds: number, crackTimeHuman: string, score: 0|1|2|3|4,
 *   label: string, warnings: string[] }}
 */
export function analyzePassword(password) {
  const length = password.length;
  const charsetSize = effectiveCharsetSize(password);
  const entropyBits = length === 0 ? 0 : length * Math.log2(charsetSize);

  const warnings = [];
  if (hasSequential(password)) warnings.push('Contains a common keyboard/alphabet/number sequence.');
  if (hasRepeats(password)) warnings.push('Contains 3+ repeated characters in a row.');
  if (length > 0 && length < 8) warnings.push('Shorter than 8 characters.');
  if (/^[a-zA-Z]+$/.test(password)) warnings.push('Letters only — add numbers/symbols to raise entropy.');
  if (/^\d+$/.test(password)) warnings.push('Digits only — very low entropy per character.');

  // Rough offline guesses-per-second assumption for a modern GPU rig on a fast hash: 1e10/s.
  const guessesPerSecond = 1e10;
  const totalGuesses = Math.pow(2, entropyBits);
  const crackTimeSeconds = totalGuesses / guessesPerSecond / 2; // average case (half the keyspace)

  let score = 0;
  if (entropyBits >= 28) score = 1;
  if (entropyBits >= 36) score = 2;
  if (entropyBits >= 60) score = 3;
  if (entropyBits >= 80) score = 4;
  if (warnings.length >= 2 && score > 0) score -= 1;

  const labels = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];

  return {
    entropyBits: Math.round(entropyBits * 10) / 10,
    charsetSize,
    length,
    crackTimeSeconds,
    crackTimeHuman: humanizeSeconds(crackTimeSeconds),
    score,
    label: labels[score],
    warnings
  };
}

const CENTURY_SECONDS = 3153600000;

function humanizeSeconds(seconds) {
  if (!isFinite(seconds) || seconds < 0) return 'unknown';
  if (seconds < 1) return 'instantly';

  // Cap absurdly large durations at a readable order-of-magnitude instead of
  // showing a huge, meaningless exact digit count.
  if (seconds >= CENTURY_SECONDS * 1e6) {
    const exponent = Math.floor(Math.log10(seconds / CENTURY_SECONDS));
    return `>10^${exponent} centuries`;
  }

  const units = [
    ['century', 'centuries', CENTURY_SECONDS],
    ['year', 'years', 31536000],
    ['day', 'days', 86400],
    ['hour', 'hours', 3600],
    ['minute', 'minutes', 60],
    ['second', 'seconds', 1]
  ];
  for (const [singular, plural, secs] of units) {
    if (seconds >= secs) {
      const val = Math.round(seconds / secs);
      return `${val.toLocaleString('en-US')} ${val === 1 ? singular : plural}`;
    }
  }
  return 'instantly';
}
