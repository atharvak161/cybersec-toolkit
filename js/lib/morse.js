/**
 * Morse code encode/decode. Pure, dependency-free. Letters and digits use
 * the international (ITU-R M.1677-1) table; word boundaries are '/' with
 * spaces around them, letters within a word are separated by a single
 * space, per standard Morse transcription convention.
 */

const MORSE_TABLE = {
  A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.',
  H: '....', I: '..', J: '.---', K: '-.-', L: '.-..', M: '--', N: '-.',
  O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-', U: '..-',
  V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..',
  0: '-----', 1: '.----', 2: '..---', 3: '...--', 4: '....-',
  5: '.....', 6: '-....', 7: '--...', 8: '---..', 9: '----.',
  '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--',
  '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...',
  ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-',
  '"': '.-..-.', '$': '...-..-', '@': '.--.-.'
};

const MORSE_TABLE_REVERSE = Object.fromEntries(
  Object.entries(MORSE_TABLE).map(([ch, code]) => [code, String(ch)])
);

/** Encode plain text to Morse. Words separated by ' / ', letters by ' '. */
export function morseEncode(text) {
  const words = text.trim().split(/\s+/).filter(Boolean);
  return words
    .map((word) =>
      Array.from(word.toUpperCase())
        .map((ch) => {
          if (ch in MORSE_TABLE) return MORSE_TABLE[ch];
          throw new Error(`No Morse mapping for character: "${ch}"`);
        })
        .join(' ')
    )
    .join(' / ');
}

/** Decode Morse back to plain text. Accepts '/' or '   ' (3+ spaces) as word separators. */
export function morseDecode(morse) {
  const normalized = morse.trim().replace(/\s*\/\s*/g, ' / ');
  const words = normalized.split(/\s+\/\s+|\s{2,}/).filter(Boolean);
  return words
    .map((word) =>
      word
        .trim()
        .split(/\s+/)
        .filter(Boolean)
        .map((code) => {
          if (code in MORSE_TABLE_REVERSE) return MORSE_TABLE_REVERSE[code];
          throw new Error(`Unrecognized Morse token: "${code}"`);
        })
        .join('')
    )
    .join(' ');
}
