/**
 * A curated (not exhaustive — Unicode's full confusables.txt is
 * thousands of entries) list of the lookalike/homoglyph characters that
 * actually show up in real-world spoofed domains and usernames: Cyrillic
 * and Greek letters that are visually near-identical to common Latin
 * letters, plus a few punctuation lookalikes. Static, pinned, no CDN
 * fetch. Cross-referenced against Unicode Technical Standard #39
 * (Unicode Security Mechanisms) "confusables.txt" for the specific
 * character pairs listed — a curated subset, not the full file.
 */

export const CONFUSABLES = [
  { char: 'а', looksLike: 'a', script: 'Cyrillic', name: 'CYRILLIC SMALL LETTER A' },
  { char: 'е', looksLike: 'e', script: 'Cyrillic', name: 'CYRILLIC SMALL LETTER IE' },
  { char: 'о', looksLike: 'o', script: 'Cyrillic', name: 'CYRILLIC SMALL LETTER O' },
  { char: 'р', looksLike: 'p', script: 'Cyrillic', name: 'CYRILLIC SMALL LETTER ER' },
  { char: 'с', looksLike: 'c', script: 'Cyrillic', name: 'CYRILLIC SMALL LETTER ES' },
  { char: 'х', looksLike: 'x', script: 'Cyrillic', name: 'CYRILLIC SMALL LETTER HA' },
  { char: 'у', looksLike: 'y', script: 'Cyrillic', name: 'CYRILLIC SMALL LETTER U' },
  { char: 'і', looksLike: 'i', script: 'Cyrillic', name: 'CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I' },
  { char: 'ј', looksLike: 'j', script: 'Cyrillic', name: 'CYRILLIC SMALL LETTER JE' },
  { char: 'һ', looksLike: 'h', script: 'Cyrillic', name: 'CYRILLIC SMALL LETTER SHHA' },
  { char: 'ѕ', looksLike: 's', script: 'Cyrillic', name: 'CYRILLIC SMALL LETTER DZE' },
  { char: 'ԁ', looksLike: 'd', script: 'Cyrillic', name: 'CYRILLIC SMALL LETTER KOMI DE' },
  { char: 'А', looksLike: 'A', script: 'Cyrillic', name: 'CYRILLIC CAPITAL LETTER A' },
  { char: 'В', looksLike: 'B', script: 'Cyrillic', name: 'CYRILLIC CAPITAL LETTER VE' },
  { char: 'Е', looksLike: 'E', script: 'Cyrillic', name: 'CYRILLIC CAPITAL LETTER IE' },
  { char: 'К', looksLike: 'K', script: 'Cyrillic', name: 'CYRILLIC CAPITAL LETTER KA' },
  { char: 'М', looksLike: 'M', script: 'Cyrillic', name: 'CYRILLIC CAPITAL LETTER EM' },
  { char: 'Н', looksLike: 'H', script: 'Cyrillic', name: 'CYRILLIC CAPITAL LETTER EN' },
  { char: 'О', looksLike: 'O', script: 'Cyrillic', name: 'CYRILLIC CAPITAL LETTER O' },
  { char: 'Р', looksLike: 'P', script: 'Cyrillic', name: 'CYRILLIC CAPITAL LETTER ER' },
  { char: 'С', looksLike: 'C', script: 'Cyrillic', name: 'CYRILLIC CAPITAL LETTER ES' },
  { char: 'Т', looksLike: 'T', script: 'Cyrillic', name: 'CYRILLIC CAPITAL LETTER TE' },
  { char: 'Х', looksLike: 'X', script: 'Cyrillic', name: 'CYRILLIC CAPITAL LETTER HA' },
  { char: 'ο', looksLike: 'o', script: 'Greek', name: 'GREEK SMALL LETTER OMICRON' },
  { char: 'ν', looksLike: 'v', script: 'Greek', name: 'GREEK SMALL LETTER NU' },
  { char: 'α', looksLike: 'a', script: 'Greek', name: 'GREEK SMALL LETTER ALPHA' },
  { char: 'κ', looksLike: 'k', script: 'Greek', name: 'GREEK SMALL LETTER KAPPA' },
  { char: 'Α', looksLike: 'A', script: 'Greek', name: 'GREEK CAPITAL LETTER ALPHA' },
  { char: 'Β', looksLike: 'B', script: 'Greek', name: 'GREEK CAPITAL LETTER BETA' },
  { char: 'Ε', looksLike: 'E', script: 'Greek', name: 'GREEK CAPITAL LETTER EPSILON' },
  { char: 'Η', looksLike: 'H', script: 'Greek', name: 'GREEK CAPITAL LETTER ETA' },
  { char: 'Ι', looksLike: 'I', script: 'Greek', name: 'GREEK CAPITAL LETTER IOTA' },
  { char: 'Κ', looksLike: 'K', script: 'Greek', name: 'GREEK CAPITAL LETTER KAPPA' },
  { char: 'Μ', looksLike: 'M', script: 'Greek', name: 'GREEK CAPITAL LETTER MU' },
  { char: 'Ν', looksLike: 'N', script: 'Greek', name: 'GREEK CAPITAL LETTER NU' },
  { char: 'Ο', looksLike: 'O', script: 'Greek', name: 'GREEK CAPITAL LETTER OMICRON' },
  { char: 'Ρ', looksLike: 'P', script: 'Greek', name: 'GREEK CAPITAL LETTER RHO' },
  { char: 'Τ', looksLike: 'T', script: 'Greek', name: 'GREEK CAPITAL LETTER TAU' },
  { char: 'Χ', looksLike: 'X', script: 'Greek', name: 'GREEK CAPITAL LETTER CHI' },
  { char: 'İ', looksLike: 'I', script: 'Latin Extended', name: 'LATIN CAPITAL LETTER I WITH DOT ABOVE' },
  { char: 'ı', looksLike: 'i', script: 'Latin Extended', name: 'LATIN SMALL LETTER DOTLESS I' },
  { char: '‐', looksLike: '-', script: 'Punctuation', name: 'HYPHEN' },
  { char: '−', looksLike: '-', script: 'Punctuation', name: 'MINUS SIGN' },
  { char: ' ', looksLike: ' ', script: 'Punctuation', name: 'NO-BREAK SPACE' },
  { char: '⁄', looksLike: '/', script: 'Punctuation', name: 'FRACTION SLASH' },

  // Full-width Latin letters (U+FF21-FF3A, U+FF41-FF5A) — used in real-world
  // phishing/spoofing to visually mimic plain ASCII while evading naive
  // substring/blacklist filters (e.g. full-width "ａ" vs ASCII "a").
  ...fullwidthLatinConfusables()
];

/** Generates the 52 full-width Latin A-Z/a-z -> ASCII confusable entries. */
function fullwidthLatinConfusables() {
  const entries = [];
  for (let i = 0; i < 26; i++) {
    const upperAscii = String.fromCharCode(65 + i); // 'A'..'Z'
    const lowerAscii = String.fromCharCode(97 + i); // 'a'..'z'
    entries.push({
      char: String.fromCodePoint(0xFF21 + i), // FULLWIDTH LATIN CAPITAL LETTER A..Z
      looksLike: upperAscii,
      script: 'Fullwidth',
      name: `FULLWIDTH LATIN CAPITAL LETTER ${upperAscii}`
    });
    entries.push({
      char: String.fromCodePoint(0xFF41 + i), // FULLWIDTH LATIN SMALL LETTER a..z
      looksLike: lowerAscii,
      script: 'Fullwidth',
      name: `FULLWIDTH LATIN SMALL LETTER ${upperAscii}`
    });
  }
  return entries;
}

// Zero-width / invisible characters used for injection/obfuscation (e.g.
// splitting a blocked keyword so a naive filter misses it, or padding a
// spoofed string so it visually matches a target while differing byte-for-
// byte). These are NOT lookalikes of any specific visible character — they
// render as nothing — so they're tracked separately from CONFUSABLES and
// flagged by detectHomoglyphs() as their own "invisible character" category
// rather than shoehorned into the confusable-pair ("looks like X") shape.
export const INVISIBLE_CHARS = [
  { char: String.fromCodePoint(0x200B), codepoint: 'U+200B', name: 'ZERO WIDTH SPACE' },
  { char: String.fromCodePoint(0x200C), codepoint: 'U+200C', name: 'ZERO WIDTH NON-JOINER' },
  { char: String.fromCodePoint(0x200D), codepoint: 'U+200D', name: 'ZERO WIDTH JOINER' },
  { char: String.fromCodePoint(0xFEFF), codepoint: 'U+FEFF', name: 'ZERO WIDTH NO-BREAK SPACE (BOM)' }
];
