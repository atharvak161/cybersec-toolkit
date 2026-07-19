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
  { char: '⁄', looksLike: '/', script: 'Punctuation', name: 'FRACTION SLASH' }
];
