/**
 * Homoglyph / lookalike-character detector. Scans text for characters
 * that are visually confusable with common ASCII Latin letters — the
 * same trick used in typosquatted/spoofed domains ("microsоft.com" with
 * a Cyrillic о). Pairs with the Punycode/IDN tool and Phishing Checker.
 */

import { CONFUSABLES, INVISIBLE_CHARS } from '../../data/confusables.js';

const CONFUSABLE_MAP = new Map(CONFUSABLES.map((c) => [c.char, c]));
const INVISIBLE_MAP = new Map(INVISIBLE_CHARS.map((c) => [c.char, c]));

function toCodepointHex(char) {
  return 'U+' + char.codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
}

/**
 * @param {string} text
 * @returns {{ flagged: Array<{char: string, index: number, codepoint: string,
 *   looksLike: string, script: string, name: string}>, hasMixedScript: boolean,
 *   scriptsSeen: string[], invisibleChars: Array<{char: string, index: number,
 *   codepoint: string, name: string}>, hasInvisibleChars: boolean }}
 */
export function detectHomoglyphs(text) {
  const flagged = [];
  const invisibleChars = [];
  const scriptsSeen = new Set();

  const chars = Array.from(text); // iterate by codepoint, not UTF-16 code unit
  let index = 0;
  for (const char of chars) {
    const invisible = INVISIBLE_MAP.get(char);
    const entry = CONFUSABLE_MAP.get(char);
    if (invisible) {
      // Invisible/zero-width characters aren't a lookalike of anything —
      // they're an injection technique in their own right — so they're
      // reported as a distinct category rather than in `flagged`.
      invisibleChars.push({
        char,
        index,
        codepoint: toCodepointHex(char),
        name: invisible.name
      });
    } else if (entry) {
      flagged.push({
        char,
        index,
        codepoint: toCodepointHex(char),
        looksLike: entry.looksLike,
        script: entry.script,
        name: entry.name
      });
      scriptsSeen.add(entry.script);
    } else if (/[a-zA-Z0-9]/.test(char)) {
      scriptsSeen.add('Latin/ASCII');
    }
    index += char.length;
  }

  return {
    flagged,
    hasMixedScript: flagged.length > 0 && scriptsSeen.has('Latin/ASCII'),
    scriptsSeen: Array.from(scriptsSeen),
    invisibleChars,
    hasInvisibleChars: invisibleChars.length > 0
  };
}
