/**
 * A small library of common, useful regex patterns for the regex
 * tester tool, plus a thin test/match wrapper.
 */

// Patterns are intentionally NOT anchored (no ^...$) so the tester can find
// matches embedded within larger pasted text, not just whole-string matches.
// (Use word boundaries / lookarounds where that matters for precision.)
export const COMMON_PATTERNS = [
  { name: 'Email address', pattern: '[\\w.+-]+@([\\w-]+\\.)+[a-zA-Z]{2,}', flags: '' },
  { name: 'IPv4 address', pattern: '\\b(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\b', flags: '' },
  { name: 'IPv6 address', pattern: '\\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\\b|\\b::\\b|\\b([0-9a-fA-F]{1,4}:){1,7}:', flags: '' },
  { name: 'URL', pattern: '\\bhttps?:\\/\\/[\\w-]+(\\.[\\w-]+)+(:\\d+)?(\\/[^\\s]*)?', flags: '' },
  { name: 'Hex color', pattern: '#(?:[0-9a-fA-F]{3}){1,2}\\b', flags: '' },
  { name: 'MAC address', pattern: '\\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\\b', flags: '' },
  { name: 'UUID', pattern: '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', flags: 'i' },
  { name: 'Date (YYYY-MM-DD)', pattern: '\\b\\d{4}-\\d{2}-\\d{2}\\b', flags: '' },
  { name: 'Credit card (basic)', pattern: '\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b', flags: '' },
  { name: 'Slug (kebab-case)', pattern: '\\b[a-z0-9]+(?:-[a-z0-9]+)*\\b', flags: '' }
];

/**
 * Test/match a pattern against a text. Returns matches with indices, or
 * throws a descriptive error for invalid regex.
 */
export function testRegex(pattern, flags, text) {
  let re;
  try {
    re = new RegExp(pattern, flags.includes('g') ? flags : flags + 'g');
  } catch (e) {
    throw new Error('Invalid regular expression: ' + e.message);
  }
  const matches = [];
  let m;
  let iterations = 0;
  while ((m = re.exec(text)) !== null && iterations < 10000) {
    matches.push({ match: m[0], index: m.index, groups: m.slice(1) });
    if (m[0].length === 0) re.lastIndex++;
    iterations++;
  }
  return matches;
}
