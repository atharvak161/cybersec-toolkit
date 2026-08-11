/**
 * IOC (Indicator of Compromise) extraction + defang/refang.
 *
 * extractIocs() normalizes defanged notation (hxxp://, 1[.]2[.]3[.]4,
 * user[at]example[.]com) back to standard form first, then pulls
 * category-specific matches out of the text in most-specific-first order,
 * masking each match out of a working copy before running the next,
 * less-specific pattern — that's what keeps a domain that's really just
 * the host of an already-extracted URL from also showing up, noisily, in
 * the domains list.
 */

// ---------- defang / refang ----------

/** Standard analyst "defang": neuters URLs/domains/emails so they can be
 * pasted into chat/ticket tools without becoming clickable/scannable. */
export function defang(text) {
  if (typeof text !== 'string') return '';
  return text
    .replace(/https/gi, 'hxxps')
    .replace(/http/gi, 'hxxp')
    .replace(/\./g, '[.]')
    .replace(/@/g, '[at]');
}

/** Reverses defang() — also tolerant of the "(.)"/"(at)" variants some
 * analysts use instead of square brackets. */
export function refang(text) {
  if (typeof text !== 'string') return '';
  return text
    .replace(/\[\.\]|\(\.\)/g, '.')
    .replace(/\[at\]|\(at\)/gi, '@')
    .replace(/hxxps/gi, 'https')
    .replace(/hxxp/gi, 'http');
}

// ---------- extraction regexes ----------

const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g;
const URL_RE = /\bhttps?:\/\/[^\s"'<>()\[\]]+/gi;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
// Standard IPv6 regex — covers full, compressed (::), and mixed forms.
// Alternatives are ordered most-specific-first: the bare "ends in ::"
// catch-all sits second-to-last so it only fires when nothing with an
// actual trailing hextet (e.g. "2001:db8::1") matched first — otherwise,
// without ^/$ anchors, the engine happily stops at the shorter alternative
// and drops the trailing group. Boundaries use lookaround on hex/colon
// characters rather than \b: a plain \b fails at the start of "::1" (a
// legitimate, common address) because ':' isn't a word character, so
// there's no word-boundary transition between a preceding space and it.
const IPV6_RE = /(?<![0-9a-fA-F:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))(?![0-9a-fA-F:])/g;
// Letters-only TLD: cheaply excludes version strings ("1.2.3") and already-masked IPs.
const DOMAIN_RE = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b/g;
const MD5_RE = /\b[a-fA-F0-9]{32}\b/g;
const SHA1_RE = /\b[a-fA-F0-9]{40}\b/g;
const SHA256_RE = /\b[a-fA-F0-9]{64}\b/g;
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;

function uniq(arr) { return [...new Set(arr)]; }
function uniqLower(arr) { return uniq(arr.map((s) => s.toLowerCase())); }
function uniqUpper(arr) { return uniq(arr.map((s) => s.toUpperCase())); }

/** Replaces every match of `re` with spaces of the same length, so a
 * subsequent, less-specific regex can't re-match the same characters. */
function mask(text, re) {
  re.lastIndex = 0;
  return text.replace(re, (m) => ' '.repeat(m.length));
}

/**
 * Extracts categorized, deduped IOCs from free text. Accepts plain or
 * defanged input (hxxp://, 1[.]2[.]3[.]4, user[at]example[.]com).
 */
export function extractIocs(text) {
  if (typeof text !== 'string' || !text) {
    return { ipv4: [], ipv6: [], domains: [], urls: [], emails: [], md5: [], sha1: [], sha256: [], cves: [] };
  }

  const refanged = refang(text);
  let working = refanged;

  const urls = uniq((working.match(URL_RE) || []).map((u) => u.replace(/[.,;:!?)]+$/, '')));
  working = mask(working, URL_RE);

  const emails = uniqLower(working.match(EMAIL_RE) || []);
  working = mask(working, EMAIL_RE);

  const ipv6 = uniqLower(working.match(IPV6_RE) || []);
  working = mask(working, IPV6_RE);

  const ipv4 = uniq(working.match(IPV4_RE) || []);
  working = mask(working, IPV4_RE);

  const domains = uniqLower(working.match(DOMAIN_RE) || []);

  // Hex-digest categories are naturally mutually exclusive: \b boundaries
  // stop a 32/40-char regex from matching a substring of a longer hex run.
  const sha256 = uniqLower(refanged.match(SHA256_RE) || []);
  const sha1 = uniqLower(refanged.match(SHA1_RE) || []);
  const md5 = uniqLower(refanged.match(MD5_RE) || []);

  const cves = uniqUpper(refanged.match(CVE_RE) || []);

  return { ipv4, ipv6, domains, urls, emails, md5, sha1, sha256, cves };
}
