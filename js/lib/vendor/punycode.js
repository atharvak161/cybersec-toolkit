/**
 * Punycode (Bootstring) — hand-implemented reference version 1.0.
 *
 * Source: RFC 3492 (Punycode: A Bootstring encoding of Unicode for
 * Internationalized Domain Names in Applications), A. Costello, 2003.
 * https://www.rfc-editor.org/rfc/rfc3492
 *
 * Provenance note: this file is NOT pulled from an external package/CDN.
 * It is a direct implementation of the RFC 3492 bootstring algorithm
 * with the parameters specified for Punycode (base=36, tmin=1, tmax=26,
 * skew=38, damp=700, initial_bias=72, initial_n=128), written for this
 * project and validated against the RFC 3492 sample strings (e.g.
 * "bücher" -> "bcher-kva", "München" -> "Mnchen-3ya") in
 * test/run-tests.js.
 *
 * ES module. Exposes punycodeEncode(input: string): string (ASCII, no
 * "xn--" prefix) and punycodeDecode(input: string): string, plus
 * toASCII/toUnicode helpers that handle the "xn--" domain-label prefix.
 */

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const DELIMITER = '-';

function adapt(delta, numPoints, firstTime) {
  delta = firstTime ? Math.floor(delta / DAMP) : Math.floor(delta / 2);
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > Math.floor(((BASE - TMIN) * TMAX) / 2)) {
    delta = Math.floor(delta / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

function digitToBasic(digit) {
  // 0..25 -> a..z, 26..35 -> 0..9
  return digit + 22 + (digit < 26 ? 75 : 0);
}

function basicToDigit(codePoint) {
  if (codePoint >= 0x30 && codePoint <= 0x39) return codePoint - 0x30 + 26; // 0-9
  if (codePoint >= 0x41 && codePoint <= 0x5a) return codePoint - 0x41; // A-Z
  if (codePoint >= 0x61 && codePoint <= 0x7a) return codePoint - 0x61; // a-z
  return -1;
}

function codePointsOf(str) {
  return Array.from(str).map((ch) => ch.codePointAt(0));
}

/**
 * Encode a Unicode string label into its Punycode (ASCII) form,
 * without the "xn--" prefix.
 * @param {string} input
 * @returns {string}
 */
export function punycodeEncode(input) {
  const codePoints = codePointsOf(input);
  const output = [];

  // Basic (ASCII) code points go through untouched.
  const basic = codePoints.filter((cp) => cp < 0x80);
  basic.forEach((cp) => output.push(String.fromCodePoint(cp)));
  const basicLength = basic.length;
  let handledCPCount = basicLength;

  if (basicLength > 0) output.push(DELIMITER);

  let n = INITIAL_N;
  let delta = 0;
  let bias = INITIAL_BIAS;
  const inputLength = codePoints.length;

  while (handledCPCount < inputLength) {
    let m = Infinity;
    for (const cp of codePoints) {
      if (cp >= n && cp < m) m = cp;
    }
    delta += (m - n) * (handledCPCount + 1);
    n = m;

    for (const cp of codePoints) {
      if (cp < n) delta++;
      if (cp === n) {
        let q = delta;
        for (let k = BASE; ; k += BASE) {
          const t = k <= bias ? TMIN : (k >= bias + TMAX ? TMAX : k - bias);
          if (q < t) break;
          output.push(String.fromCodePoint(digitToBasic(t + ((q - t) % (BASE - t)))));
          q = Math.floor((q - t) / (BASE - t));
        }
        output.push(String.fromCodePoint(digitToBasic(q)));
        bias = adapt(delta, handledCPCount + 1, handledCPCount === basicLength);
        delta = 0;
        handledCPCount++;
      }
    }
    delta++;
    n++;
  }

  return output.join('');
}

/**
 * Decode a Punycode (ASCII) label (without "xn--" prefix) back to the
 * original Unicode string.
 * @param {string} input
 * @returns {string}
 */
export function punycodeDecode(input) {
  const inputCPs = codePointsOf(input);
  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;
  const output = [];

  let lastDelim = -1;
  for (let idx = 0; idx < inputCPs.length; idx++) {
    if (inputCPs[idx] === 0x2d) lastDelim = idx;
  }
  if (lastDelim >= 0) {
    for (let idx = 0; idx < lastDelim; idx++) output.push(String.fromCodePoint(inputCPs[idx]));
  }
  let pos = lastDelim + 1;

  while (pos < inputCPs.length) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (pos >= inputCPs.length) throw new Error('Invalid punycode input');
      const digit = basicToDigit(inputCPs[pos++]);
      if (digit === -1) throw new Error('Invalid punycode digit');
      i += digit * w;
      const t = k <= bias ? TMIN : (k >= bias + TMAX ? TMAX : k - bias);
      if (digit < t) break;
      w *= (BASE - t);
    }
    const outLen = output.length + 1;
    bias = adapt(i - oldi, outLen, oldi === 0);
    n += Math.floor(i / outLen);
    i %= outLen;
    output.splice(i, 0, String.fromCodePoint(n));
    i++;
  }

  return output.join('');
}

/** Convert a Unicode domain to its ASCII ("xn--"-prefixed) form, label by label. */
export function toASCII(domain) {
  return domain
    .split('.')
    .map((label) => {
      // eslint-disable-next-line no-control-regex
      if (/^[\x00-\x7F]*$/.test(label)) return label;
      return 'xn--' + punycodeEncode(label);
    })
    .join('.');
}

/** Convert an ASCII ("xn--"-prefixed) domain back to Unicode, label by label. */
export function toUnicode(domain) {
  return domain
    .split('.')
    .map((label) => {
      if (label.toLowerCase().startsWith('xn--')) {
        return punycodeDecode(label.slice(4));
      }
      return label;
    })
    .join('.');
}
