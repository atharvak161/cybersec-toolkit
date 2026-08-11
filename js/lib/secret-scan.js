/**
 * Local secret / API-key scanner. Runs a set of provider-specific regexes
 * plus a Shannon-entropy fallback for anything else that looks like a
 * pasted-in credential. Everything happens in-memory against the pasted
 * text — nothing is sent anywhere, which is also why this is safe to run
 * against real config files.
 */

/** Shannon entropy of a string, in bits per character. Also exported for
 * reuse by the standalone Entropy Calculator tool. */
export function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  const len = str.length;
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Rough, human-readable read on what a given bits/char entropy value
 * suggests the source data is — used by both the Secret Scanner summary
 * and the standalone Entropy Calculator tool. Bands are deliberately
 * approximate (real classification needs more than unigram entropy) but
 * useful as a fast first read. */
export function describeEntropy(bitsPerChar) {
  if (!Number.isFinite(bitsPerChar) || bitsPerChar <= 0) return 'no variation — a single repeated character or empty input';
  if (bitsPerChar < 1.5) return 'very low — highly repetitive or uniform data';
  if (bitsPerChar < 3.0) return 'low-to-moderate — plausibly natural-language text';
  if (bitsPerChar < 4.3) return 'moderate — consistent with English text, JSON/structured data, or a short identifier';
  if (bitsPerChar < 5.2) return 'high — consistent with Base64/hex-encoded data or compressed content';
  return 'very high — consistent with random data, an encryption key, or encrypted/compressed binary';
}

const NAMED_PATTERNS = [
  { type: 'AWS Access Key ID', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { type: 'GitHub Token', re: /\bgh[pos]_[A-Za-z0-9]{36}\b/g },
  { type: 'Slack Token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,72}\b/g },
  { type: 'Google API Key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { type: 'JWT', re: /\bey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g }
];

// 40 chars from the base64 alphabet — AWS secret access keys are exactly
// this shape. Pure-hex 40-char runs are excluded here (those are almost
// always SHA-1 digests, not secrets) and left to the JWT/hash-shaped world.
const AWS_SECRET_RE = /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g;
const PRIVATE_KEY_RE = /-----BEGIN ((?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY)-----[\s\S]*?-----END \1-----/g;
const GENERIC_RE = /[A-Za-z0-9+/_=.-]{20,}/g;
const HEX_RE = /^[0-9a-fA-F]+$/;

/** Masks a matched secret down to a few boundary characters — enough to
 * spot which credential it is without printing the whole thing. */
function maskSecret(match) {
  if (match.length <= 8) return match.slice(0, 2) + '*'.repeat(Math.max(0, match.length - 2));
  return `${match.slice(0, 4)}…${match.slice(-4)}`;
}

function isCoveredByNamedPattern(token) {
  if (HEX_RE.test(token) && (token.length === 32 || token.length === 40 || token.length === 64)) return true;
  for (const { re } of NAMED_PATTERNS) {
    re.lastIndex = 0;
    if (re.test(token)) return true;
  }
  return false;
}

/**
 * Scans pasted text for likely secrets/API keys.
 * @param {string} text
 * @returns {{type:string, match:string, line:number}[]}
 */
export function scanSecrets(text) {
  if (typeof text !== 'string' || !text) return [];
  const findings = [];
  const lines = text.split('\n');

  lines.forEach((line, i) => {
    // Tokens already flagged by a more specific detector on this line are
    // skipped by the generic entropy fallback below, so one credential
    // never shows up twice under two different labels.
    const flaggedTokens = new Set();

    for (const { type, re } of NAMED_PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(line))) {
        flaggedTokens.add(m[0]);
        findings.push({ type, match: maskSecret(m[0]), line: i + 1 });
      }
    }

    AWS_SECRET_RE.lastIndex = 0;
    let sm;
    while ((sm = AWS_SECRET_RE.exec(line))) {
      const token = sm[0];
      if (HEX_RE.test(token)) continue; // pure hex 40-char run — that's a SHA-1 digest, not a secret
      if (shannonEntropy(token) > 4.0) {
        flaggedTokens.add(token);
        findings.push({ type: 'AWS Secret Access Key (possible)', match: maskSecret(token), line: i + 1 });
      }
    }

    GENERIC_RE.lastIndex = 0;
    let gm;
    while ((gm = GENERIC_RE.exec(line))) {
      const token = gm[0];
      if (token.length < 20) continue;
      if (flaggedTokens.has(token) || isCoveredByNamedPattern(token)) continue;
      if (shannonEntropy(token) > 4.0) {
        findings.push({ type: 'Possible secret (high entropy)', match: maskSecret(token), line: i + 1 });
      }
    }
  });

  PRIVATE_KEY_RE.lastIndex = 0;
  let pm;
  while ((pm = PRIVATE_KEY_RE.exec(text))) {
    const lineNum = text.slice(0, pm.index).split('\n').length;
    findings.push({ type: `Private Key Block (${pm[1].trim()})`, match: `-----BEGIN ${pm[1]}----- … (redacted block)`, line: lineNum });
  }

  findings.sort((a, b) => a.line - b.line);
  return findings;
}
