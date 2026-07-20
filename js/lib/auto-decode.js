/**
 * Auto-Decode (Magic Wand) — the "identify anything" engine.
 *
 * Given a mystery string of unknown encoding/cipher, this orchestrator tries
 * every decoder in the toolkit, recursively re-decodes the results (to peel
 * layered encodings like base64->hex->plain), and returns the plausible
 * decodings ranked by a transparent scoring heuristic.
 *
 * IMPORTANT — this file is pure orchestration. It does NOT reimplement any
 * encoding/decoding/cipher. Every decoder is imported and reused from the
 * existing library modules:
 *   - hex / base64 / base32 / base58 / binary / url / rot13  -> ./encoding.js
 *   - base85 / base91 / uudecode                             -> ./encoding-extra.js
 *   - morse                                                  -> ./morse.js
 *   - punycode (toUnicode)                                   -> ./vendor/punycode.js
 *   - hash-type identification                               -> ./hashing.js (identifyHash)
 *
 * Search strategy: best-first (a priority frontier ordered by how "promising"
 * a node still looks as further-encoded data), with a hard depth cap and a
 * hard, actually-enforced cap on total decode attempts. Best-first ordering
 * guarantees that if the attempt budget is exhausted mid-search, it was spent
 * on the most plausible branches first, not starved on a dead branch.
 */

import {
  hexDecode,
  base64Decode,
  base32Decode,
  base58Decode,
  binaryDecode,
  urlDecode,
  rot13,
  caesarShift,
  bytesToStr
} from './encoding.js';
import { base85Decode, base91Decode, uuDecode } from './encoding-extra.js';
import { morseDecode } from './morse.js';
import { toUnicode } from './vendor/punycode.js';
import { identifyHash } from './hashing.js';

// ---------------------------------------------------------------------------
// Tuning constants (both overridable via options for testing)
// ---------------------------------------------------------------------------

/**
 * DEFAULT_DEPTH_CAP = 4.
 * Real-world layered encodings (CTF challenges, config-blob obfuscation,
 * malware droppers) almost never exceed 3-4 layers — e.g. base64(gzip)=2,
 * base64(hex(rot13))=3. Beyond 4 the chance a genuine human-intended layer
 * exists collapses while the search tree grows geometrically (~branching^depth).
 * 4 captures essentially every real case with margin.
 */
const DEFAULT_DEPTH_CAP = 4;

/**
 * DEFAULT_MAX_ATTEMPTS = 400.
 * With ~12 decoders and depth 4 the unbounded worst-case tree is up to
 * 12^4 ~= 20,700 nodes. 400 keeps wall-time well under a 1s budget (each
 * attempt is one O(n) decode of a small string) while still allowing the top
 * handful of promising branches to be explored to full depth (best-first
 * spends the budget on the most plausible branches first). Realistic inputs
 * terminate naturally — the frontier empties — long before 400; the cap only
 * bites on adversarial maximally-branching inputs, which is exactly its job.
 */
const DEFAULT_MAX_ATTEMPTS = 400;

// A short list of the ~100 most common English words, used purely for a
// lightweight "does this look like English?" ratio. Deliberately inline — no
// new data file, per spec.
const COMMON_WORDS = new Set([
  'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i', 'it', 'for',
  'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at', 'this', 'but', 'his',
  'by', 'from', 'they', 'we', 'say', 'her', 'she', 'or', 'an', 'will', 'my',
  'one', 'all', 'would', 'there', 'their', 'what', 'so', 'up', 'out', 'if',
  'about', 'who', 'get', 'which', 'go', 'me', 'when', 'make', 'can', 'like',
  'time', 'no', 'just', 'him', 'know', 'take', 'people', 'into', 'year', 'your',
  'good', 'some', 'could', 'them', 'see', 'other', 'than', 'then', 'now',
  'look', 'only', 'come', 'its', 'over', 'think', 'also', 'back', 'after',
  'use', 'two', 'how', 'our', 'work', 'first', 'well', 'way', 'even', 'new',
  'want', 'because', 'any', 'these', 'give', 'day', 'most', 'us', 'is', 'are',
  'was', 'hello', 'world', 'secret', 'password', 'flag', 'message', 'attack'
]);

// Strict UTF-8 decoder — throws on invalid byte sequences, so we can honestly
// tell "valid UTF-8" from "bytes that only accidentally decode".
const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true });

// ---------------------------------------------------------------------------
// Decoder registry — each entry reuses an existing library function.
// kind 'bytes'  -> fn(str, true) returns a Uint8Array (we then UTF-8 decode it)
// kind 'text'   -> fn(str) returns a String directly
// precheck(str) -> cheap regex/length gate BEFORE we ever call the decoder,
//                  so obviously-invalid candidates cost ~nothing.
// involution    -> true if applying twice returns the original (cycle risk).
// ---------------------------------------------------------------------------

const B91_CHARS =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' +
  '!#$%&()*+,./:;<=>?@[]^_`{|}~"';
const B91_SET = new Set(B91_CHARS.split(''));

const DECODERS = [
  {
    name: 'base64',
    kind: 'bytes',
    // base64 alphabet incl. url-safe (- _) and padding; needs real length.
    precheck: (s) => s.length >= 8 && /^[A-Za-z0-9+/\-_]+={0,2}$/.test(s.replace(/\s+/g, '')),
    decode: (s) => base64Decode(s, true)
  },
  {
    name: 'hex',
    kind: 'bytes',
    precheck: (s) => {
      const c = s.trim().replace(/\s+/g, '').replace(/^0x/i, '');
      return c.length >= 4 && c.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(c);
    },
    decode: (s) => hexDecode(s, true)
  },
  {
    name: 'base32',
    kind: 'bytes',
    precheck: (s) => {
      const c = s.trim().replace(/\s+/g, '').replace(/=+$/, '');
      return c.length >= 8 && /^[A-Za-z2-7]+$/.test(c);
    },
    decode: (s) => base32Decode(s, true)
  },
  {
    name: 'base58',
    kind: 'bytes',
    // Bitcoin alphabet: no 0 O I l, no +/=; this excludes most noise.
    precheck: (s) => {
      const c = s.trim();
      return c.length >= 4 && /^[1-9A-HJ-NP-Za-km-z]+$/.test(c);
    },
    decode: (s) => base58Decode(s, true)
  },
  {
    name: 'base85',
    kind: 'bytes',
    // Ascii85 digits are '!'(33)..'u'(117), plus 'z' and optional <~ ~> delims.
    precheck: (s) => {
      const c = s.trim().replace(/^<~/, '').replace(/~>$/, '').replace(/\s+/g, '');
      return c.length >= 5 && /^[\x21-\x75z]+$/.test(c);
    },
    decode: (s) => base85Decode(s, true)
  },
  {
    name: 'base91',
    kind: 'bytes',
    precheck: (s) => {
      const c = s.trim();
      return c.length >= 3 && c.split('').every((ch) => B91_SET.has(ch));
    },
    decode: (s) => base91Decode(s, true)
  },
  {
    name: 'binary',
    kind: 'bytes',
    precheck: (s) => /^[01\s]+$/.test(s.trim()) && s.replace(/\s+/g, '').length >= 8,
    decode: (s) => binaryDecode(s, true)
  },
  {
    name: 'uudecode',
    kind: 'bytes',
    precheck: (s) => /^begin\s+\d+\s+\S/m.test(s) || /^begin\s/.test(s.trim()),
    decode: (s) => uuDecode(s, true)
  },
  {
    name: 'url',
    kind: 'text',
    // Only meaningful when there is an actual percent-escape; otherwise
    // urlDecode is the identity function and would just cause a self-cycle.
    precheck: (s) => /%[0-9a-fA-F]{2}/.test(s),
    decode: (s) => urlDecode(s)
  },
  {
    name: 'morse',
    kind: 'text',
    precheck: (s) => /[.\-]/.test(s) && /^[.\-/\s]+$/.test(s.trim()),
    decode: (s) => morseDecode(s)
  },
  {
    name: 'rot13',
    kind: 'text',
    involution: true, // rot13(rot13(x)) === x — cycle-detection must catch this
    precheck: (s) => /[a-zA-Z]/.test(s),
    decode: (s) => rot13(s)
  },
  {
    name: 'punycode',
    kind: 'text',
    // Only try when there is an actual xn-- label to decode.
    precheck: (s) => /xn--/i.test(s),
    decode: (s) => toUnicode(s)
  }
];

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

// Fraction of code points that are printable ASCII (or common whitespace).
// Deliberately does NOT count code points > 0x7f: for encoding detection, a
// decode that yields a wall of high-Unicode/CJK code points is almost always
// mis-decoded bytes, not the intended plaintext. Legitimate non-ASCII text is
// still credited separately via the valid-UTF-8 signal.
function printableRatio(text) {
  const cps = Array.from(text);
  if (cps.length === 0) return 0;
  let printable = 0;
  for (const ch of cps) {
    const code = ch.codePointAt(0);
    if ((code >= 0x20 && code <= 0x7e) || code === 0x09 || code === 0x0a || code === 0x0d) {
      printable++;
    }
  }
  return printable / cps.length;
}

// Fraction of alphabetic characters that belong to a recognised common English
// word. Character *coverage* (not token count) is used on purpose: it is not
// fooled by garbage that happens to contain stray single letters (a decode
// full of isolated 'a'/'A' chars would inflate a naive token-count ratio).
// Only words of length >= 2 count as matches for the same reason.
function englishWordRatio(text) {
  const tokens = text.toLowerCase().split(/[^a-z']+/).filter((w) => w.length > 0);
  let letters = 0;
  let matched = 0;
  for (const t of tokens) {
    const word = t.replace(/'/g, '');
    letters += word.length;
    if (word.length >= 2 && COMMON_WORDS.has(word)) matched += word.length;
  }
  return letters === 0 ? 0 : matched / letters;
}

function jsonSignal(text) {
  const t = text.trim();
  if (t.length === 0) return { valid: false, shaped: false };
  const looksShaped = (t[0] === '{' || t[0] === '[') && (t[t.length - 1] === '}' || t[t.length - 1] === ']');
  if (!looksShaped) return { valid: false, shaped: false };
  try {
    JSON.parse(t);
    return { valid: true, shaped: true };
  } catch {
    return { valid: false, shaped: true };
  }
}

function urlSignal(text) {
  const t = text.trim();
  return /^[a-z][a-z0-9+.\-]*:\/\//i.test(t) || /\bhttps?:\/\/\S+/i.test(t);
}

/**
 * Score a candidate decode. Returns { score (0..1), reasons: string[] }.
 * Every signal that fires is recorded in `reasons` — this transparency is a
 * hard requirement: nothing that influenced the score is hidden.
 */
function scoreOutput(text, validUtf8) {
  let score = 0;
  const reasons = [];

  if (validUtf8) {
    score += 0.15;
    reasons.push('valid UTF-8');
  } else {
    reasons.push('not valid UTF-8 (bytes decoded lossily)');
  }

  const pr = printableRatio(text);
  score += 0.25 * pr;
  if (pr >= 0.85) reasons.push(`${Math.round(pr * 100)}% printable ASCII`);
  else reasons.push(`only ${Math.round(pr * 100)}% printable ASCII`);

  const json = jsonSignal(text);
  if (json.valid) {
    score += 0.35;
    reasons.push('parses as valid JSON');
  } else if (json.shaped) {
    score += 0.1;
    reasons.push('JSON-shaped (brackets match) but does not parse');
  }

  if (urlSignal(text)) {
    score += 0.2;
    reasons.push('looks like a URL');
  }

  const eng = englishWordRatio(text);
  if (eng > 0) {
    score += 0.4 * eng;
    reasons.push(`${Math.round(eng * 100)}% common-English word coverage`);
  }

  return { score: Math.min(score, 1), reasons };
}

// "Promise" heuristic used only to order the best-first frontier: how likely a
// node's text is to still be *further-encoded* data worth peeling. Encoded
// blobs (base64/hex/etc.) are fully printable ASCII, so printable ratio is a
// good cheap proxy; garbage (low printable) is unlikely to be a real layer.
function promise(text) {
  return printableRatio(text);
}

// ---------------------------------------------------------------------------
// Hash detection (informational — hashes are one-way, NOT decode candidates)
// ---------------------------------------------------------------------------

const KNOWN_HASH_HEX_LENGTHS = new Set([8, 32, 40, 56, 64, 96, 128]);

function detectHash(input) {
  const clean = input.trim();
  const isBareHex = /^[0-9a-fA-F]+$/.test(clean) && KNOWN_HASH_HEX_LENGTHS.has(clean.length);
  const isCryptFormat = /^\$(2[aby]?|argon2(i|d|id)|1|5|6)\$/.test(clean);
  if (!isBareHex && !isCryptFormat) return null;
  const matches = identifyHash(clean); // reuse existing identifier, no reimplementation
  if (!matches.length || matches[0].confidence === 'none') return null;
  return {
    input: clean,
    matches,
    note:
      'This looks like a one-way hash, not an encoding — it cannot be reversed to ' +
      'plaintext. Shown for identification only.'
  };
}

// ---------------------------------------------------------------------------
// Main engine
// ---------------------------------------------------------------------------

/**
 * @param {string} input - the mystery string
 * @param {object} [options]
 * @param {number} [options.maxDepth=4]     - recursion depth cap (per branch)
 * @param {number} [options.maxAttempts=400]- hard cap on total decode attempts
 * @param {number} [options.maxResults=40]  - cap on returned candidates
 * @returns {{
 *   input: string,
 *   candidates: Array<{path:string[], output:string, score:number,
 *                      reasons:string[], depth:number, validUtf8:boolean}>,
 *   hashInfo: null | {input:string, matches:Array, note:string},
 *   stats: {attempts:number, capHit:boolean, cyclesDetected:number,
 *           maxDepthReached:number, decodersTried:number, elapsedMs:number}
 * }}
 */
export function autoDecode(input, options = {}) {
  const started = (typeof performance !== 'undefined' ? performance.now() : Date.now());
  const maxDepth = Number.isInteger(options.maxDepth) ? options.maxDepth : DEFAULT_DEPTH_CAP;
  const maxAttempts = Number.isInteger(options.maxAttempts) ? options.maxAttempts : DEFAULT_MAX_ATTEMPTS;
  const maxResults = Number.isInteger(options.maxResults) ? options.maxResults : 40;

  const stats = {
    attempts: 0,
    capHit: false,
    cyclesDetected: 0,
    maxDepthReached: 0,
    decodersTried: 0,
    elapsedMs: 0
  };

  const str = typeof input === 'string' ? input : String(input == null ? '' : input);
  const candidates = [];
  const hashInfo = detectHash(str);

  if (str.trim().length === 0) {
    stats.elapsedMs = (typeof performance !== 'undefined' ? performance.now() : Date.now()) - started;
    return { input: str, candidates, hashInfo, stats };
  }

  // Seen-set for cycle detection. Seed with the raw input so an immediate
  // loop-back (e.g. an involution like rot13) is caught on the first return.
  const seen = new Set([str]);

  // Best-first frontier. Ordered by descending promise before each expansion.
  const frontier = [{ text: str, path: [], depth: 0 }];

  while (frontier.length > 0) {
    if (stats.attempts >= maxAttempts) {
      stats.capHit = true;
      break;
    }

    // Rank the frontier so the most promising node is expanded next.
    frontier.sort((a, b) => promise(b.text) - promise(a.text));
    const node = frontier.shift();

    if (node.depth >= maxDepth) continue;

    for (const decoder of DECODERS) {
      if (stats.attempts >= maxAttempts) {
        stats.capHit = true;
        break;
      }
      // Cheap pre-filter — does NOT count as an attempt.
      if (!decoder.precheck(node.text)) continue;

      // This is a real decode attempt against the hard cap.
      stats.attempts++;
      stats.decodersTried++;

      let output;
      let validUtf8;
      try {
        if (decoder.kind === 'bytes') {
          const bytes = decoder.decode(node.text);
          if (!bytes || bytes.length === 0) continue;
          try {
            output = STRICT_UTF8.decode(bytes);
            validUtf8 = true;
          } catch {
            output = bytesToStr(bytes); // lossy fallback for display
            validUtf8 = false;
          }
        } else {
          output = decoder.decode(node.text);
          validUtf8 = true;
        }
      } catch {
        continue; // decoder rejected the input — prune this edge
      }

      if (output == null || output.length === 0) continue;
      if (output === node.text) continue; // identity — no progress

      if (seen.has(output)) {
        stats.cyclesDetected++; // loop back to an already-seen output — stop branch
        continue;
      }
      seen.add(output);

      const path = [...node.path, decoder.name];
      const { score, reasons } = scoreOutput(output, validUtf8);
      candidates.push({ path, output, score, reasons, depth: node.depth + 1, validUtf8 });
      stats.maxDepthReached = Math.max(stats.maxDepthReached, node.depth + 1);

      // Recurse: only worthwhile if it still looks like it could be more data.
      if (node.depth + 1 < maxDepth) {
        frontier.push({ text: output, path, depth: node.depth + 1 });
      }
    }
  }

  // --- Caesar brute-force on the RAW input only (bounded pre-pass) ---------
  // rot13 (shift 13) is already covered recursively above; here we sweep the
  // other 24 shifts on the original input for the classic CTF case. Reuses
  // enc.caesarShift; only surfaces a shift that actually looks like English so
  // we don't flood the results with 24 lines of garbage.
  if (/[a-zA-Z]/.test(str)) {
    for (let shift = 1; shift <= 25; shift++) {
      if (shift === 13) continue; // already produced by the rot13 decoder
      if (stats.attempts >= maxAttempts) {
        stats.capHit = true;
        break;
      }
      stats.attempts++;
      const shifted = caesarShift(str, shift);
      if (shifted === str || seen.has(shifted)) continue;
      const eng = englishWordRatio(shifted);
      const urls = urlSignal(shifted);
      if (eng >= 0.34 || urls) {
        seen.add(shifted);
        const { score, reasons } = scoreOutput(shifted, true);
        candidates.push({
          path: [`caesar (shift ${shift})`],
          output: shifted,
          score,
          reasons,
          depth: 1,
          validUtf8: true
        });
      }
    }
  }

  // Rank: highest score first; tie-break toward the simpler (shorter) path,
  // then the shallower depth — the most parsimonious explanation wins.
  candidates.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    if (a.path.length !== b.path.length) return a.path.length - b.path.length;
    return a.depth - b.depth;
  });

  const trimmed = candidates.slice(0, maxResults);
  stats.elapsedMs = (typeof performance !== 'undefined' ? performance.now() : Date.now()) - started;

  return { input: str, candidates: trimmed, hashInfo, stats };
}

// Exposed for tests and for any UI that wants to show "N decoders available".
export const DECODER_NAMES = DECODERS.map((d) => d.name);
