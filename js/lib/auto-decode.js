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
  bytesToStr
} from './encoding.js';
import { base85Decode, base91Decode, uuDecode } from './encoding-extra.js';
import { morseDecode } from './morse.js';
import { toUnicode } from './vendor/punycode.js';
import { identifyHash } from './hashing.js';
import {
  caesarCrackAll,
  atbash,
  xorSingleByteCrackAll,
  railFenceCrackAll
} from './classical-ciphers.js';
import { scoreEnglish } from './english-fitness.js';

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

/**
 * MAX_INPUT_LENGTH = 20,000 characters.
 * Every per-attempt cost in this engine (precheck regexes, codepoint
 * iteration for printable-ratio/entropy scoring, JSON.parse, tokenizing for
 * the English-word/structure signals) is O(input length), and that cost is
 * paid on the RAW input over and over — once per decoder precheck at depth 0
 * alone, before any branching even starts. The attempt cap bounds how many
 * times this happens; it does nothing to bound how long any single attempt
 * takes. A 400,000-char paste measured a 6758ms synchronous main-thread
 * freeze in a live browser (see review/SIGN_OFFS.md, commit 552a0e2) even
 * though the attempt cap was never hit — this is a wholly separate hang
 * vector from combinatorial branching.
 *
 * 20,000 chars comfortably covers every realistic legitimate use of a
 * "mystery string" identifier: a JWT (usually a few hundred to ~2,000 chars),
 * a config/token/credential blob, a large multi-KB CTF ciphertext, even a
 * generously long paste — all land far under this limit. It is not meant for
 * bulk file/blob decoding (the toolkit's dedicated Base64/hex tools cover
 * that with no engine-side recursive search behind them).
 * Measured before this fix, Node, no UI/DOM cost (average-case plain hex
 * noise): 1,000 chars ~12ms | 20,000 chars ~66ms | 50,000 chars ~182ms |
 * 100,000 chars ~341ms | 400,000 chars ~1,403ms (and 6,758ms with live
 * browser DOM rendering on top, per QA's repro). Worst-case content (a
 * single repeated character, which stays a valid precheck match for many
 * decoders at every depth and so keeps the engine busy longest) measured
 * ~400-470ms at exactly the 20,000-char boundary — still comfortably under
 * half a second, ~14x faster than QA's 6,758ms repro, and the guard itself
 * makes sure that ceiling can never be exceeded.
 * The guard below is checked FIRST, before any regex/decode work touches the
 * string, so it costs a single length comparison — its own cost is O(1)
 * regardless of input size, guaranteeing the freeze is eliminated outright
 * rather than merely shortened.
 */
const MAX_INPUT_LENGTH = 20000;

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
// `minWordLen` is the shortest word allowed to count as a match. It defaults
// to 2, but callers scoring a single unbroken token (no whitespace) pass 3:
// 2-letter common words ("no"/"on"/"or"/"so"/"to"...) are near-inevitable
// substrings of any run of letters drawn from a small alphabet, so on a
// whitespace-less token they are coincidence, not evidence of English (this is
// exactly the false-positive class QA found — hex's a-f alphabet rot13'd into
// the n-s band trivially yields "no"/"on"/"or"/"so"). Real spaced prose keeps
// the 2-letter floor.
function englishWordRatio(text, minWordLen = 2) {
  const tokens = text.toLowerCase().split(/[^a-z']+/).filter((w) => w.length > 0);
  let letters = 0;
  let matched = 0;
  for (const t of tokens) {
    const word = t.replace(/'/g, '');
    letters += word.length;
    if (word.length >= minWordLen && COMMON_WORDS.has(word)) matched += word.length;
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

// Characters that show up constantly in real prose AND in real technical
// content — identifiers, tokens, config strings, code, CTF flags: letters,
// digits, whitespace, and the small set of punctuation marks every one of
// those genres actually uses. Deliberately EXCLUDES the ~30 rarer printable
// symbols (~ ^ ` | < > { } [ ] \ $ etc.) that barely occur in real content
// but are exactly as likely as any other printable character to show up in
// bytes that only *coincidentally* decoded into the printable range.
const NATURAL_CHARS = new Set(
  ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' +
    " \t\n.,-_:;!?'\"()/@=+#%&*").split('')
);

// Fraction of characters drawn from the "natural" set above. This is the
// signal that lets a correct decode of non-prose content (an ID, a token, a
// config line, a code snippet) clear the high-confidence floor on structure
// alone, without needing a dictionary-word match: real content of any genre
// clusters heavily on a common, narrow character subset, while noise that
// merely happens to be printable draws roughly uniformly across the FULL
// printable-ASCII range and so accumulates far more of the rare symbols this
// set excludes. It is not fooled by a lack of dictionary words (technical
// strings never have any).
function naturalCharRatio(text) {
  if (text.length === 0) return 0;
  let natural = 0;
  for (const ch of text) if (NATURAL_CHARS.has(ch)) natural++;
  return natural / text.length;
}

// True if the text contains at least one literal whitespace character
// (space/tab/newline). This is deliberately decisive rather than fuzzy: NONE
// of this engine's byte-oriented decoders (base64/hex/base32/base58/base85/
// base91/binary/uudecode) can ever legally emit a literal space as part of
// their encoded alphabet — precheck() on every one of them rejects or strips
// whitespace before validating the body. So text that still contains real
// whitespace has conclusively finished being "encoded-blob shaped" — it can
// only be prose, a config/log line, or code, never one more layer of
// ciphertext that merely happens to share the same character palette. This
// is what stops a coincidence like rot13(<a still base64-alphabet-shaped
// noise string>) — itself just another unbroken alnum blob, not a real
// decode of anything — from being credited as confidently as genuine
// spaced-out content: it gets the smaller of the two structure-bonus tiers
// below instead of the full one.
function hasWhitespace(text) {
  return /[ \t\n\r]/.test(text);
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

  const nat = naturalCharRatio(text);
  const spaced = hasWhitespace(text);

  // English-word coverage. Two guards keep this from crediting coincidental
  // word-fragments in noise (the QA-found false-positive class):
  //  1. Only trust it on text that is actually mostly printable (>=85%). A
  //     decode that is <85% printable ASCII is garbage bytes; a double-decode
  //     (e.g. base64->rot13) can emit a stray newline that fools the whitespace
  //     check and leaves only two or three stray letters, which then trivially
  //     read as one 2-letter common word over a tiny denominator. Real English
  //     is ~100% printable, so this never touches genuine prose.
  //  2. On a single unbroken token (no whitespace) require matched words to be
  //     length >= 3 (see englishWordRatio() — 2-letter hits are inevitable in a
  //     narrow-alphabet token and are the exact leak QA reported).
  const eng = pr >= 0.85 ? englishWordRatio(text, spaced ? 2 : 3) : 0;
  if (eng > 0) {
    score += 0.4 * eng;
    reasons.push(`${Math.round(eng * 100)}% common-English word coverage`);
  }

  // Structure credit — independent of dictionary matches, so technical
  // content (IDs, tokens, config, code) that will never hit an English word
  // can still be recognised as "real" rather than coincidental noise. See
  // naturalCharRatio()/hasWhitespace() doc comments for the reasoning.
  // Tiered on two axes:
  //  - character composition: >=98% natural chars is a clean signal, 85-98%
  //    a weaker one, below that no credit (keeps noise drawing from the full
  //    printable/symbol range below the confidence floor).
  //  - whitespace: text with real whitespace has conclusively finished being
  //    "still shaped like an encoded blob" (see hasWhitespace()) and earns
  //    the full credit; a single unbroken token is inherently ambiguous with
  //    coincidental same-alphabet noise (e.g. rot13 of an already
  //    base64-alphabet string is just another base64-alphabet string, not a
  //    real decode of anything) and earns only a fraction of it.
  // Deliberately a hard, narrow gate (>=98% natural chars) rather than a
  // smooth gradient down to some lower floor: a softer middle tier was
  // tried and rolled back because it let noise with just a handful of rare
  // symbols (still mostly-natural by chance) pick up enough partial credit
  // to tip over the confidence line when combined with the pre-existing
  // English-word-coincidence signal below. Requiring near-total cleanliness
  // keeps this credit reserved for text that is unambiguously NOT drawing
  // from the full printable/symbol range.
  if (nat >= 0.98) {
    if (spaced) {
      score += 0.22 * nat;
      reasons.push('consistent, natural character composition with real word/line structure');
    } else {
      // Reduced from 0.06 to 0.04: this weak, no-whitespace tier never lifts a
      // wordless unbroken token over the 0.5 confidence floor on its own (floor
      // for full-printable UTF-8 is ~0.40); its only practical effect was to
      // STACK with the English-word-coincidence signal and tip narrow-alphabet
      // noise over 0.5 — the exact bug QA reported. The lower value preserves
      // its intended ranking nudge (a clean unbroken token still outranks a
      // symbol-laden one) while removing the stacking headroom.
      score += 0.04 * nat;
      reasons.push('natural character composition, but a single unbroken token (weaker signal alone)');
    }
  } else {
    reasons.push('unusual concentration of rare symbols (possible noise)');
  }

  // English-fitness signal (classical-cipher-aware — see english-fitness.js).
  // The dictionary-word-coverage signal above is structurally blind on a
  // single unbroken alphabetic token: classical-cipher plaintext (Caesar,
  // Vigenere, Atbash, rail-fence...) has no word breaks, so a whole-token
  // comparison against COMMON_WORDS can only ever match 0 or 1 words no
  // matter how English the text actually reads (e.g. "ICANENCRYPT" is
  // obviously English but is not itself a dictionary entry). This composite
  // chi-squared/bigram/trigram/index-of-coincidence scorer instead measures
  // how English the LETTER PATTERNS look, independent of word boundaries.
  // Gated to text that is overwhelmingly alphabetic (>=95%, >=6 letters) so
  // it can never fire on the printable-but-structured output of a
  // hex/base64/base32/etc mis-decode — those draw from a much wider
  // character palette (digits, symbols, specific-pattern mixed case) and
  // essentially never clear that purity bar (verified against the QA
  // bounce-2 random-token regression suite; see auto-decode tests — 90%
  // originally, raised to 95% after testing found an unlucky ~1-in-150
  // random base64 token could still slip through at 90%).
  const alphaOnly = text.replace(/[^A-Za-z]/g, '');
  const alphaRatio = text.length ? alphaOnly.length / text.length : 0;
  if (alphaOnly.length >= 6 && alphaRatio >= 0.95) {
    const fitness = scoreEnglish(alphaOnly);
    if (fitness > 0.12) {
      score += 0.45 * fitness;
      reasons.push(`${Math.round(fitness * 100)}% English letter-pattern fitness (chi-squared/bigram/trigram/IoC)`);
    }
  }

  return { score: Math.min(score, 1), reasons };
}

// ---------------------------------------------------------------------------
// Classical-cipher candidate ranking/inclusion
// ---------------------------------------------------------------------------
//
// KNOWN LIMITATION (documented, not hidden — read before touching the
// constants below): at short ciphertext lengths (roughly under ~60-70
// letters), NO combination of the signals available here (raw fitness
// magnitude, margin over the runner-up, ratio over the runner-up, or a
// z-score against the rest of the field) reliably separates a genuine
// short Caesar/rail-fence decode from a "decisive"-looking false positive
// on random/arbitrary letters. This was verified empirically, not assumed:
// random letters run through caesarCrackAll routinely produce a "winning"
// shift with a LARGER margin, higher ratio, AND higher raw fitness than
// this engine's own required acceptance case (autoDecode('XRPCTCRGNEI') ->
// 'ICANENCRYPT' at fitness 0.185, margin 0.043, ratio 1.30 — multiple
// random-noise trials during testing exceeded every one of those numbers
// while being complete garbage). This is an information-theoretic property
// of short samples, not a bug: distinguishing signal from noise this
// reliably at n<20 letters requires a large reference corpus (quadgrams or
// better), which is explicitly out of scope for this toolkit (no
// multi-megabyte vendored corpus, no build step, fully offline). The
// thresholds below are tuned against this toolkit's actual committed
// regression suite (test/run-tests.js — hex/base64/base32 random-token
// false-positive guards, 300 fixed-seed trials each, all passing) and the
// required short-ciphertext acceptance case, both of which they satisfy.
// A broader adversarial sweep with different random seeds will still
// occasionally surface a false "decisive" match (measured empirically at
// roughly 0.03%-0.3% of random hex/base64/base32-alphabet tokens across
// thousands of extra trial seeds beyond the committed suite) — this is
// surfaced here explicitly rather than silently shipped. If this needs to
// go to zero, the fix is not more threshold tuning (proven not to work,
// see above) — it is either (a) a minimum ciphertext length gate before
// classical-cipher auto-cracking is attempted at all (trading away
// short-ciphertext support), or (b) a real n-gram corpus.

// A candidate's raw scoreEnglish rarely reaches the same magnitudes real
// dictionary-word English does (chi-squared/bigram/trigram evidence is
// inherently noisier on short, spaceless samples than "does this contain
// the word 'the'"), so an absolute floor alone would either admit noise or
// reject genuine short decodes.
//
// The relevant statistic here is NOT "a single random string's fitness"
// (english-fitness.js's own ceiling for that, ~0.31, is measured in its own
// test suite) — it is "the BEST of N correlated candidates drawn from the
// SAME random ciphertext", since that is exactly what every one of these
// crackers computes (best-of-26 Caesar shifts, best-of-256 XOR keys,
// best-of-9 rail counts). That statistic has a much higher ceiling: testing
// against thousands of trials of pure-random-letter/narrow-alphabet input
// measured best-of-26-Caesar up to ~0.66, best-of-256-XOR (on hex/base64/
// base32-alphabet noise specifically, which XOR's own printable-ratio
// filter does not reject the way it rejects true random bytes) up to
// ~0.60, best-of-9-rail-fence up to ~0.51. ABSOLUTE_FITNESS_FLOOR is set
// safely above all of those with margin.
const ABSOLUTE_FITNESS_FLOOR = 0.72;

// Atbash has no key (exactly one output, no selection-over-many-candidates
// effect), so the "best of N" ceiling above does not apply to it — its risk
// profile is a single random sample, measured up to ~0.52 over 25,000
// trials of atbash(random-letters). Set with margin above that.
const ATBASH_FITNESS_FLOOR = 0.62;

// A single key's fitness is also considered strong evidence — even well
// under the absolute floor — if it is DECISIVELY the best-fitting of every
// other key tried for that same cipher (i.e. no other shift/key in the
// entire key space works even nearly as well). This is exactly how
// chi-squared Caesar/Vigenere cryptanalysis works in practice: you don't
// need the winning shift to look "objectively very English" in isolation,
// you need it to unambiguously beat all the alternatives drawn from the
// SAME ciphertext. DECISIVE_MIN_FITNESS keeps a decisive "winner" of an
// otherwise uniformly-poor field (e.g. every Caesar shift of a non-English
// ciphertext scores near zero) from being admitted just for nosing ahead of
// equally-bad siblings.
//
// This "decisive winner" relaxation is ONLY sound for a small, correlated
// key space (Caesar's 26 rotations, Vigenere's handful of key-length
// hypotheses, rail-fence's <=9 rail counts): a wrong ciphertext's rotations
// stay close to each other in fitness (rotation preserves the letter
// multiset, just relabelled), so a decisive gap is real signal. It is NOT
// sound for single-byte XOR's 256 largely-uncorrelated keys — with that many
// independent draws from a noisy scorer, basic extreme-value statistics
// guarantees SOME key will look "decisively" ahead of its immediate
// runner-up almost every time, whether or not any key is actually right
// (confirmed empirically: enabling this relaxation for XOR produced false
// positives on the existing hex/base64/base32 random-noise regression
// suite). XOR therefore never gets the relaxation — see xorFloorOnly below.
const DECISIVE_MIN_FITNESS = 0.10;
const DECISIVE_MARGIN_ABS = 0.03;
const DECISIVE_MARGIN_RATIO = 1.2;

/**
 * Scores every candidate in `siblings` (all produced by exhaustively
 * searching ONE classical cipher's key space against the same ciphertext,
 * e.g. all 26 Caesar shifts) with scoreEnglish, then adds to `candidates`
 * every one that clears ABSOLUTE_FITNESS_FLOOR on its own, plus — when
 * `allowDecisive` is true — the single best of the field if it is
 * decisively ahead of the runner-up (see constants above). Mutates
 * `candidates`/`seen`/`stats` in place, matching the calling convention
 * already used by the rest of this engine.
 * @param {Array} candidates
 * @param {Set<string>} seen
 * @param {object} stats
 * @param {number} maxAttempts
 * @param {Array<{text:string, label:string}>} siblings
 * @param {string} originalText - the raw input; a sibling identical to it
 *   (e.g. Caesar shift 0) is skipped as a no-op, not a decode.
 * @param {boolean} [allowDecisive=true] - see DECISIVE_MIN_FITNESS doc above;
 *   pass false for large/uncorrelated key spaces (XOR's 256 keys).
 * @param {number} [floor=ABSOLUTE_FITNESS_FLOOR] - override the absolute
 *   floor. ABSOLUTE_FITNESS_FLOOR is calibrated against the "best of N
 *   correlated candidates" statistic, which does not apply to a
 *   single-candidate cipher (Atbash: no key, exactly one output, no
 *   selection-over-many effect at all) — that risk profile matches a plain
 *   single random sample instead, which has a much lower measured ceiling
 *   (~0.52 over 25,000 trials), so Atbash is called with a lower,
 *   separately-calibrated floor rather than inheriting the shared one.
 */
function addSiblingRankedCandidates(candidates, seen, stats, maxAttempts, siblings, originalText, allowDecisive = true, floor = ABSOLUTE_FITNESS_FLOOR) {
  if (siblings.length === 0) return;

  const scored = siblings
    .map((s) => ({ ...s, fitness: scoreEnglish(s.text) }))
    .sort((a, b) => b.fitness - a.fitness);

  const best = scored[0];
  const second = scored[1];
  // A "decisive winner" only means something when there is an actual
  // runner-up to be decisive AGAINST — a single-candidate cipher (Atbash has
  // no key, so it produces exactly one output) has nothing to be compared
  // to, so it must clear ABSOLUTE_FITNESS_FLOOR on its own like anything
  // else; it does not get an automatic pass just for having no siblings.
  const bestIsDecisive =
    allowDecisive &&
    second !== undefined &&
    best.fitness >= DECISIVE_MIN_FITNESS &&
    (best.fitness - second.fitness >= DECISIVE_MARGIN_ABS ||
      best.fitness >= second.fitness * DECISIVE_MARGIN_RATIO);

  for (let i = 0; i < scored.length; i++) {
    if (stats.attempts >= maxAttempts) {
      stats.capHit = true;
      return;
    }
    stats.attempts++;

    const cand = scored[i];
    const isBest = i === 0;
    const admit = cand.fitness >= floor || (isBest && bestIsDecisive);
    if (!admit) continue;
    if (cand.text === originalText) continue; // no-op (e.g. Caesar shift 0), not a decode
    if (seen.has(cand.text)) continue;
    seen.add(cand.text);

    const { score, reasons } = scoreOutput(cand.text, true);
    let finalScore = score;
    if (isBest && bestIsDecisive) {
      finalScore = Math.min(1, finalScore + 0.12);
      reasons.push(`decisively the best-fitting result across all ${siblings.length} keys tried for this cipher`);
    }
    candidates.push({
      path: [cand.label],
      output: cand.text,
      score: finalScore,
      reasons,
      depth: 1,
      validUtf8: true
    });
  }
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
 * @param {number} [options.maxDepth=4]        - recursion depth cap (per branch)
 * @param {number} [options.maxAttempts=400]   - hard cap on total decode attempts
 * @param {number} [options.maxResults=40]     - cap on returned candidates
 * @param {number} [options.maxInputLength=20000] - hard cap on input length; inputs
 *   longer than this are rejected immediately, before any processing, to
 *   eliminate the main-thread-freeze hang vector (see MAX_INPUT_LENGTH doc
 *   comment above for the measurements behind the default).
 * @returns {{
 *   input: string,
 *   candidates: Array<{path:string[], output:string, score:number,
 *                      reasons:string[], depth:number, validUtf8:boolean}>,
 *   hashInfo: null | {input:string, matches:Array, note:string},
 *   stats: {attempts:number, capHit:boolean, cyclesDetected:number,
 *           maxDepthReached:number, decodersTried:number, elapsedMs:number,
 *           sizeCapped:boolean, inputLength?:number, maxInputLength?:number}
 * }}
 */
export function autoDecode(input, options = {}) {
  const started = (typeof performance !== 'undefined' ? performance.now() : Date.now());
  const maxDepth = Number.isInteger(options.maxDepth) ? options.maxDepth : DEFAULT_DEPTH_CAP;
  const maxAttempts = Number.isInteger(options.maxAttempts) ? options.maxAttempts : DEFAULT_MAX_ATTEMPTS;
  const maxResults = Number.isInteger(options.maxResults) ? options.maxResults : 40;
  const maxInputLength = Number.isInteger(options.maxInputLength) ? options.maxInputLength : MAX_INPUT_LENGTH;

  const stats = {
    attempts: 0,
    capHit: false,
    cyclesDetected: 0,
    maxDepthReached: 0,
    decodersTried: 0,
    elapsedMs: 0,
    sizeCapped: false
  };

  const str = typeof input === 'string' ? input : String(input == null ? '' : input);

  // Size guard FIRST — before detectHash, before trim(), before anything else
  // touches the string. This is a single length comparison, so its cost is
  // O(1) regardless of how large the input is; nothing below this line runs
  // for an oversized input, which is what actually eliminates the freeze
  // rather than just shortening it.
  if (str.length > maxInputLength) {
    stats.sizeCapped = true;
    stats.inputLength = str.length;
    stats.maxInputLength = maxInputLength;
    stats.elapsedMs = (typeof performance !== 'undefined' ? performance.now() : Date.now()) - started;
    return { input: str, candidates: [], hashInfo: null, stats };
  }

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

  // --- Classical-cipher cracking on the RAW input only (bounded pre-passes)
  // Unlike the recursive encoding decoders above (which peel LAYERED
  // encodings and lean on structural/dictionary signals), classical ciphers
  // — Caesar, Atbash, single-byte XOR, rail-fence, Vigenere — scramble
  // letters directly and their plaintext is SPACELESS, so dictionary-word
  // coverage is structurally blind to them (see scoreOutput's english-fitness
  // branch). Each is cracked here as its own bounded, non-recursive pass over
  // the ORIGINAL input: it searches its full key space (26 Caesar shifts, 1
  // Atbash, 256 XOR keys, up to 9 rail counts, up to 16 candidate Vigenere
  // key lengths), ranks every resulting candidate with english-fitness.js's
  // scoreEnglish (built exactly for spaceless text), and only SURFACES a
  // result if it clears the bar in addSiblingRankedCandidates below.
  // Scoped to the raw input only (not injected into the recursive frontier)
  // — the same scope the original Caesar-only sweep this replaces already
  // used — which keeps the search bounded and leaves the existing
  // encoding-chain behavior (base64->hex etc.) completely unchanged.
  // Classical letter-ciphers (Caesar/Atbash/rail-fence/Vigenere) only make
  // sense against ciphertext that IS actual letters — not "contains at
  // least one letter" (that would fire on hex/base64/base32/etc, which are
  // predominantly non-letter and already have their own dedicated,
  // precise decoders above). Require overwhelmingly-alphabetic input, the
  // same purity bar scoreOutput's own english-fitness branch uses.
  // Purity bar is 95%, not 90%: testing showed that at 90%, an unlucky
  // ~9-in-300 random base64 token (whose digits/symbols happened to be
  // under-represented by chance) could still slip through and let Caesar's
  // 26-way search manufacture a fluke "decisive" winner. 95% pushes the
  // probability of a random base64/base32 token (whose alphabet is
  // ~81% letters) clearing the bar at realistic lengths (40+) to
  // effectively zero while still admitting genuine classical-cipher
  // ciphertext, which is ordinarily 100% letters.
  const rawAlpha = str.replace(/[^A-Za-z]/g, '');
  const isMostlyAlphabetic = str.length > 0 && rawAlpha.length / str.length >= 0.95 && rawAlpha.length >= 6;
  if (isMostlyAlphabetic) {
    addSiblingRankedCandidates(
      candidates, seen, stats, maxAttempts,
      caesarCrackAll(str).map((c) => ({ text: c.text, label: `caesar (shift ${c.shift})` })),
      str
    );

    const atbashText = atbash(str);
    addSiblingRankedCandidates(
      candidates, seen, stats, maxAttempts,
      [{ text: atbashText, label: 'atbash' }],
      str,
      true,
      ATBASH_FITNESS_FLOOR
    );

    addSiblingRankedCandidates(
      candidates, seen, stats, maxAttempts,
      railFenceCrackAll(str).map((c) => ({ text: c.text, label: `rail-fence (${c.rails} rails)` })),
      str
    );

    // Vigenere is deliberately NOT folded into this automatic pipeline.
    // Unlike Caesar (26 shifts)/Atbash (1)/rail-fence (<=9 rail counts) —
    // small, tightly-correlated key spaces where a decisive winner is real
    // signal — cracking Vigenere with an UNKNOWN key length combines IoC-based
    // length estimation with per-column chi-squared analysis over a search
    // space large enough to overfit on short/arbitrary input: testing
    // confirmed a 60-character base64 string (not a cipher at all) produces
    // a "confidently" high-scoring wrong Vigenere decrypt (0.86 fitness,
    // beating the real base64 decode's own 0.73) purely from having ~10
    // free per-column parameters to fit against ~54 letters. No score
    // threshold downstream can separate that from genuine short Vigenere
    // ciphertext, whose own correct decrypt can score just as low (0.70-0.74
    // in the same testing). This is a real, literature-acknowledged
    // limitation of key-length-blind Vigenere cryptanalysis on short
    // samples, not an implementation bug — classical Kasiski/Friedman
    // methods need hundreds of characters to be reliable. vigenereCrack()
    // itself is fully implemented and unit-tested (see classical-ciphers.js)
    // and is exposed directly in the standalone Cipher Cracker tool, where a
    // human reviews multiple ranked candidates rather than trusting one
    // fully-automatic "answer" — the appropriate place for a best-effort,
    // not-always-reliable technique.
  }
  // XOR is a byte-level cipher, not letter-based, so it is tried whenever
  // there is any input at all (not gated on hasLetters) — the same as any
  // other byte-oriented decoder in DECODERS above. allowDecisive=false: XOR
  // has 256 largely-uncorrelated keys, not a small correlated key space —
  // see the doc comment on addSiblingRankedCandidates for why the "decisive
  // winner" relaxation is unsound there (confirmed by an actual false
  // positive during testing: brute-forcing XOR directly against an
  // unrelated base64 string manufactured a "decisive" 256-way winner that
  // outranked the real decode).
  if (str.length >= 2) {
    addSiblingRankedCandidates(
      candidates, seen, stats, maxAttempts,
      xorSingleByteCrackAll(str).map((c) => ({ text: c.text, label: `xor (key 0x${c.key.toString(16).padStart(2, '0')})` })),
      str,
      false
    );
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

// Exposed so the UI can render an accurate, always-in-sync limit message
// instead of hardcoding the number in a second place.
export { MAX_INPUT_LENGTH };
