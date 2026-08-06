/**
 * Password crack-time estimation and human-readable strength verdicts.
 *
 * Pure logic — takes an entropy value (in bits) and returns, for a range of
 * realistic attacker capabilities, how long an average brute-force search
 * would take, plus a plain-English verdict and vivid real-world comparison.
 * No password value is ever needed here (entropy is a property of the
 * generator's settings, not the specific string), and nothing touches the
 * network. All arithmetic is done in log10 space so arbitrarily strong
 * passwords never overflow to Infinity.
 *
 * The model, deliberately kept honest:
 *   - Average-case work is HALF the keyspace: 2^(bits-1) guesses.
 *   - "Crack time" for a tier = 2^(bits-1) / (guesses per second).
 *   - This is a pure brute-force / exhaustive-search estimate. For a
 *     RANDOM password (which is all this generator produces) that is the
 *     right model — there is no smarter attack than trying keys, so a
 *     wordlist/dictionary attack is strictly worse for the attacker, not
 *     better. (This estimator is therefore NOT valid for human-chosen
 *     passwords, where dictionary/pattern attacks dominate; it is only
 *     applied to the crypto-random output of the generator.)
 */

// ---------------------------------------------------------------------------
// Attacker capability tiers. Rates are guesses/second — chosen to be
// defensible and to tell a story about WHO is attacking and HOW, rather
// than an abstract number. Ordered weakest attacker -> strongest.
// ---------------------------------------------------------------------------
export const ATTACKER_TIERS = [
  {
    id: 'online',
    icon: '\u{1F511}',                       // key
    name: 'Online guessing at a login form',
    detail: 'Someone hammering the login screen with a script. The server fights back — rate limits and lockouts hold this to a crawl.',
    guessesPerSecond: 10
  },
  {
    id: 'bcrypt-gpu',
    icon: '\u{1F4A7}',                       // droplet (slow)
    name: 'Your leaked hash, slow algorithm (bcrypt), one GPU',
    detail: 'The site got breached but hashed passwords properly. One graphics card grinds through the stolen hash.',
    guessesPerSecond: 1e4
  },
  {
    id: 'fast-rig',
    icon: '\u{1F5A5}\u{FE0F}',               // desktop computer
    name: 'Your leaked hash, fast algorithm (MD5/NTLM), GPU rig',
    detail: 'Breached site hashed carelessly. Eight high-end GPUs in parallel — this is the realistic serious attacker.',
    guessesPerSecond: 1e12
  },
  {
    id: 'nation-state',
    icon: '\u{1F6F0}\u{FE0F}',               // satellite
    name: 'Nation-state supercomputer, best case for the attacker',
    detail: 'A quintillion guesses every second — wildly generous, an upper bound on what physics itself allows.',
    guessesPerSecond: 1e18
  }
];

// The realistic "serious attacker" whose crack time drives the verdict band.
export const REFERENCE_TIER_ID = 'fast-rig';

const LOG10_2 = Math.log10(2);
const YEAR_SECONDS = 31557600;                 // Julian year
const UNIVERSE_AGE_YEARS = 13.8e9;             // ~13.8 billion years
const UNIVERSE_AGE_SECONDS = UNIVERSE_AGE_YEARS * YEAR_SECONDS;
const LOG10_UNIVERSE_AGE_SECONDS = Math.log10(UNIVERSE_AGE_SECONDS);

/**
 * Average-case crack time, returned as log10(seconds) to stay finite for
 * any entropy. Pure.
 */
export function crackTimeLog10Seconds(entropyBits, guessesPerSecond) {
  // seconds = 2^(bits-1) / rate  ->  log10 = (bits-1)*log10(2) - log10(rate)
  return (entropyBits - 1) * LOG10_2 - Math.log10(guessesPerSecond);
}

const TIME_UNITS = [
  ['second', 1],
  ['minute', 60],
  ['hour', 3600],
  ['day', 86400],
  ['month', 2629800],
  ['year', YEAR_SECONDS]
];

/**
 * Turn a log10(seconds) duration into a vivid, human-readable string.
 * Scales from "instantly" up through years, then anchors enormous values
 * to the age of the universe, and finally to bare orders of magnitude.
 * Pure.
 */
export function humanizeLog10Seconds(log10s) {
  if (!Number.isFinite(log10s)) return 'effectively forever';
  if (log10s < 0) return 'instantly';         // < 1 second

  const seconds = Math.pow(10, log10s);

  // Sub-year: pick the largest whole unit that fits.
  if (log10s < Math.log10(YEAR_SECONDS)) {
    let chosen = TIME_UNITS[0];
    for (const unit of TIME_UNITS) {
      if (seconds >= unit[1]) chosen = unit; else break;
    }
    const val = Math.max(1, Math.round(seconds / chosen[1]));
    return `${val.toLocaleString('en-US')} ${chosen[0]}${val === 1 ? '' : 's'}`;
  }

  // Years, up to a thousand: show the number.
  const log10Years = log10s - Math.log10(YEAR_SECONDS);
  if (log10Years < 3) {
    const years = Math.round(Math.pow(10, log10Years));
    return `${years.toLocaleString('en-US')} years`;
  }

  // Thousands to billions of years: readable magnitude words.
  if (log10Years < 6) return `${Math.round(Math.pow(10, log10Years) / 1e3).toLocaleString('en-US')} thousand years`;
  if (log10Years < 9) return `${Math.round(Math.pow(10, log10Years) / 1e6).toLocaleString('en-US')} million years`;

  // Past a billion years, anchor to the age of the universe.
  const universesLog10 = log10s - LOG10_UNIVERSE_AGE_SECONDS;
  if (universesLog10 < 6) {
    const universes = Math.round(Math.pow(10, universesLog10));
    if (universes <= 1) return 'longer than the universe has existed';
    return `${universes.toLocaleString('en-US')}× the age of the universe`;
  }
  // Absurdly large: bare order of magnitude of "universe lifetimes".
  return `10^${Math.round(universesLog10)}× the age of the universe`;
}

/**
 * A single real-world comparison that makes the strongest realistic-attacker
 * time tangible. Pure. `log10s` is the crack time at the reference tier.
 */
export function realWorldAnchor(log10s) {
  if (!Number.isFinite(log10s) || log10s < 0) return 'gone before you finish reading this';
  const map = [
    [Math.log10(60), 'less time than a coffee break'],
    [Math.log10(3600), 'the length of a lunch break'],
    [Math.log10(86400), 'about a day'],
    [Math.log10(2629800), 'a few weeks'],
    [Math.log10(YEAR_SECONDS), 'roughly a year'],
    [Math.log10(YEAR_SECONDS * 80), 'a human lifetime'],
    [Math.log10(YEAR_SECONDS * 5000), 'longer than recorded human history'],
    [Math.log10(YEAR_SECONDS * 300000), 'longer than our species has existed'],
    [LOG10_UNIVERSE_AGE_SECONDS, 'longer than the age of the universe']
  ];
  for (const [threshold, phrase] of map) {
    if (log10s < threshold) return phrase;
  }
  return 'far, far longer than the age of the universe';
}

// ---------------------------------------------------------------------------
// Verdict bands. Thresholds are entropy in bits; the phrasing is written to
// match the crack time a serious GPU rig (the reference tier) would need, so
// the words and the numbers always agree.
// ---------------------------------------------------------------------------
const BANDS = [
  {
    max: 35, id: 'catastrophic', icon: '☠️', label: 'Catastrophic',
    headline: 'Cracked instantly.',
    message: 'A basic wordlist or a single old laptop would have this in under a second. Never protect anything real with a password this weak.'
  },
  {
    max: 49, id: 'critical', icon: '⚠️', label: 'Critical',
    headline: 'Barely a speed bump.',
    message: 'If the site is ever breached, an attacker with one graphics card cracks this in {ref}. Add length and more character types.'
  },
  {
    max: 59, id: 'weak', icon: '\u{1F7E0}', label: 'Weak',
    headline: 'Falls fast under real pressure.',
    message: 'Okay for a throwaway account, but a GPU rig would get there in {ref}. Push the length up before using this anywhere that matters.'
  },
  {
    max: 69, id: 'fair', icon: '\u{1F7E1}', label: 'Fair',
    headline: 'Solid for everyday accounts.',
    message: 'A determined attacker with a GPU rig would need {ref} — fine for everyday accounts. Go longer for email, banking, or anything you can’t afford to lose.'
  },
  {
    max: 79, id: 'strong', icon: '\u{1F7E2}', label: 'Strong',
    headline: 'A hard target.',
    message: 'Even a serious GPU rig would grind for {ref} — {anchor}. This properly protects real accounts.'
  },
  {
    max: 99, id: 'very-strong', icon: '\u{1F4AA}', label: 'Very strong',
    headline: 'Serious protection.',
    message: 'A GPU rig would need {ref} to break this — {anchor}. You are comfortably ahead of any realistic attacker.'
  },
  {
    max: Infinity, id: 'fortress', icon: '\u{1F6E1}️', label: 'Fortress',
    headline: 'This cannot be brute-forced.',
    message: 'Even a nation-state supercomputer guessing a quintillion times a second would still be at it {nation} from now — {anchor}. Your data is genuinely, mathematically safe here. Nicely done. \u{1F389}'
  }
];

/** Pick the verdict band for a given entropy. Pure. */
export function verdictBand(entropyBits) {
  return BANDS.find((b) => entropyBits <= b.max) || BANDS[BANDS.length - 1];
}

/**
 * Full strength assessment for a given entropy: the per-tier crack times,
 * the chosen verdict band with its message fully interpolated, a 0..1 bar
 * fill, and the reference/nation-state human times. Pure and network-free.
 *
 * The bar fills linearly with entropy and saturates at 128 bits (a 128-bit
 * random key is the conventional "unbreakable" ceiling — beyond it the bar
 * is simply full).
 */
export function assessStrength(entropyBits) {
  const bits = Number.isFinite(entropyBits) && entropyBits > 0 ? entropyBits : 0;

  const tiers = ATTACKER_TIERS.map((t) => {
    const log10s = crackTimeLog10Seconds(bits, t.guessesPerSecond);
    return {
      id: t.id,
      icon: t.icon,
      name: t.name,
      detail: t.detail,
      log10Seconds: log10s,
      human: humanizeLog10Seconds(log10s)
    };
  });

  const refTier = tiers.find((t) => t.id === REFERENCE_TIER_ID);
  const nationTier = tiers.find((t) => t.id === 'nation-state');
  const band = verdictBand(bits);
  const anchor = realWorldAnchor(refTier.log10Seconds);

  const message = band.message
    .replace('{ref}', refTier.human)
    .replace('{nation}', nationTier.human)
    .replace('{anchor}', anchor);

  return {
    entropyBits: Math.round(bits * 10) / 10,
    band: { id: band.id, icon: band.icon, label: band.label, headline: band.headline, message },
    barFill: Math.max(0, Math.min(1, bits / 128)),
    tiers,
    referenceTierId: REFERENCE_TIER_ID
  };
}
