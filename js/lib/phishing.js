/**
 * Phishing URL heuristic checker — PURE client-side pattern analysis.
 * This is NOT a live blocklist lookup and does not contact any server;
 * it only inspects the URL string structurally: IP-literal hosts,
 * excessive subdomains, punycode/homograph indicators, suspicious
 * keywords, @ symbol tricks, and lookalike-character substitution
 * against a small set of commonly-impersonated brand domains.
 */

const COMMONLY_IMPERSONATED = [
  'google.com', 'paypal.com', 'apple.com', 'microsoft.com', 'amazon.com',
  'facebook.com', 'instagram.com', 'netflix.com', 'bankofamerica.com',
  'chase.com', 'wellsfargo.com', 'github.com', 'linkedin.com'
];

// Common homograph/confusable substitutions (attacker char -> legit char)
const CONFUSABLES = {
  '0': 'o', '1': 'l', '3': 'e', '5': 's', '@': 'a',
  'rn': 'm', 'vv': 'w', 'l': 'i'
};

function isIpLiteral(host) {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) || /^\[[0-9a-fA-F:]+\]$/.test(host);
}

function countSubdomains(host) {
  const parts = host.split('.');
  return Math.max(0, parts.length - 2);
}

function normalizeConfusables(host) {
  let normalized = host.toLowerCase();
  for (const [bad, good] of Object.entries(CONFUSABLES)) {
    normalized = normalized.split(bad).join(good);
  }
  return normalized;
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

const SUSPICIOUS_KEYWORDS = ['login', 'verify', 'account', 'secure', 'update', 'confirm', 'signin', 'banking', 'suspend'];

/**
 * Analyze a URL for phishing heuristics. Returns a risk score (0-100)
 * and the specific reasons that contributed to it. Heuristic only —
 * not a definitive verdict.
 */
export function analyzeUrl(urlStr) {
  const reasons = [];
  let score = 0;

  let url;
  try {
    url = new URL(urlStr.includes('://') ? urlStr : 'http://' + urlStr);
  } catch {
    return { score: 0, risk: 'unknown', reasons: ['Could not parse as a URL.'] };
  }

  const host = url.hostname;

  if (isIpLiteral(host)) {
    score += 30;
    reasons.push('Host is a raw IP address literal rather than a domain name.');
  }

  if (urlStr.includes('@')) {
    score += 25;
    reasons.push('URL contains an "@" symbol — text before it may be a decoy, real host is after.');
  }

  const subCount = countSubdomains(host);
  if (subCount >= 3) {
    score += 20;
    reasons.push(`Host has ${subCount} subdomain levels — unusually deep.`);
  } else if (subCount === 2) {
    score += 8;
    reasons.push('Host has multiple subdomain levels.');
  }

  if (host.split('.').some((label) => label.toLowerCase().startsWith('xn--'))) {
    score += 25;
    reasons.push('Host contains a punycode ("xn--") label — possible homograph/IDN spoofing attempt.');
  }

  const lowerUrl = urlStr.toLowerCase();
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter((k) => lowerUrl.includes(k));
  if (matchedKeywords.length > 0) {
    score += Math.min(20, matchedKeywords.length * 7);
    reasons.push(`Contains suspicious keyword(s): ${matchedKeywords.join(', ')}.`);
  }

  if (host.length > 40) {
    score += 10;
    reasons.push('Unusually long hostname.');
  }

  if ((host.match(/-/g) || []).length >= 3) {
    score += 10;
    reasons.push('Hostname contains many hyphens — common in typosquatting.');
  }

  // Lookalike-domain detection via normalized-confusable Levenshtein distance
  const registrableGuess = host.split('.').slice(-2).join('.');
  const normalized = normalizeConfusables(registrableGuess);
  for (const brand of COMMONLY_IMPERSONATED) {
    if (registrableGuess === brand) continue; // it IS the real domain
    const dist = levenshtein(normalized, brand);
    if (dist > 0 && dist <= 2) {
      score += 35;
      reasons.push(`Domain "${registrableGuess}" closely resembles "${brand}" (edit distance ${dist}) — possible lookalike/typosquat.`);
      break;
    }
  }

  if (url.protocol !== 'https:') {
    score += 5;
    reasons.push('Not using HTTPS.');
  }

  score = Math.min(100, score);
  const risk = score >= 60 ? 'high' : score >= 30 ? 'medium' : score > 0 ? 'low' : 'minimal';

  return { score, risk, reasons: reasons.length ? reasons : ['No obvious heuristic red flags detected.'] };
}
