/**
 * Email-authentication DNS TXT record tools: SPF (RFC 7208), DKIM
 * (RFC 6376), DMARC (RFC 7489), and BIMI parsing/lookup, plus a pure
 * DMARC record generator.
 *
 * All four lookups are plain DNS TXT queries — same public, no-key
 * Google DNS-over-HTTPS JSON API (dns.google) the DNS Lookup / WHOIS
 * tools already use (see js/lib/net-lookups.js). No new external host
 * is introduced; `lookupDns` is reused as-is.
 *
 * As with net-lookups.js, every parser here is pure (string/JSON in,
 * plain object out, no network) and independently unit-tested; only the
 * `lookup*` wrappers touch the network, via the existing `lookupDns`.
 */

import { lookupDns } from './net-lookups.js';

// ---------- Shared TXT-record helpers ----------

/**
 * dns.google returns a TXT record's `data` field as one or more
 * double-quoted <character-string>s (RFC 1035 allows a TXT RR to be
 * split into multiple strings that concatenate into one logical value,
 * e.g. long SPF records). Strip the quoting and concatenate. Falls back
 * to a plain trim if the value isn't quoted at all (e.g. a raw string
 * passed directly into a parser in a unit test).
 */
export function normalizeTxtValue(raw) {
  if (typeof raw !== 'string') return '';
  const segments = raw.match(/"((?:[^"\\]|\\.)*)"/g);
  if (!segments) return raw.trim();
  return segments.map((s) => s.slice(1, -1).replace(/\\"/g, '"')).join('');
}

/** Parses a `tag=value; tag=value` list (DKIM/DMARC/BIMI tag syntax).
 * Only the FIRST '=' in each segment is treated as the delimiter, since
 * tag values (e.g. DKIM's base64 `p=`) commonly contain '=' themselves. */
function parseTagList(value) {
  const tags = {};
  for (const part of value.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    tags[key] = trimmed.slice(eq + 1).trim();
  }
  return tags;
}

function parseAddressList(v) {
  if (!v) return [];
  return v.split(',').map((s) => s.trim()).filter(Boolean);
}

// ============================================================
// SPF — RFC 7208
// ============================================================

const SPF_MECHANISM_TYPES = ['ip4', 'ip6', 'a', 'mx', 'ptr', 'exists', 'include'];
/** Mechanisms (and the redirect= modifier) that each cost one DNS lookup. */
const SPF_LOOKUP_MECHANISMS = new Set(['include', 'a', 'mx', 'ptr', 'exists']);
export const SPF_LOOKUP_LIMIT = 10;

function extractSpfMechanism(rest) {
  const lower = rest.toLowerCase();
  for (const type of SPF_MECHANISM_TYPES) {
    if (lower === type) return { type, value: null };
    if (lower.startsWith(`${type}:`)) return { type, value: rest.slice(type.length + 1) };
    if (lower.startsWith(`${type}/`)) return { type, value: rest.slice(type.length) };
  }
  return null;
}

/**
 * Pure: parse a single SPF TXT record string (quoted or not) into its
 * mechanisms, overall policy, and RFC 7208 §4.6.4 lookup-count check.
 */
export function parseSpf(record) {
  const value = normalizeTxtValue(record).trim();
  if (!/^v=spf1(\s|$)/i.test(value)) {
    throw new Error('Not a valid SPF record (must start with "v=spf1").');
  }

  const terms = value.split(/\s+/).slice(1).filter(Boolean);
  const mechanisms = [];
  let allQualifier = null;
  let redirect = null;
  let lookupCount = 0;

  for (const term of terms) {
    const qualMatch = term.match(/^([+\-~?])?(.+)$/);
    if (!qualMatch) continue;
    const qualifier = qualMatch[1] || '+';
    const rest = qualMatch[2];

    if (rest.toLowerCase() === 'all') {
      allQualifier = qualifier;
      mechanisms.push({ qualifier, type: 'all', value: null });
      continue;
    }

    const modMatch = rest.match(/^(redirect|exp)=(.+)$/i);
    if (modMatch) {
      const modType = modMatch[1].toLowerCase();
      if (modType === 'redirect') {
        redirect = modMatch[2];
        lookupCount += 1;
      }
      mechanisms.push({ qualifier: null, type: modType, value: modMatch[2] });
      continue;
    }

    const mech = extractSpfMechanism(rest);
    if (mech) {
      mechanisms.push({ qualifier, type: mech.type, value: mech.value });
      if (SPF_LOOKUP_MECHANISMS.has(mech.type)) lookupCount += 1;
    } else {
      mechanisms.push({ qualifier, type: 'unknown', value: rest });
    }
  }

  const warnings = [];
  if (lookupCount > SPF_LOOKUP_LIMIT) {
    warnings.push(`This record uses ${lookupCount} DNS-lookup mechanisms, exceeding the RFC 7208 limit of ${SPF_LOOKUP_LIMIT}. Lookups may fail with a permanent error (permerror) at some receivers.`);
  }
  if (!allQualifier && !redirect) {
    warnings.push('No "all" mechanism or redirect= modifier — this record does not specify a catch-all policy.');
  }

  return {
    raw: value,
    mechanisms,
    all: allQualifier,
    redirect,
    lookupCount,
    lookupLimitExceeded: lookupCount > SPF_LOOKUP_LIMIT,
    warnings
  };
}

/** Filters a list of raw TXT record data strings down to SPF records. */
export function findSpfRecords(txtData) {
  return txtData.map(normalizeTxtValue).filter((v) => /^v=spf1(\s|$)/i.test(v));
}

/** Looks up the SPF record published at a domain's apex. */
export async function lookupSpf(domain, fetchImpl) {
  const { records } = await lookupDns(domain, 'TXT', fetchImpl);
  const spfTxts = findSpfRecords(records.map((r) => r.data));
  if (!spfTxts.length) {
    throw new Error(`No SPF record found at the apex of ${domain}.`);
  }
  const parsed = parseSpf(spfTxts[0]);
  const result = { domain, multipleRecords: spfTxts.length > 1, ...parsed };
  if (result.multipleRecords) {
    result.warnings = [...result.warnings, 'Multiple SPF records were found at this name — RFC 7208 permits exactly one, and most receivers treat this as a permanent error (permerror).'];
  }
  return result;
}

// ============================================================
// DKIM — RFC 6376
// ============================================================

/** Pure: parse a single DKIM TXT record string (the "DKIM public key" record, not a DKIM-Signature header). */
export function parseDkim(record) {
  const value = normalizeTxtValue(record).trim();
  const tags = parseTagList(value);
  if (tags.v && tags.v.toUpperCase() !== 'DKIM1') {
    throw new Error(`Unsupported DKIM record version tag: "${tags.v}" (expected DKIM1).`);
  }
  const publicKey = tags.p !== undefined ? tags.p.trim() : null;
  const revoked = publicKey === '';
  const missingKey = publicKey === null;

  return {
    raw: value,
    tags,
    version: tags.v || 'DKIM1',
    keyType: (tags.k || 'rsa').toLowerCase(),
    serviceType: tags.s || '*',
    flags: tags.t ? tags.t.split(':').map((f) => f.trim()).filter(Boolean) : [],
    publicKey,
    publicKeyPresent: !!publicKey,
    revoked,
    missingKey,
    warnings: [
      ...(revoked ? ['This key is REVOKED (p= is present but empty) — mail signed with this selector will fail DKIM.'] : []),
      ...(missingKey ? ['No p= public-key tag found — this is not a usable DKIM key record.'] : [])
    ]
  };
}

/** Looks up a DKIM public-key record at `<selector>._domainkey.<domain>`. */
export async function lookupDkim(domain, selector = 'default', fetchImpl) {
  const sel = (selector || 'default').trim() || 'default';
  const name = `${sel}._domainkey.${domain}`;
  const { records } = await lookupDns(name, 'TXT', fetchImpl);
  if (!records.length) {
    throw new Error(`No DKIM record found at ${name}. The selector may be wrong, or DKIM may not be configured for this domain.`);
  }
  const normalized = records.map((r) => normalizeTxtValue(r.data));
  const dkimTxt = normalized.find((v) => /(^|;)\s*v=dkim1/i.test(v)) || normalized.find((v) => /(^|;)\s*p=/i.test(v)) || normalized[0];
  return { domain, selector: sel, name, ...parseDkim(dkimTxt) };
}

// ============================================================
// DMARC — RFC 7489
// ============================================================

export function explainDmarcPolicy(policy) {
  switch (policy) {
    case 'reject': return 'Reject — mail failing DMARC alignment is rejected outright by the receiving server.';
    case 'quarantine': return 'Quarantine — mail failing DMARC alignment is typically routed to spam/junk.';
    case 'none': return 'None — mail failing DMARC alignment is delivered normally; this is monitoring-only, with no enforcement.';
    default: return 'Unknown policy.';
  }
}

/** Pure: parse a single DMARC TXT record string. */
export function parseDmarc(record) {
  const value = normalizeTxtValue(record).trim();
  if (!/^v=dmarc1(;|\s|$)/i.test(value)) {
    throw new Error('Not a valid DMARC record (must start with "v=DMARC1").');
  }
  const tags = parseTagList(value);
  const policy = (tags.p || '').toLowerCase();
  if (!['none', 'quarantine', 'reject'].includes(policy)) {
    throw new Error('DMARC record is missing a valid required "p=" policy tag.');
  }
  const subdomainPolicy = tags.sp ? tags.sp.toLowerCase() : policy;
  const pctNum = tags.pct !== undefined ? Number(tags.pct) : 100;
  const pct = Number.isFinite(pctNum) ? pctNum : 100;

  const warnings = [];
  if (policy === 'none') warnings.push('Policy is "none" — DMARC is monitoring-only; non-aligned mail is not blocked.');
  if (pct < 100) warnings.push(`Only ${pct}% of non-aligned mail is subject to the policy (pct=${pct}).`);
  if (!tags.rua) warnings.push('No rua= aggregate-report address configured — no DMARC reports will be received.');

  return {
    raw: value,
    tags,
    policy,
    subdomainPolicy,
    rua: parseAddressList(tags.rua),
    ruf: parseAddressList(tags.ruf),
    pct,
    adkim: (tags.adkim || 'r').toLowerCase(),
    aspf: (tags.aspf || 'r').toLowerCase(),
    fo: tags.fo || '0',
    policyExplanation: explainDmarcPolicy(policy),
    warnings
  };
}

/** Looks up the DMARC record at `_dmarc.<domain>`. */
export async function lookupDmarc(domain, fetchImpl) {
  const name = `_dmarc.${domain}`;
  const { records } = await lookupDns(name, 'TXT', fetchImpl);
  const normalized = records.map((r) => normalizeTxtValue(r.data));
  const dmarcTxt = normalized.find((v) => /^v=dmarc1(;|\s|$)/i.test(v));
  if (!dmarcTxt) {
    throw new Error(`No DMARC record found at ${name}. This domain has no DMARC policy published.`);
  }
  return { domain, name, ...parseDmarc(dmarcTxt) };
}

/**
 * Pure, network-free: builds a syntactically correct v=DMARC1 record
 * string from form-style options. Throws with a human-readable message
 * (and a `validationErrors` array) if any input is invalid.
 */
export function generateDmarc(options = {}) {
  const {
    policy = 'none',
    subdomainPolicy = '',
    rua = '',
    ruf = '',
    pct = 100,
    adkim = 'r',
    aspf = 'r',
    fo = ''
  } = options;

  const errors = [];
  if (!['none', 'quarantine', 'reject'].includes(policy)) {
    errors.push('Policy (p) must be one of: none, quarantine, reject.');
  }
  if (subdomainPolicy && !['none', 'quarantine', 'reject'].includes(subdomainPolicy)) {
    errors.push('Subdomain policy (sp) must be one of: none, quarantine, reject.');
  }
  const ruaList = validateMailtoList(rua, 'rua', errors);
  const rufList = validateMailtoList(ruf, 'ruf', errors);

  const pctNum = Number(pct);
  if (!Number.isInteger(pctNum) || pctNum < 0 || pctNum > 100) {
    errors.push('Percentage (pct) must be a whole number between 0 and 100.');
  }
  if (!['r', 's'].includes(adkim)) errors.push('DKIM alignment (adkim) must be r (relaxed) or s (strict).');
  if (!['r', 's'].includes(aspf)) errors.push('SPF alignment (aspf) must be r (relaxed) or s (strict).');
  if (fo && !/^[01ds](:[01ds])*$/.test(fo)) {
    errors.push('Failure options (fo) must be a colon-separated combination of 0, 1, d, s.');
  }

  if (errors.length) {
    const err = new Error(errors.join(' '));
    err.validationErrors = errors;
    throw err;
  }

  const parts = ['v=DMARC1', `p=${policy}`];
  if (subdomainPolicy) parts.push(`sp=${subdomainPolicy}`);
  if (ruaList.length) parts.push(`rua=${ruaList.join(',')}`);
  if (rufList.length) parts.push(`ruf=${rufList.join(',')}`);
  if (pctNum !== 100) parts.push(`pct=${pctNum}`);
  if (adkim !== 'r') parts.push(`adkim=${adkim}`);
  if (aspf !== 'r') parts.push(`aspf=${aspf}`);
  if (fo) parts.push(`fo=${fo}`);
  return parts.join('; ');
}

function validateMailtoList(value, tagName, errors) {
  if (!value || !value.trim()) return [];
  const list = value.split(',').map((s) => s.trim()).filter(Boolean);
  for (const addr of list) {
    if (!/^mailto:[^\s@]+@[^\s@]+\.[^\s@]+/i.test(addr)) {
      errors.push(`${tagName} address "${addr}" must be a mailto: URI (e.g. mailto:dmarc@example.com).`);
    }
  }
  return list;
}

// ============================================================
// BIMI (draft-brand-indicators-for-message-identification)
// ============================================================

/** Pure: parse a single BIMI TXT record string. */
export function parseBimi(record) {
  const value = normalizeTxtValue(record).trim();
  if (!/^v=bimi1(;|\s|$)/i.test(value)) {
    throw new Error('Not a valid BIMI record (must start with "v=BIMI1").');
  }
  const tags = parseTagList(value);
  return {
    raw: value,
    tags,
    logoUrl: tags.l || null,
    vmcUrl: tags.a || null
  };
}

/** Looks up the BIMI record at `<selector>._bimi.<domain>` (selector defaults to "default"). */
export async function lookupBimi(domain, selector = 'default', fetchImpl) {
  const sel = (selector || 'default').trim() || 'default';
  const name = `${sel}._bimi.${domain}`;
  const { records } = await lookupDns(name, 'TXT', fetchImpl);
  const normalized = records.map((r) => normalizeTxtValue(r.data));
  const bimiTxt = normalized.find((v) => /^v=bimi1(;|\s|$)/i.test(v));
  if (!bimiTxt) {
    throw new Error(`No BIMI record found at ${name}.`);
  }
  return { domain, selector: sel, name, ...parseBimi(bimiTxt) };
}

// ============================================================
// Domain Health — combined DMARC + SPF + BIMI view
// ============================================================

async function safeLookup(fn) {
  try {
    return { ok: true, data: await fn() };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

/**
 * Pure: given the three individual lookup results, computes an overall
 * pass/warn/fail health score and a plain-English issue list. Kept
 * separate from lookupDomainHealth so it's independently unit-testable
 * against synthetic results (no network involved).
 */
export function computeOverallHealth({ dmarc, spf, bimi }) {
  const issues = [];
  let score = 'pass';
  const worsen = (level) => {
    if (level === 'fail') score = 'fail';
    else if (level === 'warn' && score !== 'fail') score = 'warn';
  };

  if (!dmarc.ok) {
    issues.push('No DMARC record — SPF/DKIM alignment is never enforced and no reports are received.');
    worsen('fail');
  } else if (dmarc.data.policy === 'none') {
    issues.push('DMARC policy is p=none (monitoring only, no enforcement).');
    worsen('warn');
  }

  if (!spf.ok) {
    issues.push('No SPF record.');
    worsen('fail');
  } else if (spf.data.lookupLimitExceeded) {
    issues.push(`SPF exceeds the RFC 7208 10-lookup limit (${spf.data.lookupCount} lookups) — may fail with permerror.`);
    worsen('warn');
  } else if (!spf.data.all && !spf.data.redirect) {
    issues.push('SPF record has no "all" mechanism or redirect= modifier.');
    worsen('warn');
  }

  if (bimi.ok) {
    if (!dmarc.ok || !['quarantine', 'reject'].includes(dmarc.data.policy)) {
      issues.push('BIMI is published, but DMARC is not at enforcement (quarantine/reject) — most mailbox providers will not display the BIMI logo without it.');
      worsen('warn');
    }
  }

  return { score, issues };
}

/** Combined one-shot lookup: DMARC + SPF + BIMI for a single domain, with an overall health summary. Reuses the individual lookup* functions — no parsing logic is duplicated. */
export async function lookupDomainHealth(domain, fetchImpl) {
  const [dmarc, spf, bimi] = await Promise.all([
    safeLookup(() => lookupDmarc(domain, fetchImpl)),
    safeLookup(() => lookupSpf(domain, fetchImpl)),
    safeLookup(() => lookupBimi(domain, 'default', fetchImpl))
  ]);
  const overall = computeOverallHealth({ dmarc, spf, bimi });
  return { domain, dmarc, spf, bimi, overall };
}
