/**
 * Raw email header block parser. Distinct from js/lib/http-headers.js
 * (which analyzes HTTP *response* headers for a web security posture
 * check) — this parses RFC 5322 *email message* headers pasted from a
 * "View source" / "Show original" mail-client view, to trace the
 * delivery path (Received: hops) and surface the receiving servers'
 * own SPF/DKIM/DMARC authentication verdicts. Pure text parsing only —
 * no network request, ever.
 */

/**
 * Parses a raw header block into an ordered list of { name, value }
 * entries, exactly as they appear in the source (top to bottom — i.e.
 * newest-hop-first for Received:, since each hop prepends its own
 * header). Handles RFC 5322 header folding (continuation lines starting
 * with whitespace belong to the previous header) and stops at the first
 * blank line (start of the message body), if a body was pasted too.
 */
export function parseEmailHeaders(raw) {
  if (typeof raw !== 'string' || !raw.trim()) {
    throw new Error('Paste a raw email header block first.');
  }
  const headerBlock = raw.replace(/^﻿/, '').split(/\r?\n\r?\n/)[0];
  const lines = headerBlock.split(/\r?\n/);
  const headers = [];

  for (const line of lines) {
    if (/^[ \t]/.test(line) && headers.length) {
      headers[headers.length - 1].value += ' ' + line.trim();
      continue;
    }
    const idx = line.indexOf(':');
    if (idx === -1) continue; // skip stray non-header lines (e.g. an mbox "From " separator)
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (!name) continue;
    headers.push({ name, value });
  }

  if (!headers.length) {
    throw new Error('No headers recognized — paste raw "Name: value" header lines (one per line).');
  }
  return headers;
}

/** Case-insensitive lookup of every header with the given name, in source order. */
export function getHeaders(headers, name) {
  const lower = name.toLowerCase();
  return headers.filter((h) => h.name.toLowerCase() === lower);
}

function firstHeaderValue(headers, name) {
  const found = getHeaders(headers, name);
  return found.length ? found[0].value : null;
}

// ---------- Received: chain ----------

/** Pure: parse one Received: header's value into its component parts. */
export function parseReceivedHeader(value) {
  const dateMatch = value.match(/;\s*([^;]+)$/);
  const dateRaw = dateMatch ? dateMatch[1].trim() : null;
  const date = dateRaw ? new Date(dateRaw) : null;
  const validDate = date && !Number.isNaN(date.getTime()) ? date : null;

  const fromMatch = value.match(/\bfrom\s+(\S+)/i);
  const byMatch = value.match(/\bby\s+(\S+)/i);
  const withMatch = value.match(/\bwith\s+(\S+)/i);
  const forMatch = value.match(/\bfor\s+<?([^\s>;]+)>?/i);

  return {
    raw: value,
    from: fromMatch ? fromMatch[1].replace(/[,;]$/, '') : null,
    by: byMatch ? byMatch[1].replace(/[,;]$/, '') : null,
    protocol: withMatch ? withMatch[1].replace(/[,;]$/, '') : null,
    for: forMatch ? forMatch[1] : null,
    date: validDate,
    dateRaw
  };
}

/**
 * Orders and analyzes every Received: header into a chronological
 * (sender -> recipient) delivery path. Raw header order is newest-first
 * (each relay prepends its own Received: line above the ones already
 * there), so the parsed list is reversed to read top-to-bottom in
 * delivery order. Flags any gap of more than 5 minutes between
 * consecutive hops as a notable delay.
 */
export function analyzeReceivedChain(headers) {
  const receivedHeaders = getHeaders(headers, 'Received');
  const hops = [...receivedHeaders].reverse().map((h, i) => ({ hop: i + 1, ...parseReceivedHeader(h.value) }));

  const GAP_THRESHOLD_MS = 5 * 60 * 1000;
  const gaps = [];
  for (let i = 1; i < hops.length; i++) {
    const prev = hops[i - 1];
    const curr = hops[i];
    if (prev.date && curr.date) {
      const deltaMs = curr.date.getTime() - prev.date.getTime();
      if (Math.abs(deltaMs) > GAP_THRESHOLD_MS) {
        gaps.push({ afterHop: prev.hop, beforeHop: curr.hop, deltaMs });
      }
    }
  }

  return { hopCount: hops.length, hops, gaps };
}

// ---------- Authentication verdicts ----------

/** Pure: parse an Authentication-Results (or ARC-Authentication-Results) header value. */
export function parseAuthenticationResults(value) {
  const authservid = value.split(';')[0].trim();
  const results = {};
  const re = /\b(spf|dkim|dmarc)=(\w+)/gi;
  let m;
  while ((m = re.exec(value)) !== null) {
    const mech = m[1].toLowerCase();
    const verdict = m[2].toLowerCase();
    if (!results[mech]) results[mech] = [];
    results[mech].push(verdict);
  }
  return { raw: value, authservid, results };
}

/** Pure: parse a legacy Received-SPF header value (e.g. "pass (…) client-ip=…"). */
export function parseReceivedSpf(value) {
  const m = value.match(/^(\w+)/);
  return { raw: value, result: m ? m[1].toLowerCase() : null };
}

/** Pure: parse a DKIM-Signature header's tag list down to the fields relevant to a passive read (domain, selector, algorithm) — this does NOT verify the signature (no crypto, no key fetch). */
export function parseDkimSignatureHeader(value) {
  const tags = {};
  for (const part of value.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    tags[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  }
  return { raw: value, domain: tags.d || null, selector: tags.s || null, algorithm: tags.a || null };
}

/**
 * Combines every authentication-relevant header into one verdict view.
 * Prefers Authentication-Results (added by the receiving server after
 * actually checking SPF/DKIM/DMARC) and falls back to a legacy
 * Received-SPF header for the SPF verdict if no Authentication-Results
 * header is present. DKIM-Signature / ARC headers are surfaced for
 * context (a signature's mere presence isn't a pass — this is a passive
 * parser, not a cryptographic verifier).
 */
export function analyzeAuthentication(headers) {
  const authenticationResults = getHeaders(headers, 'Authentication-Results').map((h) => parseAuthenticationResults(h.value));
  const arcAuthenticationResults = getHeaders(headers, 'ARC-Authentication-Results').map((h) => parseAuthenticationResults(h.value));
  const receivedSpf = getHeaders(headers, 'Received-SPF').map((h) => parseReceivedSpf(h.value));
  const dkimSignatures = getHeaders(headers, 'DKIM-Signature').map((h) => parseDkimSignatureHeader(h.value));
  const arcHopCount = getHeaders(headers, 'ARC-Seal').length;

  const verdicts = { spf: null, dkim: null, dmarc: null };
  for (const ar of authenticationResults) {
    if (ar.results.spf && !verdicts.spf) verdicts.spf = ar.results.spf[0];
    if (ar.results.dkim && !verdicts.dkim) verdicts.dkim = ar.results.dkim[0];
    if (ar.results.dmarc && !verdicts.dmarc) verdicts.dmarc = ar.results.dmarc[0];
  }
  if (!verdicts.spf && receivedSpf.length) verdicts.spf = receivedSpf[0].result;

  return {
    authenticationResults,
    arcAuthenticationResults,
    receivedSpf,
    dkimSignatures,
    arcChainPresent: arcHopCount > 0,
    arcHopCount,
    verdicts
  };
}

/**
 * Top-level pure entry point: parses a raw header block and returns the
 * headers, the basic envelope fields, the ordered Received: chain, and
 * the authentication verdicts — everything the Header Analyzer tool
 * needs in one call.
 */
export function analyzeEmailHeaders(raw) {
  const headers = parseEmailHeaders(raw);
  return {
    headers,
    basics: {
      from: firstHeaderValue(headers, 'From'),
      to: firstHeaderValue(headers, 'To'),
      subject: firstHeaderValue(headers, 'Subject'),
      date: firstHeaderValue(headers, 'Date'),
      messageId: firstHeaderValue(headers, 'Message-ID')
    },
    receivedChain: analyzeReceivedChain(headers),
    authentication: analyzeAuthentication(headers)
  };
}
