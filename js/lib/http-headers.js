/**
 * HTTP security headers checker. Primary path (and the only path this
 * module implements): parse a block of raw HTTP response headers pasted
 * from browser devtools (Network tab -> a request -> Response Headers ->
 * "raw"/copy), and flag missing or weak security-relevant headers with
 * plain-language explanations. Pure text parsing — no network request.
 */

const SECURITY_HEADERS = [
  {
    key: 'content-security-policy',
    label: 'Content-Security-Policy',
    why: 'Restricts which sources scripts, styles, images, and other resources can load from — the primary browser-side defense against XSS and data-injection attacks.',
    severity: 'high'
  },
  {
    key: 'strict-transport-security',
    label: 'Strict-Transport-Security',
    why: 'Tells the browser to only ever connect over HTTPS for this site (and optionally subdomains), preventing downgrade and SSL-stripping attacks on future visits.',
    severity: 'high'
  },
  {
    key: 'x-frame-options',
    label: 'X-Frame-Options',
    why: "Prevents the page from being loaded in an <iframe> on another site, the classic defense against clickjacking. (Modern sites can use CSP's frame-ancestors instead — this checker flags it separately below.)",
    severity: 'medium'
  },
  {
    key: 'x-content-type-options',
    label: 'X-Content-Type-Options',
    why: "Set to 'nosniff', this stops the browser from MIME-sniffing a response away from the declared Content-Type — closes off a class of content-sniffing attacks (e.g. a text file being executed as script).",
    severity: 'medium'
  },
  {
    key: 'referrer-policy',
    label: 'Referrer-Policy',
    why: 'Controls how much of your URL (which can contain sensitive path/query data) is leaked to other sites via the Referer header when a user clicks a link away from your site.',
    severity: 'low'
  },
  {
    key: 'permissions-policy',
    label: 'Permissions-Policy',
    why: 'Explicitly disables or restricts powerful browser features (camera, microphone, geolocation, etc.) for your origin and any embedded content, reducing the impact of a compromised third-party script.',
    severity: 'low'
  },
  {
    key: 'cross-origin-opener-policy',
    label: 'Cross-Origin-Opener-Policy',
    why: 'Isolates your page from cross-origin popups/windows that could otherwise interact with it, part of the modern "cross-origin isolation" defenses.',
    severity: 'low'
  },
  {
    key: 'cross-origin-resource-policy',
    label: 'Cross-Origin-Resource-Policy',
    why: 'Controls which other origins are allowed to load this resource, reducing exposure to cross-origin data-leak attacks (e.g. Spectre-style side channels).',
    severity: 'low'
  }
];

const INFO_LEAK_HEADERS = [
  { key: 'server', label: 'Server', note: 'Reveals server software (and sometimes version) — minor recon value for an attacker, consider removing or genericizing.' },
  { key: 'x-powered-by', label: 'X-Powered-By', note: 'Reveals the backend framework/language — same recon concern as Server, and easy to remove.' }
];

/**
 * Parse raw pasted headers text (one "Name: value" pair per line — the
 * format browser devtools "copy as raw headers" produces, and also
 * tolerant of a leading "HTTP/1.1 200 OK" status line if present).
 * @param {string} raw
 * @returns {Record<string,string>} lower-cased header name -> value
 */
export function parseHeaderBlock(raw) {
  const headers = {};
  const lines = raw.split(/\r?\n/);
  for (const line of lines) {
    if (!line.trim()) continue;
    if (/^HTTP\/\d(\.\d)?\s+\d{3}/.test(line.trim())) continue; // skip status line
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const name = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (name) headers[name] = value;
  }
  return headers;
}

/**
 * Analyze a parsed (or raw) header set against the standard security
 * header checklist.
 * @param {string} rawHeaders
 * @returns {{ present: Array, missing: Array, infoLeaks: Array }}
 */
export function analyzeHeaders(rawHeaders) {
  const headers = parseHeaderBlock(rawHeaders);
  if (Object.keys(headers).length === 0) {
    throw new Error('No headers recognized — paste one "Name: value" pair per line.');
  }

  const present = [];
  const missing = [];
  for (const h of SECURITY_HEADERS) {
    if (headers[h.key] !== undefined) {
      present.push({ ...h, value: headers[h.key] });
    } else {
      missing.push(h);
    }
  }

  // X-Frame-Options is only a real gap if CSP frame-ancestors isn't already covering it.
  const csp = headers['content-security-policy'] || '';
  if (missing.some((m) => m.key === 'x-frame-options') && /frame-ancestors/i.test(csp)) {
    const idx = missing.findIndex((m) => m.key === 'x-frame-options');
    missing.splice(idx, 1);
    present.push({
      key: 'x-frame-options',
      label: 'X-Frame-Options (covered by CSP frame-ancestors)',
      why: 'frame-ancestors in your Content-Security-Policy already covers clickjacking protection.',
      severity: 'medium',
      value: '(via CSP)'
    });
  }

  const infoLeaks = INFO_LEAK_HEADERS
    .filter((h) => headers[h.key] !== undefined)
    .map((h) => ({ ...h, value: headers[h.key] }));

  return { headers, present, missing, infoLeaks };
}

export { SECURITY_HEADERS, INFO_LEAK_HEADERS };
