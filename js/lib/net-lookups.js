/**
 * WHOIS / DNS / IP-geolocation lookups against free, no-API-key public
 * data sources. These are the "explicitly disclosed external API call"
 * tools — each must show the external-API badge in the UI. NOT active
 * scanning/enumeration: all three simply query a public registry's own
 * read API for data about a single name/IP the user provides.
 *
 *  - DNS:      Google Public DNS-over-HTTPS JSON API (dns.google) — no key.
 *  - WHOIS:    RDAP (the IETF/IANA-standardized WHOIS successor),
 *              queried via rdap.org's bootstrap redirector — no key.
 *  - IP geo:   ipapi.co JSON endpoint — no key required for basic lookups.
 *
 * As with hibp.js, request-building and response-parsing are pure and
 * unit-testable; only the thin fetch wrapper touches the network.
 */

export const DNS_ENDPOINT = 'https://dns.google/resolve';
export const RDAP_ENDPOINT = 'https://rdap.org/domain/';
export const IP_GEO_ENDPOINT = 'https://ipapi.co/';

export function buildDnsUrl(name, type = 'A') {
  return `${DNS_ENDPOINT}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
}

/** Pure: parse dns.google's JSON response into a simplified record list. */
export function parseDnsResponse(json) {
  const status = json.Status;
  const records = (json.Answer || []).map((a) => ({ name: a.name, type: a.type, ttl: a.TTL, data: a.data }));
  return { status, records };
}

export function buildRdapUrl(domain) {
  return RDAP_ENDPOINT + encodeURIComponent(domain);
}

/** Pure: parse an RDAP domain response into a simplified summary. */
export function parseRdapResponse(json) {
  const events = json.events || [];
  const findEvent = (action) => events.find((e) => e.eventAction === action)?.eventDate || null;
  const nameservers = (json.nameservers || []).map((ns) => ns.ldhName);
  const statuses = json.status || [];
  const registrarEntity = (json.entities || []).find((e) => (e.roles || []).includes('registrar'));
  let registrar = null;
  if (registrarEntity && registrarEntity.vcardArray) {
    const vcard = registrarEntity.vcardArray[1] || [];
    const fnEntry = vcard.find((v) => v[0] === 'fn');
    registrar = fnEntry ? fnEntry[3] : null;
  }
  return {
    domain: json.ldhName || null,
    registrar,
    statuses,
    nameservers,
    registrationDate: findEvent('registration'),
    lastChangedDate: findEvent('last changed'),
    expirationDate: findEvent('expiration')
  };
}

export function buildIpGeoUrl(ip) {
  return `${IP_GEO_ENDPOINT}${encodeURIComponent(ip)}/json/`;
}

/** Pure: parse an ipapi.co JSON response into a simplified summary. */
export function parseIpGeoResponse(json) {
  if (json.error) return { error: json.reason || 'lookup failed' };
  return {
    ip: json.ip,
    city: json.city,
    region: json.region,
    country: json.country_name,
    countryCode: json.country_code,
    latitude: json.latitude,
    longitude: json.longitude,
    org: json.org,
    timezone: json.timezone
  };
}

/** Generic thin fetch+parse wrapper, network-dependent. */
async function fetchJson(url, fetchImpl = globalThis.fetch) {
  if (!fetchImpl) throw new Error('No fetch implementation available');
  const res = await fetchImpl(url);
  return res.json();
}

export async function lookupDns(name, type = 'A', fetchImpl) {
  const json = await fetchJson(buildDnsUrl(name, type), fetchImpl);
  return parseDnsResponse(json);
}

/**
 * WHOIS/RDAP lookup for a domain. Unregistered/not-found domains commonly
 * come back from RDAP bootstrap redirects (rdap.org -> the registry's own
 * RDAP server) as an HTTP 404 with an EMPTY response body (confirmed against
 * the live rdap.org endpoint) rather than a JSON error object. Calling
 * `res.json()` on an empty body throws a raw, technical
 * "Unexpected end of JSON input" SyntaxError — not useful to an end user.
 * Catch that failure mode here and surface a friendly, unambiguous message
 * instead.
 */
export async function lookupWhois(domain, fetchImpl) {
  const impl = fetchImpl || globalThis.fetch;
  if (!impl) throw new Error('No fetch implementation available');
  const res = await impl(buildRdapUrl(domain));
  let json;
  try {
    json = await res.json();
  } catch (parseErr) {
    // Empty or non-JSON body — no RDAP record for this domain (or the
    // registry endpoint is unavailable). Either way, not a real error to
    // surface raw to the user.
    throw new Error('No WHOIS record found for this domain.');
  }
  if (!res.ok) {
    // Some RDAP servers return a JSON error object with a 404 (e.g.
    // { errorCode: 404, title: 'NOT FOUND' }) instead of an empty body.
    throw new Error('No WHOIS record found for this domain.');
  }
  return parseRdapResponse(json);
}

export async function lookupIpGeo(ip, fetchImpl) {
  const json = await fetchJson(buildIpGeoUrl(ip), fetchImpl);
  return parseIpGeoResponse(json);
}
