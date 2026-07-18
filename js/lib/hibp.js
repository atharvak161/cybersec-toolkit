/**
 * HIBP ("Have I Been Pwned") breach check using the k-anonymity range
 * API — the ONLY tool in this toolkit that calls an external API for
 * password checking, and it never sends the full password or even the
 * full hash: only the first 5 hex characters of the SHA-1 digest are
 * sent, and the match is completed locally against the returned suffix
 * list. See https://haveibeenpwned.com/API/v3#PwnedPasswords
 *
 * This module separates pure logic (parsing the API's response text,
 * building the request prefix) from the actual network call, so the
 * pure parts are unit-testable without any network access.
 */

import { sha1Hex } from './hashing.js';

export const HIBP_RANGE_ENDPOINT = 'https://api.pwnedpasswords.com/range/';

/** Pure: given a password, compute the SHA-1 hex digest, uppercase. */
export async function sha1PrefixSuffix(password) {
  const hex = (await sha1Hex(password)).toUpperCase();
  return { prefix: hex.slice(0, 5), suffix: hex.slice(5) };
}

/**
 * Pure: parse the HIBP range API's plaintext response
 * ("SUFFIX:COUNT\r\n" per line) and look up a specific suffix.
 * @param {string} responseText
 * @param {string} suffix uppercase hex suffix (35 chars)
 * @returns {number} breach count, 0 if not found
 */
export function parseHibpRangeResponse(responseText, suffix) {
  const lines = responseText.split('\n');
  for (const line of lines) {
    const [respSuffix, countStr] = line.trim().split(':');
    if (respSuffix && respSuffix.toUpperCase() === suffix.toUpperCase()) {
      return parseInt(countStr, 10) || 0;
    }
  }
  return 0;
}

/**
 * Full check: computes SHA-1 locally, calls the k-anonymity range API
 * with only the 5-char prefix, and resolves the match locally.
 * @param {string} password
 * @param {(url: string) => Promise<{text: () => Promise<string>}>} fetchImpl defaults to global fetch
 * @returns {Promise<{ breached: boolean, count: number, prefix: string }>}
 */
export async function checkHibp(password, fetchImpl = globalThis.fetch) {
  if (!fetchImpl) throw new Error('No fetch implementation available');
  const { prefix, suffix } = await sha1PrefixSuffix(password);
  const res = await fetchImpl(HIBP_RANGE_ENDPOINT + prefix);
  const text = await res.text();
  const count = parseHibpRangeResponse(text, suffix);
  return { breached: count > 0, count, prefix };
}
