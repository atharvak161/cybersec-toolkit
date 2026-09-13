/**
 * Lazy loader for the vendored SecLists breached-password corpus
 * (data/seclists-top100k.txt — 100,000 real leaked passwords, ranked by
 * frequency; MIT, Daniel Miessler; see data/SECLISTS-NOTICE.txt).
 *
 * NEVER fetched on page load. loadSeclistsWordlist() is only called from a
 * user-initiated crack (see js/lib/hash-cracker-worker.js and the sync
 * fallback in js/ui/hashing-tools.js), and only once per session — the
 * result is cached in-module so a second crack reuses it instantly.
 *
 * The file path lives ONLY here — swapping in a larger/different cut later
 * (e.g. a 500k or full 1M list) means changing SECLISTS_WORDLIST_PATH in
 * this one place. Nothing else in the codebase hardcodes the path or the
 * word count; every count shown in the UI is measured off the array this
 * module returns, at load time.
 */

export const SECLISTS_WORDLIST_PATH = 'data/seclists-top100k.txt';
export const SECLISTS_SOURCE_URL =
  'https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt';
export const SECLISTS_LICENSE = 'MIT (Daniel Miessler) — see data/SECLISTS-NOTICE.txt';

/** Pure: turn the raw fetched text into a clean word array. No I/O. */
export function parseWordlistText(text) {
  return text.split('\n').map((w) => w.trim()).filter(Boolean);
}

let wordsPromise = null;

/**
 * Fetch + parse the big wordlist once, cached for the session. Resolved
 * relative to this module's own URL (not the page's) so it works the same
 * whether called from the main thread or from inside a module Worker, and
 * regardless of which sub-path the site is served from (GitHub Pages
 * project sites live under /<repo>/).
 *
 * Throws (and clears the cache, so a retry is possible) if the fetch fails.
 */
export function loadSeclistsWordlist() {
  if (wordsPromise) return wordsPromise;
  const url = new URL('../../' + SECLISTS_WORDLIST_PATH, import.meta.url);
  wordsPromise = fetch(url)
    .then((res) => {
      if (!res.ok) throw new Error(`Could not load the SecLists wordlist (HTTP ${res.status})`);
      return res.text();
    })
    .then(parseWordlistText)
    .catch((err) => {
      wordsPromise = null; // allow a retry instead of caching a permanent failure
      throw err;
    });
  return wordsPromise;
}

/** True once loadSeclistsWordlist() has been called (whether or not it has resolved). */
export function isSeclistsWordlistLoading() {
  return wordsPromise !== null;
}
