/**
 * Web Worker wrapper around the hash-cracker so both tiers — the instant
 * quick tier (300 curated + 7,776 diceware) and the ~100,000-word SecLists
 * big tier — run OFF the main thread. At the big tier's scale (100k words x
 * ~90 rule variants = several million hashes per algorithm) running this on
 * the main thread would freeze the tab for the whole crack; a Worker keeps
 * it responsive and lets the UI show live progress with a real Cancel
 * button (worker.terminate(), same pattern as js/lib/enigma-break-worker.js).
 *
 * The SecLists wordlist is fetched from INSIDE this worker (via
 * loadSeclistsWordlist(), whose fetch is resolved relative to this worker's
 * own module URL) — so it is only ever downloaded once a crack actually
 * reaches the big tier, never on page load and never on the main thread.
 *
 * Protocol:
 *   main → worker : { hashes: string[], algorithm?: string }
 *   worker → main : { type:'progress', tier:'quick'|'big', done, total }
 *                   { type:'tier-done', tier:'quick'|'big', crackedCount, totalCount }
 *                   { type:'result', out: { type, tried, results, wordlistSize } }
 *                   { type:'error', message }
 *
 * `out.results` reflects the FINAL state after both tiers (or after the
 * quick tier alone, if it already cracked everything and the big tier never
 * needed to run). `out.wordlistSize` is the actual number of words loaded
 * from the big tier (undefined if the big tier never ran) — never a
 * hardcoded count, always measured off the real fetched list.
 */
import { crackHashes, crackHashesFromWordlist } from './hash-cracker.js';
import { loadSeclistsWordlist } from './seclists-wordlist.js';

self.onmessage = async (e) => {
  const { hashes, algorithm } = e.data || {};
  try {
    // Tier 1 — quick, bundled, instant. No network fetch.
    const quick = await crackHashes(hashes, {
      algorithm,
      onProgress: (done, total) => self.postMessage({ type: 'progress', tier: 'quick', done, total })
    });

    const stillMissing = quick.results.filter((r) => r.plaintext === null).map((r) => r.hash);
    self.postMessage({
      type: 'tier-done',
      tier: 'quick',
      crackedCount: quick.results.length - stillMissing.length,
      totalCount: quick.results.length
    });

    if (!stillMissing.length) {
      self.postMessage({ type: 'result', out: quick });
      return;
    }

    // Tier 2 — the big SecLists list. Fetched now, lazily, for the first time.
    const words = await loadSeclistsWordlist();
    const big = await crackHashesFromWordlist(stillMissing, words, {
      algorithm: algorithm || quick.type,
      onProgress: (done, total) => self.postMessage({ type: 'progress', tier: 'big', done, total })
    });

    // Merge: anything tier 1 already found, plus whatever tier 2 recovered
    // for the ones tier 1 missed.
    const bigByHash = new Map(big.results.map((r) => [r.hash, r.plaintext]));
    const merged = quick.results.map((r) =>
      r.plaintext !== null ? r : { hash: r.hash, plaintext: bigByHash.has(r.hash) ? bigByHash.get(r.hash) : null }
    );
    const crackedCount = merged.filter((r) => r.plaintext !== null).length;
    self.postMessage({ type: 'tier-done', tier: 'big', crackedCount, totalCount: merged.length });

    self.postMessage({
      type: 'result',
      out: { type: quick.type, tried: quick.tried + big.tried, results: merged, wordlistSize: words.length }
    });
  } catch (err) {
    self.postMessage({ type: 'error', message: err && err.message ? err.message : String(err) });
  }
};
