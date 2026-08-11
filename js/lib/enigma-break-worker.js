/**
 * Web Worker wrapper around enigmaAutoBreak() so the ciphertext-only Enigma
 * search (up to ~2 million decrypts) runs OFF the main thread — the tab stays
 * responsive and the UI can show live progress and offer a Cancel button
 * (worker.terminate()).
 *
 * Protocol:
 *   main → worker : { ciphertext, options }
 *   worker → main : { type:'progress', phase, done, total }
 *                   { type:'result', result }
 *                   { type:'error', message }
 *
 * The UI degrades gracefully to a synchronous call when Workers are
 * unavailable (see cipher-tools.js) — this file is the fast path, not a hard
 * dependency.
 */
import { enigmaAutoBreak } from './enigma-break.js';

self.onmessage = (e) => {
  const { ciphertext, options } = e.data || {};
  try {
    const onProgress = (p) => self.postMessage({ type: 'progress', ...p });
    const result = enigmaAutoBreak(ciphertext, { ...(options || {}), onProgress });
    self.postMessage({ type: 'result', result });
  } catch (err) {
    self.postMessage({ type: 'error', message: err && err.message ? err.message : String(err) });
  }
};
