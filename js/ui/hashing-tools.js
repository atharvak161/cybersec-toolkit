import * as hashing from '../lib/hashing.js';
import { crackHashes, crackHashesFromWordlist, detectHashType } from '../lib/hash-cracker.js';
import { loadSeclistsWordlist, SECLISTS_SOURCE_URL } from '../lib/seclists-wordlist.js';
import { el, toolHeader, clear, resultLine, showError, copyButton } from './helpers.js';

export const HASHING_TOOLS = [
  {
    id: 'hash-cracker',
    name: 'Hash Cracker',
    render(container) {
      clear(container);
      container.appendChild(toolHeader(
        'Recovers the plaintext behind MD5, SHA-1, SHA-256, and SHA-512 hashes with a real dictionary + rules '
        + 'attack, entirely in your browser. Paste one hash or many (one per line). Two tiers, run in order: an '
        + 'instant pass over ~8,000 curated common passwords, then — only if that misses — a pass over '
        + '100,000 real breached passwords from SecLists (fetched on demand, never on page load; MIT-licensed, '
        + 'see the credit below), both with case, leetspeak, and suffix variants. That is a genuinely useful '
        + 'dictionary attack, not a toy — but it is still not CrackStation’s multi-hundred-GB server-side table, '
        + 'and salted or bcrypt/argon2 hashes are out of reach by design (this is unsalted-hash cracking only). '
        + 'The big-tier pass runs in a background Web Worker so the page stays responsive, and you can cancel it '
        + 'at any time.'
      ));

      const input = el('textarea', { rows: '4', placeholder: 'Paste one or more hashes, one per line\ne.g. 5f4dcc3b5aa765d61d8327deb882cf99', style: 'width:100%; font-family:var(--mono, monospace)', spellcheck: 'false' });
      const runBtn = el('button', { class: 'btn' }, 'Crack');
      const cancelBtn = el('button', { class: 'btn secondary', style: 'display:none' }, 'Cancel');
      const status = el('div', { class: 'tool-desc', style: 'margin-top:6px' });
      const progressWrap = el('div', { style: 'display:none; margin-top:10px' }, [
        el('div', { class: 'cc-bar' }, [el('div', { class: 'cc-bar-fill', id: 'hc-prog' })]),
        el('div', { class: 'tool-desc', id: 'hc-prog-label', style: 'margin-top:4px' }, '')
      ]);
      const progFill = progressWrap.querySelector('#hc-prog');
      const progLabel = progressWrap.querySelector('#hc-prog-label');
      const resultsBox = el('div', {});
      const errorNode = el('div', {});
      const credit = el('div', { class: 'tool-desc', style: 'margin-top:10px' }, [
        'Big-tier wordlist: ',
        el('a', { href: SECLISTS_SOURCE_URL, target: '_blank', rel: 'noopener' }, 'SecLists Common-Credentials'),
        ' (Daniel Miessler, MIT). See ',
        el('code', {}, 'data/SECLISTS-NOTICE.txt'),
        ' for the full licence and provenance.'
      ]);

      let worker = null;
      let cancelled = false;

      function setRunning(on) {
        runBtn.disabled = on;
        runBtn.textContent = on ? 'Cracking…' : 'Crack';
        cancelBtn.style.display = on ? '' : 'none';
        progressWrap.style.display = on ? '' : 'none';
        if (!on) { progFill.style.width = '0%'; progLabel.textContent = ''; }
      }

      function onWorkerMessage(msg, hashCount) {
        if (msg.type === 'progress') {
          const pct = msg.total ? Math.min(99, Math.round((msg.done / msg.total) * 100)) : 0;
          progFill.style.width = `${pct}%`;
          const tierLabel = msg.tier === 'big' ? 'Big tier (SecLists, 100k passwords)' : 'Quick tier (curated + diceware)';
          progLabel.textContent = `${tierLabel} — ${msg.done.toLocaleString()} of ~${msg.total.toLocaleString()} candidates (${pct}%)`;
          return;
        }
        if (msg.type === 'tier-done') {
          if (msg.tier === 'quick' && msg.crackedCount < msg.totalCount) {
            status.textContent = `Quick tier: ${msg.crackedCount} of ${msg.totalCount} cracked. Trying the big SecLists list for the rest — fetching it now (first use only)…`;
          }
          return;
        }
        if (msg.type === 'result') {
          setRunning(false);
          if (worker) { worker.terminate(); worker = null; }
          if (!cancelled) showResult(msg.out, hashCount);
          return;
        }
        if (msg.type === 'error') {
          setRunning(false);
          if (worker) { worker.terminate(); worker = null; }
          showError(errorNode, new Error(msg.message));
        }
      }

      function showResult(out, hashCount) {
        const cracked = out.results.filter((r) => r.plaintext !== null).length;
        const wordlistNote = out.wordlistSize
          ? ` · big tier loaded ${out.wordlistSize.toLocaleString()} words`
          : '';
        status.textContent = `${out.type} · ${cracked} of ${hashCount} cracked · ${out.tried.toLocaleString()} candidates tried${wordlistNote}`;
        const rows = out.results.map((r) => el('tr', { class: r.plaintext !== null ? 'hc-hit' : 'hc-miss' }, [
          el('td', { class: 'hc-hash tabular-nums' }, r.hash),
          el('td', { class: 'hc-plain' }, r.plaintext !== null ? r.plaintext : 'not found in either tier')
        ]));
        resultsBox.appendChild(el('table', { class: 'data-table hc-table' }, [
          el('tr', {}, [el('th', {}, 'Hash'), el('th', {}, 'Plaintext')]),
          ...rows
        ]));
        resultsBox.appendChild(el('div', { class: 'hc-note' }, 'Not cracked doesn’t mean uncrackable — it means the plaintext isn’t in either bundled wordlist or its common variations. A longer or randomly generated password, or a salted/bcrypt/argon2 hash, won’t appear here by design.'));
      }

      async function runSync(hashes, algorithm) {
        // Fallback when Web Workers are unavailable: blocks the tab, so warn.
        status.textContent = 'Running without a Web Worker — the tab may be unresponsive for a while…';
        await new Promise((r) => setTimeout(r, 30));
        try {
          const quick = await crackHashes(hashes, { algorithm, onProgress: (done, total) => onWorkerMessage({ type: 'progress', tier: 'quick', done, total }) });
          const missing = quick.results.filter((r) => r.plaintext === null).map((r) => r.hash);
          if (!missing.length) { setRunning(false); showResult(quick, hashes.length); return; }
          status.textContent = 'Quick tier missed some — loading the SecLists big list (first use only)…';
          const words = await loadSeclistsWordlist();
          const big = await crackHashesFromWordlist(missing, words, { algorithm: algorithm || quick.type, onProgress: (done, total) => onWorkerMessage({ type: 'progress', tier: 'big', done, total }) });
          const bigByHash = new Map(big.results.map((r) => [r.hash, r.plaintext]));
          const merged = quick.results.map((r) => r.plaintext !== null ? r : { hash: r.hash, plaintext: bigByHash.has(r.hash) ? bigByHash.get(r.hash) : null });
          setRunning(false);
          showResult({ type: quick.type, tried: quick.tried + big.tried, results: merged, wordlistSize: words.length }, hashes.length);
        } catch (err) { setRunning(false); showError(errorNode, err); }
      }

      runBtn.addEventListener('click', () => {
        clear(errorNode); clear(resultsBox); clear(status);
        const hashes = input.value.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
        if (!hashes.length) { showError(errorNode, new Error('Paste at least one hash.')); return; }
        const det = detectHashType(hashes[0]);
        status.textContent = det ? `Detected ${det.name}. Running the quick tier…` : 'Cracking…';
        cancelled = false;
        setRunning(true);

        if (typeof Worker === 'undefined') { runSync(hashes, det ? det.name : undefined); return; }
        try {
          worker = new Worker(new URL('../lib/hash-cracker-worker.js', import.meta.url), { type: 'module' });
        } catch {
          worker = null; runSync(hashes, det ? det.name : undefined); return;
        }
        worker.onmessage = (e) => onWorkerMessage(e.data, hashes.length);
        worker.onerror = (e) => { setRunning(false); if (worker) { worker.terminate(); worker = null; } showError(errorNode, new Error(e.message || 'Worker failed')); };
        worker.postMessage({ hashes, algorithm: det ? det.name : undefined });
      });

      cancelBtn.addEventListener('click', () => {
        cancelled = true;
        if (worker) { worker.terminate(); worker = null; }
        setRunning(false);
        status.textContent = 'Cancelled.';
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Hash(es)'),
        input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn, cancelBtn]),
        status,
        progressWrap,
        errorNode,
        credit
      ]));
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'hash-generator',
    name: 'Hash Generator',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Compute MD5, SHA-1, SHA-256, SHA-512, SHA-3-256 and CRC32 of any text, all at once. SHA-1/256/512 use the browser-native Web Crypto API; MD5/SHA-3/CRC32 use this project’s hand-written reference implementations (see README).'));

      const input = el('textarea', { rows: '4', placeholder: 'Type or paste text to hash…' });
      const resultsBox = el('div', { class: 'card' });
      const runBtn = el('button', { class: 'btn' }, 'Compute hashes');
      const errorNode = el('div', {});

      runBtn.addEventListener('click', async () => {
        clear(errorNode);
        clear(resultsBox);
        try {
          const text = input.value;
          const [md5, sha1, sha256, sha512] = await Promise.all([
            Promise.resolve(hashing.md5Hex(text)),
            hashing.sha1Hex(text),
            hashing.sha256Hex(text),
            hashing.sha512Hex(text)
          ]);
          const sha3 = hashing.sha3_256Hex(text);
          const crc32 = hashing.crc32Hex(text);
          const rows = [['MD5', md5], ['SHA-1', sha1], ['SHA-256', sha256], ['SHA-3-256', sha3], ['CRC32', crc32], ['SHA-512', sha512]];
          for (const [label, value] of rows) {
            const line = resultLine(label, value);
            const btn = copyButton(() => value);
            btn.style.marginLeft = '8px';
            line.appendChild(btn);
            resultsBox.appendChild(line);
          }
        } catch (err) {
          showError(errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Input text'),
        input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
        errorNode
      ]));
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'hmac',
    name: 'HMAC Generator',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Generate an HMAC using the native Web Crypto API (never a hand-rolled implementation).'));

      const key = el('input', { type: 'text', placeholder: 'Secret key' });
      const algo = el('select', {}, ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'].map((a) => el('option', { value: a }, a)));
      const message = el('textarea', { rows: '4', placeholder: 'Message' });
      const output = el('textarea', { rows: '3', class: 'output', readonly: 'true' });
      const runBtn = el('button', { class: 'btn' }, 'Generate HMAC');
      const errorNode = el('div', {});

      runBtn.addEventListener('click', async () => {
        clear(errorNode);
        try {
          output.value = await hashing.hmacHex(algo.value, key.value, message.value);
        } catch (err) {
          showError(errorNode, err);
        }
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('div', { class: 'field-row' }, [el('label', {}, 'Algorithm'), algo]),
        el('label', {}, 'Secret key'), key,
        el('label', { style: 'margin-top:10px' }, 'Message'), message,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn]),
        errorNode,
        el('label', { style: 'margin-top:10px' }, 'HMAC'), output,
        copyButton(() => output.value)
      ]));
    }
  },
  {
    id: 'hash-identifier',
    name: 'Hash Type Identifier',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Guess the likely algorithm(s) behind a pasted hash, based on its length and charset. Heuristic only — many algorithms share output lengths.'));

      const input = el('input', { type: 'text', placeholder: 'Paste a hash…' });
      const resultsBox = el('div', { class: 'card' });
      const runBtn = el('button', { class: 'btn' }, 'Identify');

      runBtn.addEventListener('click', () => {
        clear(resultsBox);
        const guesses = hashing.identifyHash(input.value);
        for (const g of guesses) resultsBox.appendChild(resultLine(g.algorithm, g.confidence));
      });

      container.appendChild(el('div', { class: 'card' }, [
        el('label', {}, 'Hash'), input,
        el('div', { class: 'field-row', style: 'margin-top:10px' }, [runBtn])
      ]));
      container.appendChild(resultsBox);
    }
  },
  {
    id: 'file-hash-checker',
    name: 'File Hash Checker',
    render(container) {
      clear(container);
      container.appendChild(toolHeader('Drop a file to compute its hashes locally (nothing uploaded) — useful for verifying file integrity against a published checksum.'));

      const dropZone = el('div', {
        class: 'card',
        style: 'border:2px dashed var(--border); text-align:center; padding:32px; cursor:pointer;'
      }, 'Click or drag a file here');
      const fileInput = el('input', { type: 'file', style: 'display:none' });
      const resultsBox = el('div', { class: 'card' });

      dropZone.addEventListener('click', () => fileInput.click());
      dropZone.addEventListener('dragover', (e) => e.preventDefault());
      dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
      });
      fileInput.addEventListener('change', () => {
        if (fileInput.files[0]) handleFile(fileInput.files[0]);
      });

      async function handleFile(file) {
        clear(resultsBox);
        resultsBox.appendChild(el('p', { class: 'tool-desc' }, `Hashing "${file.name}" (${file.size.toLocaleString()} bytes)…`));
        const buffer = await file.arrayBuffer();
        const [sha256, sha1] = await Promise.all([hashing.sha256Hex(buffer), hashing.sha1Hex(buffer)]);
        const md5 = hashing.md5Hex(new Uint8Array(buffer));
        const crc32 = hashing.crc32Hex(new Uint8Array(buffer));
        clear(resultsBox);
        for (const [label, value] of [['MD5', md5], ['SHA-1', sha1], ['SHA-256', sha256], ['CRC32', crc32]]) {
          resultsBox.appendChild(resultLine(label, value));
        }
      }

      container.appendChild(dropZone);
      container.appendChild(fileInput);
      container.appendChild(resultsBox);
    }
  }
];
